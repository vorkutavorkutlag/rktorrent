import threading
import struct
import socket
from pprint import pprint


class Bittorrent_Constants:
    CHOKE = 0
    UNCHOKE = 1
    INTERESTED = 2
    NOT_INTERESTED = 3
    HAVE = 4
    BITFIELD = 5
    REQUEST = 6
    PIECE = 7
    CANCEL = 8
    PORT = 9

    PIECE_LENGTH = 2 ** 14  # Can be changed, but works best at this value.



class Peer:
    def __init__(self, peer_id: str, info_hash: bytes, ip: str, port: int):
        self.peer_id: str = peer_id
        self.ip: str = ip
        self.port: int = port
        self.info_hash: bytes = info_hash
        self.bitfield = None
        self.choking = True

    @staticmethod
    def send_interested(sock: socket.socket):
        length_prefix = 1
        message_id = Bittorrent_Constants.INTERESTED
        message = struct.pack(">IB", length_prefix, message_id)
        sock.sendall(message)

    @staticmethod
    def find_additional_peers(peer_sock: socket.socket):
        # REQUESTS PEERS FROM A SELECTED PEER, FILTERS OUT INVALID ADDRESSES AND RETURNS POTENTIAL NEW PEERS
        peer_sock.send(b'REQUEST_PEERS')
        response, _ = peer_sock.recvfrom(4096)

        new_peers: set = set()
        for i in range(0, len(response), 6):
            ip_bytes = response[i:i + 4]
            port_bytes = response[i + 4:i + 6]

            if len(ip_bytes) < 4 or len(port_bytes) < 2:
                continue

            ip = socket.inet_ntoa(ip_bytes)
            port = struct.unpack('!H', port_bytes)[0]
            if port == 0 or port == 65535 or ip == '255.255.255.255' or ip.startswith('0.'):
                continue
            new_peers.add((ip, port))
        return new_peers

    def handshake(self, peer_ip: str, peer_port: int, conn: socket.socket):
        pstr = b'BitTorrent protocol'
        pstrlen = len(pstr)  # Length of the protocol string (19 bytes)
        reserved = b'\x00' * 8
        handshake = struct.pack(f'>B{pstrlen}s8s20s20s', pstrlen, pstr, reserved, self.info_hash, self.peer_id.encode())
        # HANDSHAKE ACCORDING TO THE TCP PEER WIRE PROTOCOL
        try:
            conn.connect((peer_ip, peer_port)); conn.settimeout(5)
            conn.send(handshake)
            response, _ = conn.recvfrom(68)  # HANDSHAKE LENGTH IS CONSTANT, 68 BYTES
            return response

        except (ConnectionRefusedError, ConnectionResetError, TimeoutError, OSError):
            return None

    def perform_handshakes(self, peers_dict: dict) -> dict['Peer', socket.socket]:
        # ADDS MULTITHREADING TO THE HANDSHAKE FUNCTION, RETURNS PEER OBJECTS AND SOCKET CONNECTIONS
        peer_connections: dict[Peer, socket.socket] = {}
        lock = threading.Lock()

        def perform_handshake_wrapper(ip: str, port: int, conn: socket.socket):
            response = self.handshake(ip, port, conn)
            lock.acquire()
            if response is not None and response != b'':
                peer: Peer = Peer("", self.info_hash, ip, port)
                peer_connections[peer] = conn
            else:
                sock.close()
            lock.release()

        threads = []
        for peer_ip, peer_port in peers_dict.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            thread = threading.Thread(target=perform_handshake_wrapper, args=(peer_ip, peer_port, sock))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        return peer_connections

    def find_all_additional_peers(self, available_peers: dict['Peer', socket.socket]):
        # ADDS MULTITHREADING TO THE FIND ADDITIONAL PEERS FUNCTION
        # CONTACTS ALL CURRENT AVAILABLE PEERS
        # RETURNS PEER OBJECTS AND SOCKET CONNECTIONS
        # MOST MIGHT NOT BE AVAILABLE, BUT THE TIME SPENT ON MAKING SURE IS WORTH IT IF WE DO FIND MORE PEERS
        all_new_peers: set = set()
        lock = threading.Lock()

        def find_peers_wrapper(conn: socket.socket):
            new_peers = self.find_additional_peers(conn)
            if new_peers is not None:
                lock.acquire()
                nonlocal all_new_peers
                all_new_peers = all_new_peers.union(new_peers)
                lock.release()

        threads = []
        for sock in available_peers.values():
            thread = threading.Thread(target=find_peers_wrapper, args=[sock])
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()


        return all_new_peers

    def send_all_interested(self, available_peers: dict['Peer', socket.socket]):
        response_length = 5  # 4 - length, 1 - ID

        def send_interested_wrapper(peer: Peer, conn: socket.socket):
            try:
                self.send_interested(conn)
                response = conn.recv(response_length)
                length_prefix = response[:4]
                length = struct.unpack('>I', length_prefix)[0]
                response_id = response[4]

                match response_id:
                    case Bittorrent_Constants.CHOKE:
                        peer.choking = True
                    case Bittorrent_Constants.UNCHOKE:
                        peer.choking = False

                    case Bittorrent_Constants.BITFIELD:
                        bitfield = conn.recv(length - 1)
                        peer.bitfield = ''.join(format(byte, '08b') for byte in bitfield)
                        peer.choking = False


            except (IndexError, socket.error):
                peer.choking = True

        threads = []
        for peer, sock in available_peers.items():
            thread = threading.Thread(target=send_interested_wrapper, args=[peer, sock])
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    @staticmethod
    def find_rarest(peers: list['Peer'], num_pieces: int):
        piece_counts = [0] * num_pieces
        for peer in peers:
            for index, has_piece in enumerate(peer.bitfield):
                if has_piece:
                    piece_counts[index] += 1
        return piece_counts.index(min(piece_counts))

