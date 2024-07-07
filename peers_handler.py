import threading
import struct
import socket
import time
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

    BLOCK_LENGTH = 2 ** 14  # Can be changed, but works best at this value.


class Peer:
    def __init__(self, peer_id: str, info_hash: bytes, ip: str, port: int):
        self.peer_id: str = peer_id
        self.ip: str = ip
        self.port: int = port
        self.info_hash: bytes = info_hash
        self.bitfield = None
        self.choking = True
        self.being_used = False

    @staticmethod
    def send_interested(sock: socket.socket) -> None:
        length_prefix = 1
        message_id = Bittorrent_Constants.INTERESTED
        message = struct.pack(">IB", length_prefix, message_id)
        sock.sendall(message)

    @staticmethod
    def send_request(sock: socket.socket, piece_index: int, begin: int, length: int = Bittorrent_Constants.BLOCK_LENGTH) -> None:
        length_prefix = 1 + len(bytes(piece_index)) + len(bytes(begin)) + len(bytes(length))
        message_id = Bittorrent_Constants.REQUEST
        message = struct.pack('>IBIII', length_prefix, message_id, piece_index, begin, length)
        sock.sendall(message)

    @staticmethod
    def await_unchoke(sock: socket.socket):
        sock.settimeout(None)
        while True:
            # LENGTH PREFIX - 4 BYTES
            length_prefix = sock.recv(4)
            if not length_prefix:
                continue
            try:
                length = struct.unpack('>I', length_prefix)[0]
            except struct.error:
                print("EL PROBLEM DE LENGTH ", length_prefix)

            # MESSAGE ID - 1 BYTE
            message_id = sock.recv(1)
            if not message_id:
                continue

            if message_id[0] == Bittorrent_Constants.UNCHOKE:
                print(f"{sock} Unchoked")
                return
            else:
                # SKIP THE REST
                if length > 1:
                    sock.recv(length - 1)

            # SLEEP BEFORE OPTIMISTICALLY UNCHOKING
            time.sleep(1)

    @staticmethod
    def bitfield_counter_map(peers: list['Peer'], num_pieces: int) -> list[int]:  # Counter hashmap of the bitfields
        piece_counts = [0] * num_pieces
        for peer in peers:
            if peer.choking is True:
                continue
            for index, has_piece in enumerate(peer.bitfield):
                if has_piece == '1':
                    piece_counts[index] += 1
        return piece_counts

    @staticmethod
    def find_additional_peers(peer_sock: socket.socket) -> set:
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

    def handshake(self, peer_ip: str, peer_port: int, conn: socket.socket) -> (bytes, None):
        pstr = b'BitTorrent protocol'
        pstrlen = len(pstr)  # Length of the protocol string (19 bytes)
        reserved = b'\x00' * 8
        handshake = struct.pack(f'>B{pstrlen}s8s20s20s', pstrlen, pstr, reserved, self.info_hash, self.peer_id.encode())
        # HANDSHAKE ACCORDING TO THE TCP PEER WIRE PROTOCOL
        try:
            conn.connect((peer_ip, peer_port))
            conn.settimeout(5)
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

    def find_all_additional_peers(self, available_peers: dict['Peer', socket.socket]) -> set:
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

    def send_all_interested(self, available_peers: dict['Peer', socket.socket]) -> None:
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


    def download_process(self, num_pieces: int, piece_length: int, available_peers: dict['Peer', socket.socket]):
        bitfield_counter_map: list[int] = self.bitfield_counter_map(list(available_peers.keys()), num_pieces)
        indexed_occurrences = sorted(enumerate(bitfield_counter_map), key=lambda x: x[1])
        sorted_indexes = [index for index, occurrence in indexed_occurrences]
        piece_status = {key: "Absent" for key in sorted_indexes}  # ALLOWS FOR EASY IMPLEMENTATION OF RAREST PIECE
        print("Beginning download process...")
        lock = threading.Lock()

        def download_process_wrapper(conn: socket.socket):
            # FIRST, WE SELECT PIECE AND PEER
            # FIND A PIECE THAT HAS NOT BEEN DOWNLOADED, AND A PEER THAT HAS IT
            # IF NO PAIR IS FOUND, IT MEANS WE EITHER COMPLETED THE DOWNLOAD OR OTHER THREADS ARE DOWNLOADING THE END
            lock.acquire()
            unavailable_pieces = []
            while True:
                piece_index: int = -1
                for ind, stat in piece_status.items():
                    if stat == "Absent" and ind not in unavailable_pieces:
                        piece_index = ind
                        break
                if piece_index == -1:
                    lock.release()
                    return

                target_peer: (Peer, None) = None
                for p in available_peers.keys():
                    if p.choking is False and p.being_used is False and p.bitfield[piece_index] == '1':
                        target_peer = p
                        p.being_used = True
                        break

                if target_peer is not None:
                    piece_status[piece_index] = "Downloading"
                    break
                unavailable_pieces.append(piece_index)
            lock.release()

            # SECOND, THE ACTUAL DOWNLOADING
            # USING THE REQUEST MESSAGE
            piece_data: bytes = b''
            begin_offset: int = 0
            basic_header_len = 4 + 1  # ACCORDING TO THE MESSAGE EXCHANGE PROTOCOL
            full_header_len = 4 + 1 + 4 + 4

            while len(piece_data) < piece_length:
                self.send_request(available_peers[target_peer], piece_index, begin_offset)
                received_block = False

                while not received_block:
                    try:
                        basic_header: bytes = conn.recv(basic_header_len)
                    except TimeoutError:
                        break

                    print("BASIC HEADER ", basic_header)
                    if basic_header == b'':
                        continue

                    length_prefix, message_id = struct.unpack('>IB', basic_header)


                    match message_id:
                        case Bittorrent_Constants.PIECE:
                            rest_of_header = conn.recv(full_header_len - basic_header_len)
                            response_index, response_offset = struct.unpack(rest_of_header, ">II")

                            payload_len = length_prefix - 1
                            payload: bytes = conn.recv(payload_len)
                            piece_data += payload
                            begin_offset += Bittorrent_Constants.BLOCK_LENGTH
                            print(f"PIECE DOWNLOAD PROGRESS : {(len(piece_data) / piece_length) * 100}%")

                        case Bittorrent_Constants.CHOKE:
                            target_peer.choking = True
                            self.await_unchoke(conn)
                            break

                        case Bittorrent_Constants.UNCHOKE:
                            break

                        case Bittorrent_Constants.HAVE:
                            new_index = struct.unpack(">I", conn.recv(length_prefix - 1))
                            print("NEW INDEX ", new_index)
                            target_peer.bitfield[new_index] = "1"

                        case _:
                            continue



            print(f"THE DATA : {piece_data}")

            with open(f'piece_test_{piece_index}.txt', 'wb+') as test_file:
                test_file.write(piece_data)





        downloader_threads = []
        for sock in available_peers.values():
            thread = threading.Thread(target=download_process_wrapper, args=[sock])
            downloader_threads.append(thread)
            thread.start()

        for thread in downloader_threads:
            thread.join()
