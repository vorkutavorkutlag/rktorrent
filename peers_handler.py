import os
import threading
import struct
import socket
import time
from hashlib import sha1



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


DOWNLOAD_PERCENTAGE: int = 0


class Index:
    def __init__(self, val):
        self.value = val
        self.status = "Absent"


class Peer:
    def __init__(self, peer_id: str, info_hash: bytes, ip: str, port: int):
        self.peer_id: str = peer_id
        self.ip: str = ip
        self.port: int = port
        self.info_hash: bytes = info_hash
        self.bitfield: (None, bytearray) = None
        self.choking: bool = True
        self.being_used: bool = False
        self.strikes: int = 0


    @staticmethod
    def validate_piece(piece_data: bytes, piece_index: int, pieces_hash: bytes):
        piece_hash = sha1(piece_data).digest()
        expected_hash = pieces_hash[piece_index*20:(piece_index+1)*20]
        return piece_hash == expected_hash

    @staticmethod
    def recv_all(conn: socket.socket, length: int):
        data = b''
        while len(data) < length:
            packet = conn.recv(length - len(data))
            if not packet:
                raise ValueError("Connection closed unexpectedly")
            data += packet
        return data

    @staticmethod
    def send_interested(sock: socket.socket) -> None:
        length_prefix = 1
        message_id = Bittorrent_Constants.INTERESTED
        message = struct.pack(">IB", length_prefix, message_id)
        sock.sendall(message)

    @staticmethod
    def send_request(sock: socket.socket, piece_index: int, begin: int, length: int) -> None:
        length_prefix = 1 + 4 + 4 + 4  # 1 BYTE ID, 4 BYTE PIECE INDEX, 4 BYTE OFFSET, 4 BYTE LENGTH
        message_id = Bittorrent_Constants.REQUEST
        message = struct.pack('>IBIII', length_prefix, message_id, piece_index, begin, length)
        sock.sendall(message)


    def await_unchoke(self, sock: socket.socket, piece_index: int, begin: int, length: int,
                      cancel_event: threading.Event, pause_event: threading.Event):
        while True:
            if cancel_event.is_set():
                return 0
            while pause_event.is_set():
                time.sleep(1)
            time.sleep(5)
            self.send_request(sock, piece_index, begin, length)
            basic_header_len = 4 + 1
            basic_header = sock.recv(basic_header_len)
            response_length, response_id = struct.unpack(">IB", basic_header)
            if response_id == Bittorrent_Constants.UNCHOKE:
                return 1

    @staticmethod
    def bitfield_counter_map(peers: list['Peer'], num_pieces: int) -> list[int]:  # Counter hashmap of the bitfields
        piece_counts = [0] * num_pieces
        for peer in peers:
            if peer.choking is True:
                continue
            for index, has_piece in enumerate(peer.bitfield):
                if has_piece:
                    piece_counts[index] += 1
        return piece_counts

    @staticmethod
    def send_peers_request(peer_sock: socket.socket) -> set:
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
            new_peers = self.send_peers_request(conn)
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
                length = int.from_bytes(length_prefix, byteorder="big")
                response_id = response[4]

                match response_id:
                    case Bittorrent_Constants.CHOKE:
                        peer.choking = True
                    case Bittorrent_Constants.UNCHOKE:
                        peer.choking = False

                    case Bittorrent_Constants.BITFIELD:
                        bitfield = conn.recv(length - 1)
                        bitfield_str = ''.join(format(byte, '08b') for byte in bitfield)
                        peer.bitfield = bytearray(int(byte) for byte in bitfield_str)
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


    def download_process(self, num_pieces: int, piece_length: int, available_peers: dict['Peer', socket.socket],
                         torrent_info: dict, selected_dir: str, size: int,
                         cancel_event: threading.Event, pause_event: threading.Event):
        # ASCENDING ORDER LIST OF INDEXES, ALLOWS FOR RAREST PIECE SELECTION
        bitfield_counter_map: list[int] = self.bitfield_counter_map(list(available_peers.keys()), num_pieces)
        sorted_indexes: list[int] = sorted(range(len(bitfield_counter_map)), key=lambda x: bitfield_counter_map[x])
        piece_statuses: list[Index] = list(Index(ind) for ind in sorted_indexes)
        piece_stati_enum = enumerate(piece_statuses)
        print("Beginning download process...")
        acquire_piece_lock = threading.Lock()
        write_data_lock = threading.Lock()
        pieces_downloaded = 0

        if 'files' not in torrent_info.keys():
            files = [{'length': torrent_info['length'],
                      'path': os.path.join(selected_dir, torrent_info['name'])}]
        else:
            files = [{'length': torrent_file['length'],
                      'path': os.path.join(selected_dir, r'\\'.join(torrent_file['path']))}
                     for torrent_file in torrent_info['files']]

        def download_piece(conn: socket.socket, piece_size):
            nonlocal pieces_downloaded
            acquire_piece_lock.acquire()            # region SELECT PIECE AND PEER
            unavailable_pieces = []
            while True:
                if cancel_event.is_set():
                    return
                while pause_event.is_set():
                    time.sleep(1)
                piece_index: int = -1
                index_of_index: int = -1
                for ioi, index in piece_stati_enum:
                    if index.status == "Absent" and index.value not in unavailable_pieces:
                        piece_index = index.value
                        index_of_index = ioi
                        break
                if piece_index == -1:
                    acquire_piece_lock.release()
                    return

                target_peer: (Peer, None) = None
                for p in available_peers.keys():
                    if p.choking is False and p.being_used is False and p.bitfield[piece_index] == 1:
                        target_peer = p
                        p.being_used = True
                        piece_statuses[index_of_index].status = "Downloading"
                        print(f"{piece_index}, WHICH IS AT {index_of_index}, IS DOWNLOADING.")
                        break
                if target_peer is not None:
                    break
                unavailable_pieces.append(piece_index)

            print("FOUND VALID PAIR ", (piece_index, target_peer))
            print("I hope this time it goes better, God willing")
            acquire_piece_lock.release()
            # endregion

            # region DOWNLOAD PIECE
            piece_data: bytes = b''
            begin_offset: int = 0
            len_prefix_len = 4
            need_to_send = True
            is_valid = False
            while not is_valid:
                try:
                    start_time = time.time()
                    while len(piece_data) < piece_size:
                        if cancel_event.is_set():
                            return
                        while pause_event.is_set():
                            time.sleep(1)
                        if need_to_send:
                            requesting_block_length = min(Bittorrent_Constants.BLOCK_LENGTH, piece_size - len(piece_data))
                            self.send_request(conn, piece_index, begin_offset, requesting_block_length)
                        len_prefix = int.from_bytes(conn.recv(len_prefix_len), byteorder="big")
                        if len_prefix == 0:     # KEEP ALIVE MESSAGE
                            need_to_send = False
                            if time.time() - start_time > 10:
                                need_to_send = True
                            continue
                        response_id = int.from_bytes(conn.recv(1), byteorder="big")
                        need_to_send = True


                        match response_id:
                            case Bittorrent_Constants.PIECE:
                                data = self.recv_all(conn, len_prefix - 1)
                                response_index, response_offset = struct.unpack(">II", data[:8])
                                try:
                                    assert response_index == piece_index
                                    assert response_offset == begin_offset
                                except AssertionError:
                                    continue
                                block = data[8:]
                                piece_data += block
                                begin_offset += Bittorrent_Constants.BLOCK_LENGTH
                            case Bittorrent_Constants.CHOKE:
                                if not self.await_unchoke(conn, piece_index, begin_offset,
                                                          Bittorrent_Constants.BLOCK_LENGTH, cancel_event, pause_event):
                                    return
                            case Bittorrent_Constants.HAVE:
                                new_index = int.from_bytes(conn.recv(len_prefix - 1), byteorder="big")
                                target_peer.bitfield[new_index] = 1
                            case Bittorrent_Constants.UNCHOKE:
                                need_to_send = False
                                continue
                except (TimeoutError, ConnectionResetError, ConnectionError,
                        ValueError, IndexError, OSError, struct.error):
                    target_peer.being_used = False
                    write_data_lock.acquire()
                    piece_statuses[index_of_index].status = "Absent"
                    write_data_lock.release()
                    time.sleep(1)
                    continue

                is_valid = self.validate_piece(piece_data, piece_index, torrent_info['pieces'])
                target_peer.being_used = False

                print(f"VALIDATING PIECE #{piece_index}... {is_valid}")
                write_data_lock.acquire()
                if is_valid:
                    pieces_downloaded += 1
                    piece_statuses[index_of_index].status = "Downloaded"
                    write_data_lock.release()
                    return piece_index, piece_data

                piece_statuses[index_of_index].status = "Absent"
                write_data_lock.release()
                target_peer.strikes += 1
                if target_peer.strikes >= 20:
                    target_peer.being_used = True
                    return
                # endregion

        def download_all_pieces(conn: socket.socket):
            # region WRITE TO FILE
            nonlocal files
            nonlocal pieces_downloaded

            for file in files:
                with open(file['path'], 'w') as _:  # CREATE EMPTY FILE
                    pass

            while (size_of_download := sum(os.path.getsize(file['path']) for file in files)) < size:
                if cancel_event.is_set():
                    return
                while pause_event.is_set():
                    time.sleep(1)
                actual_piece_size = min(piece_length, size - size_of_download)
                print(f"{torrent_info['name']} is at {(pieces_downloaded/num_pieces)*100}%")
                try:
                    time.sleep(1)
                    piece_index, piece_data = download_piece(conn, actual_piece_size)
                except TypeError:  # RETURNING NONE = NO MORE PIECES TO DOWNLOAD
                    return

                piece_offset: int = piece_index * piece_length
                remaining_data: bytes = piece_data

                for file in files:  # FILE SELECTION
                    file_length = file['length']
                    if piece_offset >= file_length:
                        piece_offset -= file_length
                        continue

                    bytes_to_write = min(file_length - piece_offset, len(remaining_data))
                    write_data_lock.acquire()
                    with open(file['path'], 'r+b') as f:
                        f.seek(piece_offset)
                        f.write(remaining_data[:bytes_to_write])
                    write_data_lock.release()
                    remaining_data = remaining_data[bytes_to_write:]
                    piece_offset = 0  # RESET FOR SUBSEQUENT FILES

                    if not remaining_data:
                        break
            cancel_event.set()     # CANCEL EVENT USED TO SIGNAL THE DOWNLOAD PROCESS HAS FINISHED.

        def keep_aliver():
            conns = available_peers.values()
            length_prefix: int = 0
            keep_alive: bytes = struct.pack(">I", length_prefix)
            while True:
                if cancel_event.is_set():
                    return
                for conn in conns:
                    conn.send(keep_alive)
                time.sleep(10)


        downloader_threads = []
        for sock in available_peers.values():
            thread = threading.Thread(target=download_all_pieces, args=[sock])
            downloader_threads.append(thread)
            thread.start()
        keep_alive_thread = threading.Thread(target=keep_aliver, args=[])
        downloader_threads.append(keep_alive_thread)
        keep_alive_thread.start()

        for thread in downloader_threads:
            thread.join()

        print("Process Finished.")
