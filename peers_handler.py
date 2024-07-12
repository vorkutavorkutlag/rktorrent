import os
import threading
import struct
import socket
import time
from hashlib import sha1
from typing import Callable
from math import ceil


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

    @staticmethod
    def send_cancel(sock: socket.socket, piece_index: int, begin: int, length: int) -> None:
        length_prefix = 1 + 4 + 4 + 4  # 1 BYTE ID, 4 BYTE PIECE INDEX, 4 BYTE OFFSET, 4 BYTE LENGTH
        message_id = Bittorrent_Constants.CANCEL
        message = struct.pack('>IBIII', length_prefix, message_id, piece_index, begin, length)
        sock.sendall(message)


    def await_unchoke(self, sock: socket.socket, target_peer: 'Peer',
                      cancel_event: threading.Event, pause_event: threading.Event, index, begin, length):
        while True:
            if cancel_event.is_set():
                return 0
            while pause_event.is_set():
                time.sleep(1)
            time.sleep(5)
            self.send_interested(sock)
            basic_header_len = 4 + 1
            basic_header = sock.recv(basic_header_len)
            response_length, response_id = struct.unpack(">IB", basic_header)
            match response_id:
                case Bittorrent_Constants.UNCHOKE:
                    return 1
                case Bittorrent_Constants.BITFIELD:
                    data = sock.recv(response_length-1)
                    bitfield_str = ''.join(format(byte, '08b') for byte in data)
                    target_peer.bitfield = bytearray(int(byte) for byte in bitfield_str)
                    target_peer.choking = False
                    return 1
                case _:
                    self.send_cancel(sock, index, begin, length)
                    return 2

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
        pstr_len = len(pstr)  # Length of the protocol string (19 bytes)
        reserved = b'\x00' * 8
        handshake = struct.pack(f'>B{pstr_len}s8s20s20s',
                                pstr_len,
                                pstr,
                                reserved,
                                self.info_hash,
                                self.peer_id.encode())
        # HANDSHAKE ACCORDING TO THE TCP PEER WIRE PROTOCOL
        try:
            conn.connect((peer_ip, peer_port))
            conn.settimeout(5)
            conn.send(handshake)
            response, _ = conn.recvfrom(68)  # HANDSHAKE LENGTH IS CONSTANT, 68 BYTES
            return response

        except (ConnectionRefusedError, ConnectionResetError, TimeoutError, OSError):
            return None

    def perform_handshakes(self, peers_dict: dict, cancel_event, pause_event) -> dict['Peer', socket.socket]:
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
            if cancel_event.is_set():
                return {}
            while pause_event.is_set():
                time.sleep(1)
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

        def send_interested_wrapper(target_peer: Peer, conn: socket.socket):
            try:
                self.send_interested(conn)
                response = conn.recv(response_length)
                length_prefix = response[:4]
                length = int.from_bytes(length_prefix, byteorder="big")
                response_id = response[4]

                match response_id:
                    case Bittorrent_Constants.CHOKE:
                        target_peer.choking = True
                    case Bittorrent_Constants.UNCHOKE:
                        target_peer.choking = False

                    case Bittorrent_Constants.BITFIELD:
                        bitfield = conn.recv(length - 1)
                        bitfield_str = ''.join(format(byte, '08b') for byte in bitfield)
                        target_peer.bitfield = bytearray(int(byte) for byte in bitfield_str)
                        target_peer.choking = False


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
                         cancel_event: threading.Event, pause_event: threading.Event, update: Callable):
        # ASCENDING ORDER LIST OF INDEXES, ALLOWS FOR RAREST PIECE SELECTION
        bitfield_counter_map: list[int] = self.bitfield_counter_map(list(available_peers.keys()), num_pieces)
        sorted_indexes: list[int] = sorted(range(len(bitfield_counter_map)), key=lambda x: bitfield_counter_map[x])
        piece_statuses: list[Index] = list(Index(ind) for ind in sorted_indexes)
        print("Beginning download process...")
        acquire_piece_lock = threading.Lock()
        write_data_lock = threading.Lock()
        pieces_downloaded = 0
        size_of_download = 0
        start_time = time.time()
        endgame_event = threading.Event()
        _endgame_found_block = threading.Event()

        if 'files' not in torrent_info.keys():
            files = [{'length': torrent_info['length'],
                      'path': os.path.join(selected_dir, torrent_info['name'])}]
        else:
            files = [{'length': torrent_file['length'],
                      'path': os.path.join(selected_dir, r'\\'.join(torrent_file['path']))}
                     for torrent_file in torrent_info['files']]

        def download_rarest_piece(conn: socket.socket, piece_size):
            nonlocal pieces_downloaded
            is_valid = False
            unavailable_pieces = []
            target_peer = list(available_peers.keys())[list(available_peers.values()).index(conn)]

            while not is_valid:
                acquire_piece_lock.acquire()  # region SELECT PIECE AND PEER
                if cancel_event.is_set() or endgame_event.is_set():
                    return
                while pause_event.is_set():
                    time.sleep(1)
                piece_index: int = -1
                index_of_index: int = -1
                for ioi, index in enumerate(piece_statuses):
                    if index.status == "Absent" and index.value not in unavailable_pieces\
                            and target_peer.bitfield[index.value]:
                        piece_index = index.value
                        index_of_index = ioi
                        break
                if piece_index == -1:
                    acquire_piece_lock.release()
                    return

                piece_statuses[index_of_index].status = "Downloading"
                print("FOUND VALID PAIR ", (piece_index, target_peer))
                print("I hope this time it goes better, God willing")
                acquire_piece_lock.release()
                # endregion

                # region DOWNLOAD PIECE
                piece_data: bytes = b''
                begin_offset: int = 0
                len_prefix_len = 4
                need_to_send = True
                try:
                    loop_start_time = time.time()
                    while len(piece_data) < piece_size:
                        if cancel_event.is_set() or endgame_event.is_set():
                            return
                        while pause_event.is_set():
                            time.sleep(1)
                        if need_to_send:
                            requesting_block_length = min(Bittorrent_Constants.BLOCK_LENGTH,
                                                          piece_size - len(piece_data))
                            self.send_request(conn, piece_index, begin_offset, requesting_block_length)
                        len_prefix = int.from_bytes(conn.recv(len_prefix_len), byteorder="big")
                        if len_prefix == 0:     # KEEP ALIVE MESSAGE
                            need_to_send = False
                            if time.time() - loop_start_time < 10:
                                need_to_send = True
                                loop_start_time = time.time()
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
                                    if (pieces_downloaded / num_pieces) * 100 > 99.5:  # FILTERS BAD PEERS AT ENDGAME
                                        return
                                    continue
                                block = data[8:]
                                piece_data += block
                                begin_offset += Bittorrent_Constants.BLOCK_LENGTH
                            case Bittorrent_Constants.CHOKE:
                                if not self.await_unchoke(conn, target_peer, cancel_event, pause_event, piece_index,
                                                          begin_offset, piece_size):
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
                    if (pieces_downloaded/num_pieces)*100 > 99.5:   # FILTERS BAD PEERS AT ENDGAME
                        return
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
                if (pieces_downloaded / num_pieces) * 100 > 99.5:  # FILTERS BAD PEERS AT ENDGAME
                    return
                if target_peer.strikes >= 20:
                    unavailable_pieces.append(piece_index)
                    break
                # endregion

        def download_process(conn):
            # region WRITE TO FILE
            nonlocal files
            nonlocal pieces_downloaded
            nonlocal size_of_download

            for file in files:
                with open(file['path'], 'w') as _:  # CREATE EMPTY FILE
                    pass

            while True:
                if cancel_event.is_set() or endgame_event.is_set():
                    return
                while pause_event.is_set():
                    time.sleep(1)
                actual_piece_size = min(piece_length, size - size_of_download)
                download_percent = round((pieces_downloaded/num_pieces)*100, 2)
                try:
                    update(download_percent, "Downloading from peers...", time.time()-start_time)
                except Exception as ex:    # Tkinter exception
                    return ex
                print(f"{torrent_info['name']} is at {download_percent}%")
                try:
                    piece_index, piece_data = download_rarest_piece(conn, actual_piece_size)
                except TypeError:  # RETURNING NONE = NO MORE PIECES TO DOWNLOAD
                    return

                piece_offset: int = piece_index * piece_length
                remaining_data: bytes = piece_data
                write_data_lock.acquire()
                size_of_download += len(piece_data)
                write_data_lock.release()

                for file in files:  # FILE SELECTION
                    if piece_offset >= file['length']:
                        piece_offset -= file['length']
                        continue

                    bytes_to_write = min(file['length'] - piece_offset, len(remaining_data))
                    write_data_lock.acquire()
                    with open(file['path'], 'r+b') as f:
                        f.seek(piece_offset)
                        f.write(remaining_data[:bytes_to_write])
                    write_data_lock.release()
                    remaining_data = remaining_data[bytes_to_write:]
                    piece_offset = 0  # RESET FOR SUBSEQUENT FILES

                    if not remaining_data:
                        break


        def keep_aliver():
            conns = available_peers.values()
            length_prefix: int = 0
            keep_alive: bytes = struct.pack(">I", length_prefix)
            while not endgame_event.is_set():
                if cancel_event.is_set() or (pieces_downloaded/num_pieces)*100 > 90:
                    return
                if not pause_event.is_set():
                    continue
                for conn in conns:
                    try:
                        conn.send(keep_alive)
                    except (ConnectionAbortedError, ConnectionRefusedError,
                            ConnectionResetError, ConnectionError, OSError):
                        pass
                time.sleep(5)


        def _endgame_request_block(piece_index: int, target_peer: Peer,
                                   piece_size: int, downloaded_len: int, begin_offset: int):
            requesting_block_length = min(Bittorrent_Constants.BLOCK_LENGTH, piece_size - downloaded_len)
            conn = available_peers[target_peer]
            need_to_send = True
            len_prefix_len = 4
            loop_start_time = time.time()

            while not _endgame_found_block.is_set():
                if cancel_event.is_set():
                    return
                while pause_event.is_set():
                    time.sleep(1)
                try:
                    if need_to_send:
                        self.send_request(conn, piece_index, begin_offset, requesting_block_length)
                    len_prefix = int.from_bytes(conn.recv(len_prefix_len), byteorder="big")
                    if len_prefix == 0:  # KEEP ALIVE MESSAGE
                        need_to_send = False
                        if time.time() - loop_start_time < 10:
                            need_to_send = True
                            loop_start_time = time.time()
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
                                return
                            _endgame_found_block.set()
                            nonlocal block_data
                            write_data_lock.acquire()
                            block_data = data[8:]
                            write_data_lock.release()
                            return

                        case Bittorrent_Constants.CHOKE:
                            if not self.await_unchoke(conn, target_peer, cancel_event, pause_event, piece_index,
                                                      begin_offset, piece_size):
                                return
                            need_to_send = True
                        case Bittorrent_Constants.HAVE:
                            new_index = int.from_bytes(conn.recv(len_prefix - 1), byteorder="big")
                            target_peer.bitfield[new_index] = 1
                        case Bittorrent_Constants.UNCHOKE:
                            need_to_send = False
                            continue
                except (TimeoutError, ConnectionResetError, ConnectionError, IndexError):
                    return
            try:
                self.send_cancel(conn, piece_index, begin_offset, requesting_block_length)
            except (TimeoutError, ConnectionResetError, ConnectionAbortedError, ConnectionRefusedError, socket.error):
                pass

        def write_individual_piece(piece_index, piece_data):
            nonlocal size_of_download
            piece_offset: int = piece_index * piece_length
            remaining_data: bytes = piece_data
            write_data_lock.acquire()
            size_of_download += len(remaining_data)
            write_data_lock.release()

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
                piece_offset = 0

                if not remaining_data:
                    break

        downloader_threads = []
        for sock in available_peers.values():
            thread = threading.Thread(target=download_process, args=[sock])
            downloader_threads.append(thread)
            thread.start()
        keep_alive_thread = threading.Thread(target=keep_aliver, args=[])
        downloader_threads.append(keep_alive_thread)
        keep_alive_thread.start()

        for thread in downloader_threads:
            thread.join()

        print("ENDGAME.")
        missing_pieces = [p for p in piece_statuses if p.status == "Absent" or p.status == "Downloading"]
        print(missing_pieces)

        for p in missing_pieces:
            if cancel_event.is_set():
                return
            while pause_event.is_set():
                time.sleep(1)
            piece: bytes = b''
            real_piece_size: int = min(piece_length, size - size_of_download)
            download_percentage = round((pieces_downloaded / num_pieces) * 100, 2)
            try:
                update(download_percentage, "Endgame", time.time()-start_time)
            except Exception as e:  # Tkinter Exception
                return e
            while True:
                endgame_threads = []
                offset = 0
                for num_block in range(ceil(real_piece_size / Bittorrent_Constants.BLOCK_LENGTH)):
                    if cancel_event.is_set():
                        return
                    while pause_event.is_set():
                        time.sleep(1)

                    _endgame_found_block.clear()
                    block_data = b''
                    for peer in available_peers.keys():
                        thread = threading.Thread(target=_endgame_request_block,
                                                  args=[p.value, peer, real_piece_size, len(piece), offset])
                        endgame_threads.append(thread)
                        thread.start()
                    for thread in endgame_threads:
                        thread.join()


                    piece += block_data
                    offset += len(block_data)
                    print(piece)
                print(f"validating piece #{p.value}")
                if self.validate_piece(piece, p.value, torrent_info['pieces']):
                    write_individual_piece(p.value, piece)
                    break
                print("you're going to be okay.")
