import threading
import struct
import socket
from pprint import pprint

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



class Peer:
    def __init__(self, peer_id: str, info_hash: bytes, ip: str, port: int):
        self.peer_id: str = peer_id
        self.ip: str = ip
        self.port: int = port
        self.info_hash: bytes = info_hash
        self.bitfield = None


    def handshake(self, peer_ip: str, peer_port: int, conn: socket.socket):
        pstr = b'BitTorrent protocol'
        pstrlen = len(pstr)  # Length of the protocol string (19 bytes)
        reserved = b'\x00' * 8
        handshake = struct.pack(f'>B{pstrlen}s8s20s20s', pstrlen, pstr, reserved, self.info_hash, self.peer_id.encode())

        try:
            conn.connect((peer_ip, peer_port)); conn.settimeout(3)
            conn.send(handshake)
            response, _ = conn.recvfrom(68)  # The response handshake should be 68 bytes
            return response

        except (ConnectionRefusedError, ConnectionResetError, TimeoutError, OSError):
            return None


    def perform_handshakes(self, peers_dict: dict) -> dict:
        peer_connections: dict[tuple[str, int], socket.socket] = {}
        lock = threading.Lock()

        def perform_handshake_wrapper(ip: str, port: int, conn: socket.socket):
            response = self.handshake(ip, port, conn)
            lock.acquire()
            if response is not None and response != b'':
                peer_connections[(ip, port)] = conn
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


"""
def find_rarest(peers: list[Peer], num_pieces: int):
    piece_counts = [0] * num_pieces
    for peer in peers:
        for index, has_piece in enumerate(peer.bitfield):
            if has_piece:
                piece_counts[index] += 1
    return piece_counts.index(min(piece_counts))
"""

if __name__ == "__main__":
    pass
