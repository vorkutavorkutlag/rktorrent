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


    def handshake(self, peer_ip: str, peer_port: int):
        pstr = b'BitTorrent protocol'
        pstrlen = len(pstr)  # Length of the protocol string (19 bytes)
        reserved = b'\x00' * 8
        handshake = struct.pack(f'>B{pstrlen}s8s20s20s', pstrlen, pstr, reserved, self.info_hash, self.peer_id.encode())

        try:
            sock = socket.create_connection((peer_ip, peer_port), timeout=2)
            sock.send(handshake)
            response, _ = sock.recvfrom(68)  # The response handshake should be 68 bytes
            return response

        except (ConnectionRefusedError, ConnectionResetError, TimeoutError) as e:
            pass


    def perform_handshakes(self, peers_dict: dict) -> dict:
        available_peers: dict = {}

        def perform_handshake_wrapper(ip, port):
            response = self.handshake(ip, port)
            if response is not None and response != b'':
                print("RESPONSE IS ", response)
                available_peers[ip] = port

        threads = []
        for peer_ip, peer_port in peers_dict.items():
            thread = threading.Thread(target=perform_handshake_wrapper, args=(peer_ip, peer_port))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        return available_peers


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
