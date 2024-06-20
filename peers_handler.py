class Peer:
    def __init__(self):
        self.bitfield = None
        self.peer_id = None
        self.info_hash = None


    def create_handshake(self):
        pstr = b'BitTorrent protocol'
        pstrlen = len(pstr)
        reserved = b'\x00' * 8
        handshake = bytes([pstrlen]) + pstr + reserved + self.info_hash + self.peer_id
        return handshake

    pass


def find_rarest(peers: list[Peer], num_pieces: int):
    piece_counts = [0] * num_pieces
    for peer in peers:
        for index, has_piece in enumerate(peer.bitfield):
            if has_piece:
                piece_counts[index] += 1
    return piece_counts.index(min(piece_counts))
