import socket
import logging
import requests
from bcoding import bdecode, bencode
from hashlib import sha1
import struct
from uuid import uuid4
from pprint import pprint

import peers_handler
import tracker_handler


def read_torrent(path: str) -> (dict, str, int):
    with open(path, "rb") as file:
        content: bytes = file.read()
        torrent_json: dict = bdecode(content)
        hashed_info: bytes = sha1(bencode(torrent_json['info'])).digest()
        announce_list: list[str] = [torrent_json['announce'], torrent_json['announce-list']]
        piece_length: int = torrent_json['info']['piece length']

        if 'files' not in torrent_json['info'].keys():
            num_files: int = 1
            size: int = torrent_json['info']['length']
        else:
            num_files: int = len(torrent_json['info']['files'])
            size: int = sum(file['length'] for file in torrent_json['info']['files'])

        return announce_list, piece_length, hashed_info, size




def main():
    test_torrent: str = "C:\\Users\\mensc\\Downloads\\Atomic_Heart.torrent"
    announce_list, piece_length, info_hash, size = read_torrent(test_torrent)

    logging.debug("Read file")

    handler_response = \
        tracker_handler.announce_to_peers(announce_list, info_hash, size, UNIQUE_CLIENT_ID, IP_ADDRESS, 0)

    peers_dict: dict = handler_response[0]
    tracker: tracker_handler.Tracker = handler_response[1]

    our_peer: peers_handler.Peer = peers_handler.Peer(UNIQUE_CLIENT_ID, info_hash, "localhost", 0)
    peer_connections: dict[peers_handler.Peer, socket.socket] = our_peer.perform_handshakes(peers_dict)

    new_peers: set = our_peer.find_all_additional_peers(peer_connections)
    new_peers_dict = {}
    for ip, port in new_peers:
        new_peers_dict[ip] = port
    additional_peer_connections: dict[peers_handler.Peer, socket.socket] = our_peer.perform_handshakes(new_peers_dict)

    peer_connections: dict[peers_handler.Peer, socket.socket] = peer_connections | additional_peer_connections

    pprint(peer_connections)


if __name__ == "__main__":
    version: str = "0045"
    IP_ADDRESS: str = requests.get('https://api.ipify.org').content.decode('utf8')

    client_prefix = "RK-" + version + "-"
    random_suffix = uuid4().hex[:12]
    combined_id = client_prefix + random_suffix
    UNIQUE_CLIENT_ID: str = combined_id[:20]

    main()

