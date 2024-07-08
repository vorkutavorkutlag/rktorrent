import socket
import requests
import time
from bcoding import bdecode, bencode
from hashlib import sha1
from math import ceil
from uuid import uuid4
from pprint import pprint

import peers_handler
import tracker_handler


def read_torrent(path: str) -> (dict, str, int):  # READS TORRENT FILE, EXTRACTS IMPORTANT DATA
    with open(path, "rb") as file:
        content: bytes = file.read()
        torrent_json: dict = bdecode(content)
        hashed_info: bytes = sha1(bencode(torrent_json['info'])).digest()
        # THE SHA1 ENCODING OF THE BENCODED INFO SECTION OF THE TORRENT EQUALS THE INFO HASH
        announce_list: list[str] = [torrent_json['announce']] + torrent_json['announce-list']
        piece_length: int = torrent_json['info']['piece length']

        # IF THERE'S NO 'files' KEY, THERE IS ONLY ONE FILE
        if 'files' not in torrent_json['info'].keys():
            size: int = torrent_json['info']['length']
        else:
            size: int = sum(file['length'] for file in torrent_json['info']['files'])

        num_pieces: int = ceil(size / piece_length)
        return announce_list, piece_length, hashed_info, size, num_pieces, torrent_json['info']




def main():
    # TO BE REPLACED WITH A PROMPT FROM THE GUI
    test_torrent: str = "C:\\Users\\mensc\\Downloads\\shovel_knight_dig_v1_1_5_rar.torrent"

    # CALLS THE READ TORRENT FUNCTION
    announce_list, piece_length, info_hash, size, num_pieces, torrent_info = read_torrent(test_torrent)

    print("Read file")
    # FINDS A STABLE CONNECTION WITH A TRACKER, REQUESTS PEER INFO
    handler_response = \
        tracker_handler.announce_to_peers(announce_list, info_hash, size, UNIQUE_CLIENT_ID, IP_ADDRESS, 0)

    peers_dict: dict = handler_response[0]
    tracker: tracker_handler.Tracker = handler_response[1]

    print("Got tracker response")

    # DOES HANDSHAKES WITH PEERS, FINDS OUT WHICH PEERS ARE AVAILABLE. !! KEEPS CONNECTION OPEN VIA SOCKET !!
    client_peer: peers_handler.Peer = peers_handler.Peer(UNIQUE_CLIENT_ID, info_hash, "localhost", 0)
    peer_connections = {}

    while peer_connections == {}:
        peer_connections: dict[peers_handler.Peer, socket.socket] = client_peer.perform_handshakes(peers_dict)

    print("Handshaked")
    # old_connections = peer_connections
    #
    # # SEARCHES FOR ADDITIONAL PEERS USING DHT, THEN CHECKS AVAILABILITY OF THOSE PEERS
    # new_peers: set = client_peer.find_all_additional_peers(peer_connections)
    # new_peers_dict = {}
    # for ip, port in new_peers:
    #     new_peers_dict[ip] = port
    # additional_peer_connections: dict[peers_handler.Peer, socket.socket] = client_peer.perform_handshakes(new_peers_dict)
    #
    # # COMPLETE PEER LIST THAT THE PROGRAM WILL BE WORKING WITH
    # peer_connections: dict[peers_handler.Peer, socket.socket] = peer_connections | additional_peer_connections
    # print("Handshaked some more")
    #
    # if old_connections == peer_connections:
    #     print("NOTHING CHANGED!")

    pprint(peer_connections)

    client_peer.send_all_interested(peer_connections)

    print("Got bitfield")

    # DOWNLOADING PROCESS
    client_peer.download_process(num_pieces, piece_length, peer_connections, torrent_info)




if __name__ == "__main__":
    version: str = "0045"
    IP_ADDRESS: str = requests.get('https://api.ipify.org').content.decode('utf8')

    client_prefix = "RK-" + version + "-"
    random_suffix = uuid4().hex[:12]
    combined_id = client_prefix + random_suffix
    UNIQUE_CLIENT_ID: str = combined_id[:20]
    # 20 BYTE CLIENT ID, UNIQUE FOR EVERY INSTANCE OF THE PROGRAM

    main()

