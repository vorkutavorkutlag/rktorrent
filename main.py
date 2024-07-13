import socket
import threading
import time

from bcoding import bdecode, bencode
from hashlib import sha1
from math import ceil
from pprint import pprint
from typing import Callable

import peers_handler
import tracker_handler

MAX_PEERS = 60


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




def run(selected_dir: str, selected_torrent: str,
        cancel_event: threading.Event, pause_event: threading.Event, update: Callable,
        ip_address: str, client_uuid: str) -> int:
    # CALLS THE READ TORRENT FUNCTION, GETS IMPORTANT INFO
    update(0, "Reading file...", 0)
    announce_list, piece_length, info_hash, size, num_pieces, torrent_info = read_torrent(selected_torrent)

    # FINDS A STABLE CONNECTION WITH A TRACKER, REQUESTS PEER INFO
    update(0, "Communicating with tracker server...", 0)
    handler_response = \
        tracker_handler.announce_to_peers(announce_list, info_hash, size, client_uuid, ip_address, 0)

    peers_dict: dict = handler_response[0]
    trackers: list[tracker_handler.Tracker] = handler_response[1]


    if cancel_event.is_set():
        return 0
    while pause_event.is_set():
        time.sleep(1)

    update(0, "Handshaking with peers...", 0)

    # DOES HANDSHAKES WITH PEERS, FINDS OUT WHICH PEERS ARE AVAILABLE. !! KEEPS CONNECTION OPEN VIA SOCKET !!
    client_peer: peers_handler.Peer = peers_handler.Peer(client_uuid, info_hash, "localhost", 0)
    peer_connections: dict[peers_handler.Peer, socket.socket] = {}

    while peer_connections == {}:
        if cancel_event.is_set():
            return 0
        while pause_event.is_set():
            time.sleep(1)
        peer_connections: dict[peers_handler.Peer, socket.socket] = client_peer.perform_handshakes(peers_dict,
                            cancel_event=cancel_event, pause_event=pause_event)
        time.sleep(1)


    # old_connections = peer_connections
    #
    # # SEARCHES FOR ADDITIONAL PEERS USING DHT, THEN CHECKS AVAILABILITY OF THOSE PEERS
    # new_peers: set = client_peer.find_all_additional_peers(peer_connections)
    # new_peers_dict = {}
    # for ip, port in new_peers:
    #     new_peers_dict[ip] = port
    # additional_peer_connections: dict[peers_handler.Peer,
    # socket.socket] = client_peer.perform_handshakes(new_peers_dict)
    #
    # # COMPLETE PEER LIST THAT THE PROGRAM WILL BE WORKING WITH
    # peer_connections: dict[peers_handler.Peer, socket.socket] = peer_connections | additional_peer_connections
    # print("Handshaked some more")
    #
    # if old_connections == peer_connections:
    #     print("NOTHING CHANGED!")

    # MAKES SURE WE ARE CONTACTING MO MORE THAN MAX_PEERS PEERS
    if len(peer_connections) > MAX_PEERS:
        filtered_connections: dict = {}
        for peer, sock in list(peer_connections.items())[:MAX_PEERS]:
            filtered_connections[peer] = sock
        peer_connections = filtered_connections

    if cancel_event.is_set():
        return 0
    while pause_event.is_set():
        time.sleep(1)

    update(0, "Getting bitfields...", 0)
    client_peer.send_all_interested(peer_connections)

    # DOWNLOADING PROCESS
    update(0, "Beginning download process...", 0)
    try:
        client_peer.download_process(num_pieces, piece_length, peer_connections,
                                 torrent_info, selected_dir, size, cancel_event, pause_event, update)
        return 0
    except Exception as e:
        return int(repr(e))
