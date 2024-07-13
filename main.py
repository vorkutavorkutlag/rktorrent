import socket
import threading
import time

import requests.exceptions
from bcoding import bdecode, bencode
from hashlib import sha1
from math import ceil, floor
from typing import Callable
from uuid import uuid4
from requests import get

import peers_handler
import tracker_handler

MAX_PEERS = 60
exit_code = 0

version: str = "0110"
IP_ADDRESS: str = get('https://api.ipify.org').content.decode('utf8')
client_prefix = "RK-" + version + "-"
random_suffix = uuid4().hex[:12]
combined_id = client_prefix + random_suffix
UNIQUE_CLIENT_ID: str = combined_id[:20]
# 20 BYTE CLIENT ID, UNIQUE FOR EVERY INSTANCE OF THE PROGRAM


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
        cancel_event: threading.Event, pause_event: threading.Event, update: Callable) -> int:
    # CALLS THE READ TORRENT FUNCTION, GETS IMPORTANT INFO
    update(0, "Reading file...", 0)
    announce_list, piece_length, info_hash, size, num_pieces, torrent_info = read_torrent(selected_torrent)

    # FINDS A STABLE CONNECTION WITH A TRACKER, REQUESTS PEER INFO
    update(0, "Communicating with tracker server...", 0)
    handler_response = \
        tracker_handler.announce_to_peers(announce_list, info_hash, size, UNIQUE_CLIENT_ID, IP_ADDRESS, 0)

    peers_dict: dict = handler_response[0]
    trackers: list[tracker_handler.Tracker] = handler_response[1]
    tracker_threads: list[threading.Thread] = []
    for tracker in trackers:
        tracker_thread: threading.Thread = threading.Thread(target=tracker_comm, args=[tracker, cancel_event])
        tracker_threads.append(tracker_thread)
        tracker_thread.start()
    run_continuation_thread: threading.Thread = threading.Thread(target=run_continuation, args=[selected_dir,
                                                    info_hash, peers_dict, num_pieces, piece_length, size,
                                                    torrent_info, cancel_event, pause_event, update, UNIQUE_CLIENT_ID])
    run_continuation_thread.start()

    for tracker_thread in tracker_threads:
        tracker_thread.join()
    run_continuation_thread.join()

    return exit_code


def run_continuation(selected_dir: str, info_hash: bytes, peers_dict: dict, num_pieces: int, piece_length: int,
                     size: int, torrent_info: dict, cancel_event: threading.Event, pause_event: threading.Event,
                     update: Callable, client_uuid: str):
    global exit_code
    if cancel_event.is_set():
        return 0
    while pause_event.is_set():
        time.sleep(1)

    update(0, "Handshaking with peers...", 0)

    # DOES HANDSHAKES WITH PEERS, FINDS OUT WHICH PEERS ARE AVAILABLE. !! KEEPS CONNECTION OPEN VIA SOCKET !!
    client_peer: peers_handler.Peer = peers_handler.Peer(client_uuid, info_hash, "localhost", 0)
    peer_connections: dict[peers_handler.Peer, socket.socket] = {}

    time_started = time.time()
    while peer_connections == {}:
        if cancel_event.is_set():
            exit_code = 0
            return
        while pause_event.is_set():
            time.sleep(1)
        if time.time() - time_started > 30:
            exit_code = -1
            return
        peer_connections: dict[peers_handler.Peer, socket.socket] = client_peer.perform_handshakes(peers_dict,
                            cancel_event=cancel_event, pause_event=pause_event)
        time.sleep(1)


    # MAKES SURE WE ARE CONTACTING MO MORE THAN MAX_PEERS PEERS
    if len(peer_connections) > MAX_PEERS:
        filtered_connections: dict = {}
        for peer, sock in list(peer_connections.items())[:MAX_PEERS]:
            filtered_connections[peer] = sock
        peer_connections = filtered_connections

    if cancel_event.is_set():
        exit_code = 0
        return
    while pause_event.is_set():
        time.sleep(1)

    update(0, "Getting bitfields...", 0)
    client_peer.send_all_interested(peer_connections)

    # DOWNLOADING PROCESS
    update(0, "Beginning download process...", 0)
    try:
        client_peer.download_process(num_pieces, piece_length, peer_connections,
                                 torrent_info, selected_dir, size, cancel_event, pause_event, update)
        exit_code = 0
        return
    except Exception as e:
        exit_code = int(repr(e))
        return


def tracker_comm(tracker: tracker_handler.Tracker, cancel_event: threading.Event):
    while True:
        try:
            if cancel_event.is_set():
                tracker.close_gracefully()
                return
            for _ in range(floor(tracker.interval/5)):      # 5 = Number of seconds we are willing to wait.
                if cancel_event.is_set():
                    tracker.close_gracefully()
                    return
                tracker.downloaded = peers_handler.SIZE_OF_DOWNLOAD
                if tracker.downloaded == tracker.size:
                    tracker.finish_comm()
                    return
                time.sleep(5)
            tracker.inform_tracker_download()
        except (requests.exceptions.InvalidSchema, requests.exceptions.HTTPError, TimeoutError):
            return
