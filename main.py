import socket
import requests
from bcoding import bdecode, bencode
from hashlib import sha1
import logging
from uuid import uuid4
from pprint import pprint

import tracker_handler


def read_torrent(path: str) -> (dict, str, int):
    with open(path, "rb") as file:
        content = file.read()
        torrent_json: dict = bdecode(content)
        hashed_info: str = sha1(bencode(torrent_json['info'])).hexdigest()
        size: int = sum(file['length'] for file in torrent_json['info']['files'])

        return torrent_json, hashed_info, size


def main():
    test_torrent: str = "C:\\Users\\mensc\\Downloads\\"\
                        "Atomic_Heart.torrent"

    torrent, info_hash, size = read_torrent(test_torrent)
    announce_list = [torrent['announce'], torrent['announce-list']]

    peer_dict: dict = tracker_handler.announce_to_peers(announce_list, info_hash, size, UNIQUE_CLIENT_ID, IP_ADDRESS)

    pprint(peer_dict)


if __name__ == "__main__":
    version: str = "2406"
    IP_ADDRESS: str = requests.get('https://api.ipify.org').content.decode('utf8')
    CLIENT_SOCKET: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UNIQUE_CLIENT_ID: str = ("RK-"+version  +"-").encode().hex()+uuid4().hex[:12]

    main()

