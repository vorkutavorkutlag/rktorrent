import socket
import requests
from bcoding import bdecode, bencode
from hashlib import sha1
import struct
from uuid import uuid4
from pprint import pprint

import tracker_handler


def read_torrent(path: str) -> (dict, str, int):
    with open(path, "rb") as file:
        content: bytes = file.read()
        torrent_json: dict = bdecode(content)
        hashed_info: str = sha1(bencode(torrent_json['info'])).hexdigest()
        announce_list: list[str] = [torrent_json['announce'], torrent_json['announce-list']]
        piece_length: int = torrent_json['info']['piece length']

        if 'files' not in torrent_json['info'].keys():
            num_files: int = 1
            size: int = torrent_json['info']['length']
        else:
            num_files: int = len(torrent_json['info']['files'])
            size: int = sum(file['length'] for file in torrent_json['info']['files'])

        return announce_list, piece_length, hashed_info, size


def decode_str_peers(peers_info: dict) -> dict:
    peer_dict: dict = {}
    offset: int = 0

    '''
                      - Handles bytes form of list of peers
                      - IP address in bytes form:
                      - Size of each IP: 6 bytes
                      - The first 4 bytes are for IP address
                      - Next 2 bytes are for port number
                      - To unpack initial 4 bytes !i (big-endian, 4 bytes) is used.
                      - To unpack next 2 byets !H(big-endian, 2 bytes) is used.
    '''

    for _ in range(len(peers_info['peers']) // 6):
        ip: str = struct.unpack_from("!i", peers_info['peers'], offset)[0]
        ip: str = socket.inet_ntoa(struct.pack("!i", ip))
        offset += 4
        port: str = struct.unpack_from("!H", peers_info['peers'], offset)[0]
        offset += 2

        peer_dict[ip] = port

    return peer_dict


def main():
    test_torrent: str = "C:\\Users\\mensc\\Downloads\\Atomic_Heart.torrent"
    announce_list, piece_length, info_hash, size = read_torrent(test_torrent)

    peers_dict, tracker_conn = \
        tracker_handler.announce_to_peers(announce_list, info_hash, size, UNIQUE_CLIENT_ID, IP_ADDRESS)

    pprint(announce_list)
    pprint(peers_dict)


if __name__ == "__main__":
    version: str = "0045"
    IP_ADDRESS: str = requests.get('https://api.ipify.org').content.decode('utf8')
    CLIENT_SOCKET: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UNIQUE_CLIENT_ID: str = ("RK-"+version+"-").encode().hex()+uuid4().hex[:12]

    main()

