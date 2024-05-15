import socket
import struct
import requests
from bcoding import bdecode, bencode
from hashlib import sha1
import logging
from uuid import uuid4
from pprint import pprint


def read_torrent(path: str) -> (dict, str, int):
    with open(path, "rb") as file:
        content = file.read()
        torrent_json: dict = bdecode(content)
        hashed_info: str = sha1(bencode(torrent_json['info'])).hexdigest()
        size: int = sum(file['length'] for file in torrent_json['info']['files'])

        return torrent_json, hashed_info, size


def tracker_request(tracker_url: str, info_hash: str, size: int):
    port = 6881

    params: dict =\
        {"info_hash": bytes.fromhex(info_hash),
         "peer_id": bytes.fromhex(UNIQUE_CLIENT_ID),
         "ip": IP_ADDRESS,
         "port": port,
         "uploaded": 0,
         "downloaded": 0,
         "left": size,
         "compact": 1}

    while port <= 6889:
        try:
            response = requests.get(tracker_url, params=params, timeout=5)
            response.raise_for_status()
            peer_info = response.content
            return peer_info
        except (requests.RequestException, requests.HTTPError) as e:
            logging.exception(e)
            port += 1
            continue

    return None


def main():
    test_torrent: str = "C:\\Users\\mensc\\Downloads\\"\
                        "Atomic_Heart.torrent"

    torrent, info_hash, size = read_torrent(test_torrent)
    announce_list = [torrent['announce'], torrent['announce-list']]


    responses = []

    for tracker_url in announce_list:
        print(f"Trying {tracker_url}")
        peer_info = tracker_request(tracker_url=tracker_url, info_hash=info_hash, size=size)
        if peer_info is not None:
            responses.append(peer_info)


    for response in responses:
        list_peers = bdecode(response)
        print(list_peers)

        if type(list_peers['peers']) != list:
            offset = 0

            '''
                              - Handles bytes form of list of peers
                              - IP address in bytes form:
                              - Size of each IP: 6 bytes
                              - The first 4 bytes are for IP address
                              - Next 2 bytes are for port number
                              - To unpack initial 4 bytes !i (big-endian, 4 bytes) is used.
                              - To unpack next 2 byets !H(big-endian, 2 bytes) is used.
            '''

            for _ in range(len(list_peers['peers']) // 6):
                ip = struct.unpack_from("!i", list_peers['peers'], offset)[0]
                ip = socket.inet_ntoa(struct.pack("!i", ip))
                offset += 4
                port = struct.unpack_from("!H", list_peers['peers'], offset)[0]
                offset += 2

                print(f"IP: {ip}, PORT: {port}")
        else:
            for peer in list_peers:
                ip = peer['ip']
                port = peer['port']

                print(f"IP: {ip}, PORT: {port}")


if __name__ == "__main__":
    IP_ADDRESS: str = requests.get('https://api.ipify.org').content.decode('utf8')
    CLIENT_SOCKET: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UNIQUE_CLIENT_ID: str = uuid4().hex[:20]

    main()

