import socket
import requests
from bencoding import bdecode, bencode
from hashlib import sha1
import urllib.parse
import uuid
from pprint import pprint


def read_torrent(path: str) -> (dict, str, int):
    with open(path, "rb") as file:
        content = file.read()
        torrent_json: dict = bdecode(content)

        hashed_info: str = sha1(bencode(torrent_json[b'info'])).hexdigest()

        size: int = sum(file[b'length'] for file in torrent_json[b'info'][b'files'])

        return torrent_json, hashed_info, size


def tracker_request(tracker_url: str, info_hash: str, size: int):
    port = 6881

    params: dict = \
        {"info_hash": bytes.fromhex(info_hash),
         "peer_id": bytes.fromhex(UNIQUE_CLIENT_ID),
         "ip": IP_ADDRESS,
         "port": port,
         "uploaded": 0,
         "downloaded": 0,
         "left": size}

    while port <= 6889:
        try:
            response = requests.get(tracker_url, params=params, timeout=5)
            response.raise_for_status()
            peer_info = response.text
            return peer_info
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            port += 1
            continue

    return None


def main():
    test_torrent: str = "C:\\Users\\mensc\\Downloads\\" \
                     "Atomic_Heart.torrent"

    torrent, info_hash, size = read_torrent(test_torrent)

    announce_list = [torrent[b'announce'].decode()] + \
                    list(map(lambda tracker: tracker[0].decode(), torrent[b'announce-list']))

    responses = []
    for tracker_url in announce_list:
        print(f"Trying {tracker_url}")
        peer_info = tracker_request(tracker_url=tracker_url, info_hash=info_hash, size=size)
        if peer_info is not None:
            responses.append(peer_info)

    print(f"Drumrolls... {responses}")


if __name__ == "__main__":
    IP_ADDRESS: str = requests.get('https://api.ipify.org').content.decode('utf8')
    CLIENT_SOCKET: socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    UNIQUE_CLIENT_ID: str = uuid.uuid4().hex[:20]

    main()

