import socket
import requests
import struct
from logging import exception
from bcoding import bdecode
from urllib.parse import urlparse


def http_tracker_request(tracker_url: str, info_hash: str, size: int, unique_id: str, ip_address: str):
    port: int = 6881
    params: dict = \
        {"info_hash": bytes.fromhex(info_hash),
         "peer_id": bytes.fromhex(unique_id),
         "ip": ip_address,
         "port": port,
         "uploaded": 0,
         "downloaded": 0,
         "left": size,
         "compact": 1}

    while port <= 6889:
        try:
            response: requests.Response = requests.get(tracker_url, params=params, timeout=5)
            response.raise_for_status()
            peer_info = response.content
            return peer_info
        except (requests.RequestException, requests.HTTPError) as e:
            exception(e)
            port += 1
            continue
    return None


""" UNFINISHED:
def udp_tracker_request(tracker_url: str, info_hash: str, size: int, unique_id: str, ip_address: str):
    parsed = urlparse(tracker_url)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(4)
    tracker_ip, tracker_port = socket.gethostbyname(parsed.hostname), parsed.port
"""


def decode_str_peers(peers: dict) -> dict:
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

    for _ in range(len(peers['peers']) // 6):
        ip: str = struct.unpack_from("!i", peers['peers'], offset)[0]
        ip: str = socket.inet_ntoa(struct.pack("!i", ip))
        offset += 4
        port: str = struct.unpack_from("!H", peers['peers'], offset)[0]
        offset += 2

        peer_dict[ip] = port

    return peer_dict


def announce_to_peers(announce_list: list[str], info_hash: str, size: int, unique_id: str, ip_address: str) -> dict:
    responses: list = []

    for tracker_url in announce_list:
        if tracker_url[:3] == "udp":
            continue  # ADD UDP SUPPORT
        if tracker_url[:4] == "http":
            peer_info = http_tracker_request(tracker_url, info_hash, size, unique_id, ip_address)
        else:
            peer_info = None

        if peer_info is not None:
            responses.append(peer_info)

    peer_dict: dict[str, int] = {}

    for response in responses:
        try:
            peers = bdecode(response)
            if type(peers['peers']) != list:
                peer_dict = decode_str_peers(peers)

            else:
                for peer in peers:
                    ip = peer['ip']
                    port = peer['port']

                    peer[ip] = port
            return peer_dict

        except (struct.error, TypeError, ValueError) as e:
            continue

    return {}
