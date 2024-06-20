import socket
import requests


class HTTP_Tracker:
    def __init__(self, tracker_url: str, info_hash: str, size: int, unique_id: str, ip_address: str):
        self.info_hash: bytes = bytes.fromhex(info_hash)
        self.peer_id: bytes = bytes.fromhex(unique_id)
        self.ip: str = ip_address
        self.port: int = 6881
        self.size: int = size
        self.tracker_url: str = tracker_url
        self.downloaded: int = 0

    def send_peers_request(self):
        params: dict = \
            {"info_hash": self.info_hash,
             "peer_id": self.peer_id,
             "ip": self.ip,
             "port": self.port,
             "uploaded": 0,
             "downloaded": self.downloaded,
             "left": self.size - self.downloaded,
             "event": "started",
             "compact": 1}

        while self.port <= 6889:
            try:
                response: requests.Response = requests.get(self.tracker_url, params=params, timeout=5)
                response.raise_for_status()
                peer_info: bytes = response.content
                return peer_info
            except (requests.RequestException, requests.HTTPError):
                self.port += 1
                continue
        return None

    def inform_tracker(self, event: str):
        params: dict = \
            {"info_hash": self.info_hash,
             "peer_id": self.peer_id,
             "ip": self.ip,
             "port": self.port,
             "uploaded": 0,
             "downloaded": self.downloaded,
             "left": self.size - self.downloaded,
             "event": event,
             "no_peer_id": 1}

        response: requests.Response = requests.get(self.tracker_url, params=params, timeout=5)
        response.raise_for_status()


class UDP_Tracker:
    def __int__(self):
        self.placeHolder = "BUILDING"

    def send_request(self):
        return self.placeHolder.encode()


def announce_to_peers(announce_list: list[str], info_hash: str, size: int, unique_id: str, ip_address: str) -> (bytes, str):
    for tracker_url in announce_list:
        if tracker_url[:3] == "udp":
            UDP_Connection = UDP_Tracker()
            peer_info = UDP_Connection.send_request()
            return peer_info, tracker_url
        if tracker_url[:4] == "http":
            HTTP_Connection = HTTP_Tracker(tracker_url, info_hash, size, unique_id, ip_address)
            peer_info = HTTP_Connection.send_peers_request()
            return peer_info, tracker_url
        else:
            continue
