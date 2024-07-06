import socket
import urllib.parse

import requests
import struct
from random import randint
from bcoding import bdecode


class Tracker:        # SIMPLE TRACKER INTERFACE, ONLY HAS THE BASIC ATTRIBUTES THAT OTHER VARIATIONS EXPAND ON
    def __init__(self, info_hash: bytes, size: int, unique_id: str, tracker_hn: str, downloaded: int):
        self.info_hash: bytes = info_hash
        self.peer_id: bytes = unique_id.encode()
        self.size: int = size
        self.downloaded: int = downloaded
        self.interval: int = 0  # Placeholder integer
        self.tracker_hostname = tracker_hn


    def peers_request(self) -> dict:
        return {}

    def inform_tracker(self, event: str) -> None:
        return None

    def finish(self) -> None:
        return None


class HTTP_Tracker(Tracker):   # TRACKER ACCORDING TO THE HTTP VARIATION OF THE PROTOCOL
    def __init__(self, tracker_url: str, info_hash: bytes, size: int, unique_id: str, ip_address: str, downloaded: int):
        super().__init__(info_hash, size, unique_id, tracker_url, downloaded)
        self.ip: str = ip_address
        self.port: int = 6881

    # PEER REQUEST ACCORDING TO THE HTTP TRACKER PROTOCOL
    def peers_request(self) -> dict:
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
                response: requests.Response = requests.get(self.tracker_hostname, params=params, timeout=5)
                response.raise_for_status()
                tracker_response: bytes = response.content

                peer_dict: dict = {}
                tracker_response = bdecode(tracker_response)
                if type(tracker_response['peers']) != list:
                    offset: int = 0

                    '''                 
                                      - THIS IS THE COMPACT PEER DICT IN BYTES FORM 
                                      - IP address in bytes form:
                                      - Size of each IP: 6 bytes
                                      - The first 4 bytes are for IP address
                                      - Next 2 bytes are for port number
                                      - To unpack initial 4 bytes !i (big-endian, 4 bytes) is used.
                                      - To unpack next 2 byets !H (big-endian, 2 bytes) is used.
                    '''

                    for _ in range(len(tracker_response['peers']) // 6):
                        ip: str = struct.unpack_from("!i", tracker_response['peers'], offset)[0]
                        ip: str = socket.inet_ntoa(struct.pack("!i", ip))
                        offset += 4
                        port: str = struct.unpack_from("!H", tracker_response['peers'], offset)[0]
                        offset += 2

                        peer_dict[ip] = port

                else:
                    for peer in tracker_response['peers']:
                        ip = peer['ip']
                        port = peer['port']

                        peer_dict[ip] = port

                return peer_dict

            except (struct.error, TypeError, ValueError, requests.RequestException, requests.HTTPError):
                self.port += 1
                # CYCLE THROUGH THE PORTS 6881 to 6889, WHERE BITTORRENT TAKES PLACE
                continue

        return {}

    def inform_tracker(self, event: str):
        # INFORMS TRACKER OF DOWNLOAD PROGRESS WITHOUT NEEDING TO UNPACK PEER INFO
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

        response: requests.Response = requests.get(self.tracker_hostname, params=params, timeout=5)
        response.raise_for_status()

    def finish(self):
        event = "completed"
        self.inform_tracker(event)


class UDP_Tracker(Tracker):      # TRACKER ACCORDING TO THE UDP VARIATION OF THE PROTOCOL
    def __init__(self, tracker_url: urllib.parse.ParseResult, info_hash: bytes, size: int, unique_id: str, downloaded: int):
        super().__init__(info_hash, size, unique_id, tracker_url.hostname, downloaded)
        self.ip: int = 0
        self.port: int = tracker_url.port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # DGRAM - UDP. STREAM - TCP
        self.socket.settimeout(5)

    def connection_request(self) -> tuple:     # REQUESTS CONNECTION ACCORDING TO THE PROTOCOL
        connection_id = 0x41727101980  # Magic constant
        action = 0  # Action: connect
        transaction_id = randint(0, 65535)
        response_length = 16

        packet = struct.pack("!qii", connection_id, action, transaction_id)
        self.socket.sendto(packet, (self.tracker_hostname, self.port))
        response, _ = self.socket.recvfrom(response_length)
        res_action, res_transaction, connection_id = struct.unpack("!iiq", response)

        if res_action != 0 or res_transaction != transaction_id:
            raise Exception("Invalid connection response")

        return connection_id, transaction_id

    def peers_request(self) -> dict:
        connection_id, transaction_id = self.connection_request()
        action = 1  # Action: announce
        event = 2   # Event: started
        key = randint(0, 65535)
        uploaded = 0
        num_want = -1  # Default, means we don't care how much peers we get

        packet = struct.pack("!qii20s20sqqqiiiih", connection_id, action, transaction_id, self.info_hash, self.peer_id,
                             self.downloaded, self.size-self.downloaded, uploaded,
                             event, self.ip, key, num_want, self.port)

        try:
            self.socket.sendto(packet, (self.tracker_hostname, self.port))
            response, _ = self.socket.recvfrom(4096)

            res_action, res_transaction_id, interval, leechers, seeders = struct.unpack("!iiiii", response[:20])
            if res_action != 1 or res_transaction_id != transaction_id:
                raise Exception("Invalid announce response")

            peers_dict = {}
            for i in range(20, len(response), 6): # UNPACKS THE COMPACT BYTE LIST OF THE PEERS
                ip = struct.unpack("!I", response[i:i + 4])[0]
                port = struct.unpack("!H", response[i + 4:i + 6])[0]
                peers_dict[(socket.inet_ntoa(struct.pack("!I", ip)))] = port

            self.interval = interval
            return peers_dict

        except socket.error:
            return {}

    def inform_tracker(self, event: int) -> None:
        # INFORMS TRACKER OF DOWNLOAD PROGRESS WITHOUT NEEDING TO UNPACK PEER INFO
        connection_id, transaction_id = self.connection_request()
        action = 1  # Action: announce
        event = event  # Event: started
        key = randint(0, 65535)
        uploaded = 0
        num_want = -1  # Default, means we don't care how much we get

        packet = struct.pack("!qii20s20sqqqiiiih", connection_id, action, transaction_id, self.info_hash, self.peer_id,
                             self.downloaded, self.size - self.downloaded, uploaded,
                             event, self.ip, key, num_want, self.port)

        try:
            self.socket.sendto(packet, (self.tracker_hostname, self.port))
            response, _ = self.socket.recvfrom(4096)
        except socket.error:
            pass

    def finish(self):
        event = 1
        self.inform_tracker(event)
        self.socket.close()




def announce_to_peers(announce_list: list[str, list[str]], info_hash: bytes,
                      size: int, unique_id: str, ip_address: str, downloaded: int) -> (bytes, str):

    for tracker_url in announce_list:
        if type(tracker_url) is list:
            parsed_url = urllib.parse.urlparse(tracker_url[0])
        else:
            parsed_url = urllib.parse.urlparse(tracker_url)

        if parsed_url.scheme in ['udp']:
            try:
                Tracker_Conn: Tracker = UDP_Tracker(parsed_url, info_hash, size, unique_id, downloaded)
                peers_dict = Tracker_Conn.peers_request()
                return peers_dict, Tracker_Conn
            except (socket.timeout, socket.gaierror):
                continue

        if parsed_url.scheme in ['http']:
            Tracker_Conn: Tracker = HTTP_Tracker(tracker_url, info_hash, size, unique_id, ip_address, downloaded)
            peers_dict = Tracker_Conn.peers_request()
            if peers_dict == {}:
                continue
            return peers_dict, Tracker_Conn


