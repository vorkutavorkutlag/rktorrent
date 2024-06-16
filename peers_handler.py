def handshake(info_hash: str, unique_id: str):
    info_hash_bytes = bytes.fromhex(info_hash)
    uid_bytes = unique_id.encode('utf-8')

    pstr = b'BitTorrent protocol'
    pstrlen = bytes([len(pstr)])
    reserved = b'\x00\x00\x00\x00\x00\x00\x00\x00'

    hs = (
            pstrlen +
            pstr +
            reserved +
            info_hash_bytes +
            uid_bytes)

    print(hs)

handshake("12345678901234567890abcdefabcdef12345678", "-PC0001-123456789012")