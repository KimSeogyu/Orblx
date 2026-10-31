#!/usr/bin/env python3
"""W25-28: a dead peer sink.

The sink binds UDP ports FIRST..LAST on ADDR. It records each datagram and never answers.
One line per datagram: "rx EPOCH_MS PORT SRC_IP LEN DCID". DCID is the destination connection ID
of a QUIC long header packet in hex, or "short" for a short header packet.
The sink does not record payload bytes.
"""
import selectors
import socket
import sys
import time


def dcid(data: bytes) -> str:
    if len(data) < 6 or not data[0] & 0x80:
        return "short"
    size = data[5]
    return data[6:6 + size].hex() or "empty"


def main() -> None:
    addr, first, last, out = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    sel = selectors.DefaultSelector()
    for port in range(first, last + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((addr, port))
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, port)
    with open(out, "a", buffering=1, encoding="ascii") as log:
        log.write(f"sink_ready {int(time.time() * 1000)} ports {first}-{last}\n")
        while True:
            for key, _ in sel.select():
                while True:
                    try:
                        data, src = key.fileobj.recvfrom(2048)
                    except BlockingIOError:
                        break
                    now = int(time.time() * 1000)
                    log.write(f"rx {now} {key.data} {src[0]} {len(data)} {dcid(data)}\n")


if __name__ == "__main__":
    main()
