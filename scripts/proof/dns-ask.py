#!/usr/bin/env python3
"""Send one A query and print the rcode and the first address.

Usage: dns-ask.py NAME SERVER
Usage: dns-ask.py --until-not ADDRESS NAME SERVER DEADLINE_MS
The second form asks each 20 ms. It prints the epoch ms of the first answer
without ADDRESS.
"""

import socket
import sys
import time


def encode(name):
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def ask(name, server, ident=0x1234):
    query = ident.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    query += encode(name) + b"\x00\x01\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(1500)
    finally:
        sock.close()
    rcode = data[3] & 15
    answers = int.from_bytes(data[6:8], "big")
    address = "-"
    if answers and len(data) >= 4 and data[-4:]:
        address = socket.inet_ntoa(data[-4:])
    return rcode, answers, address


def main():
    if sys.argv[1] == "--until-not":
        old, name, server, deadline_ms = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
        end = time.time() + deadline_ms / 1000.0
        ident = 1
        while time.time() < end:
            ident = (ident + 1) & 0xFFFF
            try:
                rcode, answers, address = ask(name, server, ident)
            except OSError:
                time.sleep(0.02)
                continue
            if address != old:
                now = int(time.time() * 1000)
                print("changed_at_ms %d %s rcode %d answers %d address %s" % (now, name, rcode, answers, address))
                return
            time.sleep(0.02)
        raise SystemExit("The answer for %s did not change." % name)
    name, server = sys.argv[1], sys.argv[2]
    rcode, answers, address = ask(name, server)
    print("%s rcode %d answers %d address %s" % (name, rcode, answers, address))


if __name__ == "__main__":
    main()
