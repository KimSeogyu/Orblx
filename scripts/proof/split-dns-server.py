#!/usr/bin/env python3
"""Small UDP DNS server for the W24-F split DNS proof.

Mode lan: the zone nameserver behind the subnet router.
  db.corp.lan is 10.88.24.20. Other corp.lan names are NXDOMAIN.
  Names outside corp.lan are REFUSED.
Mode sys: the system resolver of the nodes.
  Every name is 192.0.2.1. A split DNS name here is a leak.
Each query writes one line with the name and the source address.
"""

import socket
import sys

LAN_RECORDS = {"db.corp.lan": "10.88.24.20"}
SYS_ANSWER = "192.0.2.1"


def read_name(msg, pos):
    labels = []
    while True:
        size = msg[pos]
        pos += 1
        if size == 0:
            break
        labels.append(msg[pos:pos + size].decode("ascii", "replace"))
        pos += size
    return ".".join(labels).lower(), pos


def answer(query, rcode, address):
    name, end = read_name(query, 12)
    question = query[12:end + 4]
    flags = 0x8000 | 0x0400 | (query[2] & 0x01) << 8 | 0x0080 | rcode
    count = 1 if address else 0
    out = query[:2] + flags.to_bytes(2, "big") + b"\x00\x01"
    out += count.to_bytes(2, "big") + b"\x00\x00\x00\x00" + question
    if address:
        out += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04"
        out += socket.inet_aton(address)
    return name, out


def main():
    mode, listen = sys.argv[1], sys.argv[2]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen, 53))
    print("dns server mode %s listens on %s:53" % (mode, listen), flush=True)
    while True:
        query, peer = sock.recvfrom(1500)
        if len(query) < 17:
            continue
        name, end = read_name(query, 12)
        qtype = int.from_bytes(query[end:end + 2], "big")
        if mode == "lan":
            if name in LAN_RECORDS:
                rcode, address = 0, LAN_RECORDS[name]
            elif name == "corp.lan" or name.endswith(".corp.lan"):
                rcode, address = 3, None
            else:
                rcode, address = 5, None
        else:
            rcode, address = 0, SYS_ANSWER
        if qtype != 1:
            address = None
        _, out = answer(query, rcode, address)
        sock.sendto(out, peer)
        print("query %s type %d from %s rcode %d" % (name, qtype, peer[0], rcode), flush=True)


if __name__ == "__main__":
    main()
