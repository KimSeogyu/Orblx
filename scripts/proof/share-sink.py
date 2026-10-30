#!/usr/bin/env python3
"""Count the bytes that arrive from each source address (W25-1 proof, gate 2).

Usage: share-sink.py serve PORT OUT_FILE
       share-sink.py send HOST PORT BYTES TIMEOUT_S

serve listens on TCP and UDP PORT on all addresses. For each source address it
writes one line "SOURCE BYTES" to OUT_FILE after each receive.
send tries one TCP connect and sends BYTES bytes, then sends BYTES bytes in UDP
datagrams of 1000 bytes. It prints what the sender saw. It always exits 0.
"""
import os
import selectors
import socket
import sys
import time


def serve(port, out):
    counts = {}

    def add(src, n):
        counts[src] = counts.get(src, 0) + n
        with open(out + ".tmp", "w") as f:
            for key, val in sorted(counts.items()):
                f.write(f"{key} {val}\n")
        os.replace(out + ".tmp", out)

    open(out, "w").close()
    sel = selectors.DefaultSelector()
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("0.0.0.0", port))
    tcp.listen(16)
    tcp.setblocking(False)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", port))
    udp.setblocking(False)
    sel.register(tcp, selectors.EVENT_READ, "accept")
    sel.register(udp, selectors.EVENT_READ, "udp")
    while True:
        for key, _ in sel.select():
            if key.data == "accept":
                conn, addr = tcp.accept()
                conn.setblocking(False)
                add(addr[0], 0)
                sel.register(conn, selectors.EVENT_READ, ("tcp", addr[0]))
            elif key.data == "udp":
                data, addr = udp.recvfrom(65535)
                add(addr[0], len(data))
            else:
                try:
                    data = key.fileobj.recv(65536)
                except OSError:
                    data = b""
                if data:
                    add(key.data[1], len(data))
                else:
                    sel.unregister(key.fileobj)
                    key.fileobj.close()


def send(host, port, nbytes, timeout):
    tcp_sent = 0
    tcp_state = "connected"
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(b"x" * nbytes)
            tcp_sent = nbytes
    except OSError as err:
        tcp_state = f"fail {type(err).__name__}"
    udp_sent = 0
    udp_state = "sent"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            left = nbytes
            while left > 0:
                n = min(1000, left)
                udp.sendto(b"u" * n, (host, port))
                udp_sent += n
                left -= n
                time.sleep(0.002)
    except OSError as err:
        udp_state = f"fail {type(err).__name__}"
    print(f"send {host}:{port} tcp {tcp_state} tcp_sent {tcp_sent} udp {udp_state} udp_sent {udp_sent}")


def main():
    if sys.argv[1] == "serve":
        serve(int(sys.argv[2]), sys.argv[3])
    else:
        send(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), float(sys.argv[5]))


if __name__ == "__main__":
    main()
