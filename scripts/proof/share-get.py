#!/usr/bin/env python3
"""Send one HTTP GET to HOST:PORT and exit 0 on an HTTP 200 reply (W25-1 proof).

The connect and the read time out after TIMEOUT_S seconds (default 0.4).
"""
import socket
import sys


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 0.4
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(b"GET / HTTP/1.0\r\n\r\n")
            head = conn.recv(64)
    except OSError as err:
        print(f"get {host}:{port} fail {type(err).__name__}")
        sys.exit(1)
    line = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
    print(f"get {host}:{port} {line}")
    sys.exit(0 if " 200 " in line else 1)


if __name__ == "__main__":
    main()
