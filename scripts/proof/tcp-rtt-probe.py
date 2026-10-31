#!/usr/bin/env python3
"""W25-39 plain TCP RTT probe over the overlay. No orblx code is in the path.

serve HOST PORT          echo one line back on each connection
probe HOST PORT SECS MS  open one connection every MS ms for SECS s, send one line,
                         read the echo, close; print one line per attempt (Unix us)
"""
import socket
import socketserver
import sys
import time


def now_us():
    return time.time_ns() // 1000


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline()
        self.wfile.write(line)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def probe(host, port, secs, every_ms):
    end = time.monotonic() + secs
    n = 0
    while time.monotonic() < end:
        n += 1
        start = now_us()
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                connect = now_us()
                local = sock.getsockname()[1]
                sock.sendall(b"ping\n")
                data = b""
                while not data.endswith(b"\n"):
                    chunk = sock.recv(64)
                    if not chunk:
                        break
                    data += chunk
                reply = now_us()
            print(f"probe n {n} start_us {start} connect_us {connect} reply_us {reply} port {local} result ok", flush=True)
        except OSError as err:
            print(f"probe n {n} start_us {start} result failed error {type(err).__name__}", flush=True)
        time.sleep(every_ms / 1000)


def main():
    mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    if mode == "serve":
        with Server((host, port), Echo) as server:
            server.serve_forever()
    else:
        probe(host, port, float(sys.argv[4]), float(sys.argv[5]))


if __name__ == "__main__":
    main()
