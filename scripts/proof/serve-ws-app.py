#!/usr/bin/env python3
"""Local WebSocket echo app for the W25-4 serve proof.

serve-ws-app.py PORT LOG_FILE

The app binds 127.0.0.1:PORT. It uses only the Python standard library (RFC 6455).
GET with "Upgrade: websocket" gets "101 Switching Protocols". Then the app sends back
each text or binary message. A close frame gets a close frame back.
A GET without "Upgrade: websocket" gets "200" and the text "ws app".
The app appends one line for each connection to LOG_FILE: the number of messages and bytes.
The app does not log the WebSocket key or the request path.
"""

import base64
import hashlib
import socket
import struct
import sys
import threading

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def read_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def read_frame(conn):
    head = read_exact(conn, 2)
    opcode = head[0] & 0x0F
    masked = head[1] & 0x80
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(conn, 8))[0]
    mask = read_exact(conn, 4) if masked else b"\0\0\0\0"
    payload = bytearray(read_exact(conn, length))
    for i in range(length):
        payload[i] ^= mask[i % 4]
    return opcode, bytes(payload), bool(masked)


def frame(opcode, payload):
    length = len(payload)
    if length < 126:
        head = struct.pack("!BB", 0x80 | opcode, length)
    elif length < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 126, length)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, length)
    return head + payload


def handle(conn, log_file):
    with conn:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = head.split("\r\n")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        if headers.get("upgrade", "").lower() != "websocket":
            body = b"ws app\n"
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
            return
        key = headers.get("sec-websocket-key", "").encode()
        accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        messages = 0
        total = 0
        unmasked = 0
        try:
            while True:
                opcode, payload, masked = read_frame(conn)
                if not masked:
                    unmasked += 1
                if opcode == 8:
                    conn.sendall(frame(8, payload[:2]))
                    break
                if opcode in (1, 2):
                    messages += 1
                    total += len(payload)
                    conn.sendall(frame(opcode, payload))
                elif opcode == 9:
                    conn.sendall(frame(10, payload))
        except (ConnectionError, OSError):
            pass
        with open(log_file, "a") as out:
            out.write("ws_app messages %d bytes %d unmasked %d xff %s\n" % (
                messages, total, unmasked, headers.get("x-forwarded-for", "none")))


def main():
    port, log_file = int(sys.argv[1]), sys.argv[2]
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(16)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn, log_file), daemon=True).start()


if __name__ == "__main__":
    main()
