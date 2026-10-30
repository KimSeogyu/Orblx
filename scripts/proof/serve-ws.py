#!/usr/bin/env python3
"""WebSocket client for the W25-4 serve proof.

serve-ws.py HOST PORT BUNDLE WANT_URI echo COUNT KEY_FILE
serve-ws.py HOST PORT BUNDLE WANT_URI upgrade VALUE

The client checks the server certificate chain against BUNDLE (the orblx.local CA) and the URI SAN.
echo: open a WebSocket, send COUNT messages of different sizes (up to 70000 bytes),
read each echo, and compare it. Then send a close frame. The client appends its random
Sec-WebSocket-Key to KEY_FILE, so the proof can check that no log has it. It does not print the key.
upgrade: send "GET /" with "Upgrade: VALUE" and print the status line.
The client prints one result line. Exit 0: the step worked. Exit 2: no TCP connection.
Exit 3: TLS failed. Exit 4: the WebSocket or the echo failed.
"""

import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
import time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def read_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def read_head(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("latin-1")


def send_frame(conn, opcode, payload):
    mask = os.urandom(4)
    length = len(payload)
    if length < 126:
        head = struct.pack("!BB", 0x80 | opcode, 0x80 | length)
    elif length < 65536:
        head = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, length)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, length)
    body = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    conn.sendall(head + mask + body)


def read_frame(conn):
    head = read_exact(conn, 2)
    opcode = head[0] & 0x0F
    length = head[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(conn, 8))[0]
    return opcode, read_exact(conn, length)


def message(index):
    sizes = [1, 125, 126, 1000, 65535, 65536, 70000]
    size = sizes[index % len(sizes)] if index % 10 == 0 else 16 + index
    seed = ("msg %d " % index).encode()
    return (seed * (size // len(seed) + 1))[:size]


def main():
    host, port, bundle, want, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=bundle)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        raw = socket.create_connection((host, port), timeout=5)
    except OSError as err:
        print("ws %s:%d tcp_failed %s" % (host, port, type(err).__name__))
        return 2
    try:
        tls = context.wrap_socket(raw)
        uris = [v for k, v in tls.getpeercert().get("subjectAltName", ()) if k == "URI"]
    except (OSError, ssl.SSLError) as err:
        print("ws %s:%d tls_failed %s" % (host, port, type(err).__name__))
        return 3
    if want not in uris:
        print("ws %s:%d san_mismatch" % (host, port))
        return 3
    tls.settimeout(10)
    if mode == "upgrade":
        value = sys.argv[6]
        tls.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade, HTTP2-Settings\r\n"
                     "Upgrade: %s\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n"
                     "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (
                         host, value, base64.b64encode(os.urandom(16)).decode())).encode())
        head = read_head(tls)
        print("upgrade %s status %s" % (value.replace(" ", ""), head.split("\r\n", 1)[0]))
        return 0
    count, key_file = int(sys.argv[6]), sys.argv[7]
    key = base64.b64encode(os.urandom(16))
    with open(key_file, "a") as out:
        out.write(key.decode() + "\n")
    tls.sendall(b"GET /chat HTTP/1.1\r\nHost: " + host.encode() + b"\r\nUpgrade: websocket\r\n"
                b"Connection: Upgrade\r\nSec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n")
    head = read_head(tls)
    status = head.split("\r\n", 1)[0]
    accept = base64.b64encode(hashlib.sha1(key + GUID).digest()).decode()
    if " 101 " not in status + " " or ("sec-websocket-accept: " + accept.lower()) not in head.lower():
        print("ws %s:%d status %s accept_ok no" % (host, port, status))
        return 4
    sent = received = lost = total = 0
    rtts = []
    try:
        for index in range(count):
            payload = message(index)
            start = time.monotonic()
            send_frame(tls, 1 if index % 2 == 0 else 2, payload)
            sent += 1
            opcode, echo = read_frame(tls)
            rtts.append((time.monotonic() - start) * 1000)
            if echo == payload:
                received += 1
                total += len(echo)
            else:
                lost += 1
        send_frame(tls, 8, struct.pack("!H", 1000))
        opcode, _ = read_frame(tls)
        closed = "yes" if opcode == 8 else "no"
        # Send TLS close_notify, so the proxy sees a clean end of the stream.
        try:
            tls.unwrap().close()
        except (OSError, ssl.SSLError):
            closed = "unclean"
    except (OSError, ConnectionError, ssl.SSLError) as err:
        print("ws %s:%d failed %s sent %d received %d" % (host, port, type(err).__name__, sent, received))
        return 4
    slowest = max(range(len(rtts)), key=lambda i: rtts[i])
    ordered = sorted(rtts)
    print("ws %s:%d status %s accept_ok yes sent %d received %d lost %d bytes %d "
          "largest %d close %s rtt_ms median %.3f max %.3f slowest_size %d" % (
              host, port, status, sent, received, lost, total,
              max(len(message(i)) for i in range(count)), closed,
              ordered[len(ordered) // 2], ordered[-1], len(message(slowest))))
    return 0 if received == count and lost == 0 else 4


if __name__ == "__main__":
    sys.exit(main())
