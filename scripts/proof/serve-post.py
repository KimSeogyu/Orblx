#!/usr/bin/env python3
"""HTTPS POST for the W24-C serve proof.

serve-post.py HOST PORT BUNDLE WANT_URI MODE SIZE

MODE chunked: the client sends a chunked body of SIZE bytes in 65536-byte chunks.
MODE length: the client sends Content-Length: SIZE and Expect: 100-continue.
It sends the body only after a 100 Continue response.
The body bytes are i % 251 for i in 0..SIZE. The client prints the byte sum it sent.
The client checks the server certificate like serve-get.py. It does not print keys.
The client prints one result line.
Exit 0: an HTTP response came back. Exit 2: no TCP connection. Exit 3: TLS or HTTP failed.
"""

import socket
import ssl
import sys

PATTERN = bytes(i % 251 for i in range(251 * 262))


def body_parts(size, step=65536):
    sent = 0
    while sent < size:
        n = min(step, size - sent)
        offset = sent % 251
        need = offset + n
        reps = PATTERN * (need // len(PATTERN) + 1)
        yield reps[offset:offset + n]
        sent += n


def read_response(tls):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = tls.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def main():
    host, port, bundle, want = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    mode, size = sys.argv[5], int(sys.argv[6])
    want_sum = sum(i % 251 for i in range(size))
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=bundle)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        raw = socket.create_connection((host, port), timeout=30)
    except OSError as err:
        print("post %s:%d tcp_failed %s" % (host, port, type(err).__name__))
        return 2
    try:
        tls = context.wrap_socket(raw)
        cert = tls.getpeercert()
        uris = [value for kind, value in cert.get("subjectAltName", ()) if kind == "URI"]
        if want not in uris:
            print("post %s:%d san_mismatch %s" % (host, port, ",".join(uris)))
            return 3
        continued = "none"
        if mode == "chunked":
            head = ("POST /upload HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n"
                    "Connection: close\r\n\r\n" % host)
            tls.sendall(head.encode())
            for part in body_parts(size):
                tls.sendall(b"%x\r\n" % len(part) + part + b"\r\n")
            tls.sendall(b"0\r\n\r\n")
            data = read_response(tls)
        else:
            head = ("POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n"
                    "Expect: 100-continue\r\nConnection: close\r\n\r\n" % (host, size))
            tls.sendall(head.encode())
            data = read_response(tls)
            if data.startswith(b"HTTP/1.1 100"):
                continued = "yes"
                data = data.split(b"\r\n\r\n", 1)[1]
                for part in body_parts(size):
                    tls.sendall(part)
                if b"\r\n\r\n" not in data:
                    data += read_response(tls)
            else:
                continued = "no"
        while True:
            try:
                chunk = tls.recv(65536)
            except (OSError, ssl.SSLError):
                break
            if not chunk:
                break
            data += chunk
        tls.close()
    except (OSError, ssl.SSLError) as err:
        print("post %s:%d tls_failed %s" % (host, port, type(err).__name__))
        return 3
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    print("post %s:%d mode %s size %d sent_sum %d continue %s status %s body %s" % (
        host, port, mode, size, want_sum, continued, status, body.decode(errors="replace").strip()))
    return 0 if status.startswith("HTTP/1.") else 3


if __name__ == "__main__":
    sys.exit(main())
