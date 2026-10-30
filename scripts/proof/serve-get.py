#!/usr/bin/env python3
"""HTTPS GET for the orblx serve proof.

serve-get.py HOST PORT BUNDLE WANT_URI

The client checks the server certificate chain against BUNDLE (the orblx.local CA).
The SVID has a URI SAN and no DNS name. The client checks the URI SAN, not the host name.
The client prints one result line. It does not print keys.
Exit 0: the GET worked. Exit 2: no TCP connection. Exit 3: TLS or HTTP failed.
"""

import socket
import ssl
import sys


def main():
    host, port, bundle, want = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=bundle)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    try:
        raw = socket.create_connection((host, port), timeout=5)
    except OSError as err:
        print("get %s:%d tcp_failed %s" % (host, port, type(err).__name__))
        return 2
    try:
        tls = context.wrap_socket(raw)
        cert = tls.getpeercert()
        uris = [value for kind, value in cert.get("subjectAltName", ()) if kind == "URI"]
        if want not in uris:
            print("get %s:%d san_mismatch %s" % (host, port, ",".join(uris)))
            return 3
        request = "GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host
        version = tls.version()
        tls.sendall(request.encode())
        data = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            data += chunk
        tls.close()
    except (OSError, ssl.SSLError) as err:
        print("get %s:%d tls_failed %s" % (host, port, type(err).__name__))
        return 3
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    print("get %s:%d status %s tls %s san %s body %s" % (
        host, port, status, version, ",".join(uris), body.decode(errors="replace").strip()))
    return 0 if " 200 " in status + " " else 3


if __name__ == "__main__":
    sys.exit(main())
