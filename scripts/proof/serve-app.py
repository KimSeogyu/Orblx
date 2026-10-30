#!/usr/bin/env python3
"""Local web app for the W24-C serve proof.

serve-app.py PORT INDEX_FILE LOG_FILE

The app binds 127.0.0.1:PORT.
GET returns the INDEX_FILE text.
POST reads the body by Content-Length. It returns one line with the body length,
the framing headers that it got, and the byte sum of the body.
The app appends each POST result line to LOG_FILE.
The app reads chunked bodies only through the orblx serve proxy, which sends Content-Length.
"""

import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    index = b""
    log_file = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.index)))
        self.end_headers()
        self.wfile.write(self.index)

    def do_POST(self):
        te = self.headers.get("Transfer-Encoding")
        cl = self.headers.get("Content-Length")
        size = int(cl) if cl is not None else 0
        left, total, got = size, 0, 0
        while left > 0:
            chunk = self.rfile.read(min(left, 65536))
            if not chunk:
                break
            got += len(chunk)
            total += sum(chunk)
            left -= len(chunk)
        text = "app got %d te %s cl %s sum %d\n" % (got, te or "none", cl or "none", total)
        with open(self.log_file, "a") as handle:
            handle.write(text)
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("app %s\n" % (fmt % args))


def main():
    port, index = int(sys.argv[1]), sys.argv[2]
    Handler.log_file = sys.argv[3]
    with open(index, "rb") as handle:
        Handler.index = handle.read()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
