#!/usr/bin/env python3
"""W25-13 SIEM sink receivers for the proof. They stand in for a SIEM.

https: an HTTPS server on RECV_PORT with RECV_CERT and RECV_KEY. Each path is one sink:
  /services/collector/event  Splunk HEC lines.   Header "Authorization: Splunk <cred>".
  /api/v2/logs               Datadog JSON array. Header "DD-API-KEY: <cred>".
  /ndjson                    NDJSON lines.       Header "Authorization: Bearer <cred>".
  The credential files are RECV_CRED_DIR/<sink>.token. A bad credential gets 401.
  The receiver does not keep or print a header value.
syslog: a TLS server on RECV_PORT. It reads RFC 5425 frames until the client sends
  close_notify, keeps the frames, and then sends close_notify (the ack).

Each sink keeps the raw bytes in RECV_DIR/<sink>/sink.out (one HTTP body on each line)
and one line for each record in RECV_DIR/<sink>/arrivals.jsonl: {"seq", "recv_ms"}.
The files use fsync before the reply or the ack.
"""
import hmac
import http.server
import json
import os
import re
import socket
import ssl
import sys
import threading
import time

LOCK = threading.Lock()
PATHS = {
    "/services/collector/event": ("hec", "Authorization", "Splunk "),
    "/api/v2/logs": ("datadog", "DD-API-KEY", ""),
    "/ndjson": ("ndjson", "Authorization", "Bearer "),
}
SD_SEQ = re.compile(rb'\[orblx@32473 seq="(\d+)"')


def out_dir(sink):
    path = os.path.join(os.environ.get("RECV_DIR", "/recv"), sink)
    os.makedirs(path, exist_ok=True)
    return path


def keep(sink, raw, seqs, recv_ms):
    path = out_dir(sink)
    with LOCK:
        with open(os.path.join(path, "sink.out"), "ab") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        with open(os.path.join(path, "arrivals.jsonl"), "a") as handle:
            for seq in seqs:
                handle.write(json.dumps({"seq": seq, "recv_ms": round(recv_ms, 3)}) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def count(sink, name):
    path = os.path.join(out_dir(sink), name)
    with LOCK:
        with open(path, "a") as handle:
            handle.write("1\n")


def credential(sink):
    with open(os.path.join(os.environ["RECV_CRED_DIR"], sink + ".token"), "rb") as handle:
        raw = handle.read()
    return raw.rstrip(b"\r\n")


def seqs_of(fmt, body):
    if fmt == "datadog":
        return [json.loads(item["message"])["seq"] for item in json.loads(body)]
    out = []
    for line in body.decode("utf-8").split("\n"):
        if line.strip():
            value = json.loads(line)
            out.append((value["event"] if fmt == "hec" else value)["seq"])
    return out


def tls_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(os.environ["RECV_CERT"], os.environ["RECV_KEY"])
    return context


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802
        recv_ms = time.time() * 1000.0
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        route = PATHS.get(self.path)
        if route is None:
            return self.reply(404, b"{}")
        fmt, header, prefix = route
        got = self.headers.get(header, "").encode("utf-8")
        if not hmac.compare_digest(got, prefix.encode("utf-8") + credential(fmt)):
            count(fmt, "rejected.txt")
            return self.reply(401, b'{"text":"Invalid token","code":4}')
        try:
            seqs = seqs_of(fmt, body)
        except (ValueError, KeyError, TypeError):
            count(fmt, "bad-body.txt")
            return self.reply(400, b"{}")
        raw = body if body.endswith(b"\n") else body + b"\n"
        keep(fmt, raw, seqs, recv_ms)
        if fmt == "hec":
            return self.reply(200, b'{"text":"Success","code":0}')
        return self.reply(202, b"{}")

    def reply(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        sys.stdout.write("receiver %s\n" % (fmt % args))
        sys.stdout.flush()


class TlsHttpServer(http.server.ThreadingHTTPServer):
    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(10)
        try:
            return CONTEXT.wrap_socket(sock, server_side=True), addr
        except (ssl.SSLError, OSError):
            sock.close()
            raise OSError("tls handshake failed")


def serve_https(port):
    server = TlsHttpServer(("0.0.0.0", port), Handler)
    print("receiver https listen %d" % port, flush=True)
    server.serve_forever()


def syslog_conn(raw_sock, sink):
    raw_sock.settimeout(10)
    try:
        conn = CONTEXT.wrap_socket(raw_sock, server_side=True)
    except (ssl.SSLError, OSError):
        count(sink, "handshake-fail.txt")
        print("receiver syslog tls handshake failed", flush=True)
        raw_sock.close()
        return
    buf = b""
    frames = []
    clean = False
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                clean = True
                break
            buf += data
            recv_ms = time.time() * 1000.0
            while True:
                space = buf.find(b" ")
                if space <= 0:
                    break
                length = int(buf[:space])
                if len(buf) < space + 1 + length:
                    break
                frame = buf[: space + 1 + length]
                buf = buf[space + 1 + length:]
                match = SD_SEQ.search(frame)
                frames.append((frame, int(match.group(1)) if match else -1, recv_ms))
    except (ssl.SSLError, OSError, ValueError):
        clean = False
    if clean and not buf and frames:
        path = out_dir(sink)
        with LOCK:
            with open(os.path.join(path, "sink.out"), "ab") as handle:
                for frame, _, _ in frames:
                    handle.write(frame)
                handle.flush()
                os.fsync(handle.fileno())
            with open(os.path.join(path, "arrivals.jsonl"), "a") as handle:
                for _, seq, recv_ms in frames:
                    handle.write(json.dumps({"seq": seq, "recv_ms": round(recv_ms, 3)}) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        try:
            conn.unwrap()
        except (ssl.SSLError, OSError):
            pass
    conn.close()


def serve_syslog(port, sink):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(64)
    print("receiver syslog listen %d" % port, flush=True)
    while True:
        raw_sock, _ = listener.accept()
        threading.Thread(target=syslog_conn, args=(raw_sock, sink), daemon=True).start()


CONTEXT = None
if __name__ == "__main__":
    CONTEXT = tls_context()
    port = int(os.environ["RECV_PORT"])
    if sys.argv[1] == "https":
        serve_https(port)
    else:
        serve_syslog(port, os.environ.get("RECV_SINK", "syslog"))
