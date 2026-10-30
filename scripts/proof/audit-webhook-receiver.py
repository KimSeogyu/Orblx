#!/usr/bin/env python3
"""W25-7 audit webhook receiver for the proof.

serve: listen on RECV_PORT. Check X-Orblx-Signature (HMAC-SHA256 over the body) with the
secret in RECV_SECRET_FILE. A good body gets 200 and one line in RECV_DIR/received.jsonl.
A bad signature gets 401 and one line in RECV_DIR/rejected.jsonl. The receiver keeps each
good body in RECV_DIR/bodies/. The receiver never prints the secret.

verify BODY_FILE SIG_FILE: print "verify ok" (exit 0) or "verify fail" (exit 1).
"""
import hashlib
import hmac
import http.server
import json
import os
import sys
import time


def secret():
    with open(os.environ["RECV_SECRET_FILE"], "rb") as handle:
        raw = handle.read()
    return raw[:-1] if raw.endswith(b"\n") else raw


def signature_ok(key, body, header):
    if not header.startswith("sha256="):
        return False
    want = "sha256=" + hmac.new(key, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, header.strip())


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802
        recv_ms = time.time() * 1000.0
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        header = self.headers.get("X-Orblx-Signature", "")
        good = signature_ok(KEY, body, header)
        entry = {"recv_ms": round(recv_ms, 3), "sig_ok": good,
                 "hdr_seq": self.headers.get("X-Orblx-Seq", ""),
                 "hdr_id": self.headers.get("X-Orblx-Event-Id", "")}
        try:
            value = json.loads(body)
            entry.update({"seq": value.get("seq"), "id": value.get("id"),
                          "action": value.get("record", {}).get("action")})
        except ValueError:
            entry["seq"] = None
        out_dir = os.environ.get("RECV_DIR", "/recv")
        name = "received.jsonl" if good else "rejected.jsonl"
        if good:
            os.makedirs(os.path.join(out_dir, "bodies"), exist_ok=True)
            stem = os.path.join(out_dir, "bodies", "%s-%d" % (entry["seq"], int(recv_ms)))
            with open(stem + ".json", "wb") as handle:
                handle.write(body)
            with open(stem + ".sig", "w") as handle:
                handle.write(header)
        with open(os.path.join(out_dir, name), "a") as handle:
            handle.write(json.dumps(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        code = 200 if good else 401
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, fmt, *args):
        sys.stdout.write("receiver %s\n" % (fmt % args))
        sys.stdout.flush()


def main():
    global KEY
    KEY = secret()
    if len(sys.argv) >= 2 and sys.argv[1] == "verify":
        with open(sys.argv[2], "rb") as handle:
            body = handle.read()
        with open(sys.argv[3]) as handle:
            header = handle.read()
        ok = signature_ok(KEY, body, header)
        print("verify ok" if ok else "verify fail")
        sys.exit(0 if ok else 1)
    port = int(os.environ.get("RECV_PORT", "9000"))
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("receiver listen %d" % port, flush=True)
    server.serve_forever()


KEY = b""
if __name__ == "__main__":
    main()
