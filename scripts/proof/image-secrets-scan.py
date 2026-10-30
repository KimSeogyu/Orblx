#!/usr/bin/env python3
"""Scan a saved container image for secrets (W25-8).

Usage: docker save IMAGE | image-secrets-scan.py [--needle-file FILE]... [--expect-hit]

The script reads the tar from `docker save` on stdin. It opens each layer and
each config blob, and looks for:
  - a PEM block with a base64 body (a key, a certificate, or another PEM item),
  - a file with a state name: key.pem, cert.pem, bundle.pem, ticket.bin, *.key,
  - each needle value (for example an enroll token) from --needle-file.
The orblx binary has PEM label strings, but it has no PEM body. A label alone
is not a hit.
The script prints only the layer, the path, and the hit kind. It does not print a
needle value or a PEM body.
Exit 0: no hit (or a hit with --expect-hit). Exit 1: a hit (or no hit with --expect-hit).
"""

import argparse
import gzip
import io
import re
import sys
import tarfile

PEM = re.compile(
    rb"-----BEGIN [A-Z0-9 ]{3,40}-----\s{0,4}[A-Za-z0-9+/=\r\n]{48,}"
)
STATE_NAMES = {"key.pem", "cert.pem", "bundle.pem", "trust-bundle.pem", "ticket.bin"}
STATE_SUFFIXES = (".key",)


def open_tar(data):
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    try:
        return tarfile.open(fileobj=io.BytesIO(data), mode="r:")
    except tarfile.ReadError:
        return None


def scan_blob(where, data, needles, hits):
    if PEM.search(data):
        hits.append((where, "pem-block"))
    for index, needle in enumerate(needles):
        if needle in data:
            hits.append((where, f"needle-{index}"))


def scan_layer(name, data, needles, hits):
    layer = open_tar(data)
    if layer is None:
        scan_blob(name, data, needles, hits)
        return 0
    count = 0
    for member in layer:
        if not member.isfile():
            continue
        count += 1
        base = member.name.rsplit("/", 1)[-1]
        where = f"{name}:{member.name}"
        if base in STATE_NAMES or base.endswith(STATE_SUFFIXES):
            hits.append((where, "state-file-name"))
        handle = layer.extractfile(member)
        if handle is not None:
            scan_blob(where, handle.read(), needles, hits)
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--needle-file", action="append", default=[])
    parser.add_argument("--expect-hit", action="store_true")
    args = parser.parse_args()
    needles = []
    for path in args.needle_file:
        with open(path, "rb") as handle:
            value = handle.read().strip()
        if len(value) < 8:
            print(f"The needle in {path} is too short.", file=sys.stderr)
            return 2
        needles.append(value)

    outer = tarfile.open(fileobj=sys.stdin.buffer, mode="r|")
    hits = []
    layers = 0
    files = 0
    for member in outer:
        if not member.isfile():
            continue
        handle = outer.extractfile(member)
        if handle is None:
            continue
        data = handle.read()
        if member.name.endswith(".json") or member.name in ("manifest.json", "index.json", "repositories"):
            scan_blob(member.name, data, needles, hits)
            continue
        # scan_layer scans a blob that is not a tar (for example the config JSON) as one blob.
        counted = scan_layer(member.name, data, needles, hits)
        if counted:
            layers += 1
            files += counted
    print(f"layers {layers} files {files} needles {len(needles)} hits {len(hits)}")
    for where, kind in hits:
        print(f"hit {kind} {where}")
    if layers == 0:
        print("The input has no image layers.", file=sys.stderr)
        return 2
    if args.expect_hit:
        return 0 if hits else 1
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
