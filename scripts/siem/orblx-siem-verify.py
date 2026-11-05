#!/usr/bin/env python3
"""Check the orblx config audit chain from SIEM sink output only (W25-13).

The script reads the bytes that a SIEM sink got from the orblx coordinator:

- ndjson:  one body object on each line.
- hec:     Splunk HEC event objects, one on each line. The body is in "event".
- datadog: JSON arrays, one on each line. The body is a JSON string in "message".
- syslog:  RFC 5425 octet-counting frames with RFC 5424 messages. The body is the MSG.

It checks each record again: the sequence is 0, 1, 2, ... with no gap and no copy,
seq is the record index, id is the record hash, each record links to the hash before
it, and SHA-256 over the canonical bytes gives the record hash. A changed, removed, or
added record fails the check. --count and --tip also catch a removed last record.

It needs only the Python standard library. It does not need the coordinator.
Exit 0 and "siem_verify_ok" mean that the chain is complete and not changed.
"""

import argparse
import hashlib
import json
import re
import sys
import time

BODY_TYPE = "orblx.config-audit"
BODY_VERSION = 1
EVENT_VERSION = 1
GENESIS = "00" * 32

# The action names in code order: code 1 is the first name.
# The Rust test `the_siem_verifier_knows_each_action_code` checks this list.
ACTIONS = [
    "policy-load", "policy-replace", "policy-reject", "approve", "revoke",
    "expire", "routes", "exit-node", "enroll", "agent-grant",
    "agent-approve", "agent-use", "agent-deny", "agent-expire", "agent-revoke",
    "serve", "serve-off", "funnel-on", "funnel-off", "lock-init",
    "lock-sign", "lock-rotate", "lock-remove", "file-receive", "file-deny",
    "token-create", "token-use", "token-deny", "token-revoke", "share",
    "unshare", "packet-deny", "unrevoke", "sink-error", "user-approve",
    "user-reject", "reserved-37", "route-failover", "ssh-cert",
    "reserved-40", "netmap-seq-reset",
]

SYSLOG_HEAD = re.compile(
    r'^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) '
    r'\[orblx@32473 seq="(\d+)" id="([0-9a-f]{64})" action="([a-z-]+)"\] (.*)$',
    re.S,
)


class Bad(Exception):
    pass


def text_bytes(value):
    data = value.encode("utf-8")
    if len(data) > 0xFFFF:
        raise Bad("text too long")
    return len(data).to_bytes(2, "big") + data


def hex32(value, what):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise Bad(f"{what} is not 32-byte hex")
    return bytes.fromhex(value)


def record_hash(record):
    action = record["action"]
    if action not in ACTIONS or action.startswith("reserved-"):
        raise Bad(f"unknown action {action}")
    canonical = (
        bytes([EVENT_VERSION, ACTIONS.index(action) + 1])
        + int(record["at_unix"]).to_bytes(8, "big")
        + text_bytes(record["actor"])
        + text_bytes(record["target"])
        + hex32(record["before"], "before")
        + hex32(record["after"], "after")
        + text_bytes(record["detail"])
    )
    prev = hex32(record["prev_hash"], "prev_hash")
    return hashlib.sha256(prev + canonical).hexdigest()


def utc_text(at_unix):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at_unix))


def bodies_ndjson(data):
    for line in data.decode("utf-8").split("\n"):
        if line.strip():
            yield json.loads(line)


def bodies_hec(data):
    for line in data.decode("utf-8").split("\n"):
        if not line.strip():
            continue
        event = json.loads(line)
        body = event["event"]
        if event.get("time") != body["record"]["at_unix"]:
            raise Bad(f"hec time does not match seq {body.get('seq')}")
        yield body


def bodies_datadog(data):
    for line in data.decode("utf-8").split("\n"):
        if not line.strip():
            continue
        for item in json.loads(line):
            body = json.loads(item["message"])
            tags = f"action:{body['record']['action']},seq:{body['seq']}"
            if item.get("ddtags") != tags:
                raise Bad(f"datadog tags do not match seq {body.get('seq')}")
            yield body


def bodies_syslog(data):
    at = 0
    while at < len(data):
        space = data.find(b" ", at)
        if space < 0 or space - at > 10 or not data[at:space].isdigit():
            raise Bad(f"bad syslog frame length at byte {at}")
        length = int(data[at:space])
        start = space + 1
        if start + length > len(data):
            raise Bad(f"short syslog frame at byte {at}")
        message = data[start:start + length].decode("utf-8")
        at = start + length
        head = SYSLOG_HEAD.match(message)
        if not head:
            raise Bad(f"bad syslog header at byte {start}")
        body = json.loads(head.group(10))
        record = body["record"]
        if (
            int(head.group(7)) != body["seq"]
            or head.group(8) != body["id"]
            or head.group(9) != record["action"]
            or head.group(2) != record["at_utc"]
        ):
            raise Bad(f"syslog header does not match seq {body.get('seq')}")
        yield body


READERS = {
    "ndjson": bodies_ndjson,
    "hec": bodies_hec,
    "datadog": bodies_datadog,
    "syslog": bodies_syslog,
}


def verify(bodies, start=0):
    seen = {}
    prev = None
    expect = start
    count = 0
    duplicates = 0
    for body in bodies:
        if body.get("type") != BODY_TYPE or body.get("version") != BODY_VERSION:
            raise Bad("bad body type or version")
        seq = body["seq"]
        record = body["record"]
        if seq in seen:
            duplicates += 1
            raise Bad(f"duplicate seq {seq}")
        if seq != expect:
            raise Bad(f"gap or order: want seq {expect}, got seq {seq}")
        if record["index"] != seq or record["hash"] != body["id"]:
            raise Bad(f"seq or id does not match the record at seq {seq}")
        if prev is None:
            if seq == 0 and record["prev_hash"] != GENESIS:
                raise Bad("seq 0 does not start at genesis")
        elif record["prev_hash"] != prev:
            raise Bad(f"broken link at seq {seq}")
        if record_hash(record) != record["hash"]:
            raise Bad(f"bad hash at seq {seq}")
        if utc_text(int(record["at_unix"])) != record["at_utc"]:
            raise Bad(f"bad at_utc at seq {seq}")
        seen[seq] = body["id"]
        prev = record["hash"]
        expect += 1
        count += 1
    return count, prev or GENESIS, duplicates


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--format", required=True, choices=sorted(READERS))
    parser.add_argument("--count", type=int, help="the expected number of records")
    parser.add_argument("--tip", help="the expected hash of the last record")
    parser.add_argument("--start", type=int, default=0, help="the first seq (default 0)")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    data = b""
    for name in args.files:
        with open(name, "rb") as handle:
            data += handle.read()
    try:
        count, tip, _ = verify(READERS[args.format](data), args.start)
        if args.count is not None and count != args.count:
            raise Bad(f"want {args.count} records, got {count}")
        if args.tip is not None and tip != args.tip:
            raise Bad("the last hash is not the expected tip")
    except Bad as err:
        print(f"siem_verify_fail format {args.format} reason {err}")
        return 1
    except (KeyError, TypeError, ValueError) as err:
        print(f"siem_verify_fail format {args.format} reason parse {type(err).__name__}")
        return 1
    print(f"siem_verify_ok format {args.format} records {count} tip {tip}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
