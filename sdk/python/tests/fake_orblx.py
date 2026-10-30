#!/usr/bin/env python3
"""A fake `orblx` command for the SDK unit tests.

It prints the same `key value` lines as the real command. The state file
in FAKE_ORBLX_STATE counts fetch calls, so a grant is pending first.
"""

import json
import os
import sys
import time


def main() -> int:
    args = sys.argv[1:]
    state_path = os.environ["FAKE_ORBLX_STATE"]
    with open(state_path, encoding="utf-8") as handle:
        state = json.load(handle)
    state.setdefault("calls", []).append(args)
    code = 0
    flags = {}
    for index, arg in enumerate(args[:-1]):
        if arg.startswith("--"):
            flags[arg] = args[index + 1]
    if args[:3] == ["agent", "grant", "request"]:
        print("grant_id 0123456789abcdef")
        print("grant_state pending")
        print(f"grant_agent {flags.get('--agent')}")
    elif args[:3] == ["agent", "grant", "fetch"]:
        state["fetches"] = state.get("fetches", 0) + 1
        if state["fetches"] <= state.get("pending_fetches", 1):
            print(f"grant_id {flags['--id']}")
            print("grant_state pending")
            code = 3
        else:
            expires_ms = int(time.time() * 1000) + state.get("ttl_ms", 60000)
            state["expires_ms"] = expires_ms
            for line in [
                f"grant_id {flags['--id']}",
                "grant_state issued",
                "grant_agent spiffe://orblx.local/agent/bot",
                "grant_node spiffe://orblx.local/node/b",
                "grant_addr 100.64.0.3",
                "grant_service api",
                "grant_port 8080",
                "grant_path /api",
                "grant_approver spiffe://orblx.local/node/owner",
                f"grant_not_before {expires_ms // 1000 - 60}",
                f"grant_expires {expires_ms // 1000}",
                f"grant_expires_ms {expires_ms}",
                f"grant_files {flags['--out']}",
            ]:
                print(line)
    elif args[:2] == ["agent", "http"]:
        path = flags.get("--path", "/")
        method = flags.get("--method", "GET")
        now = int(time.time() * 1000)
        if now >= state.get("expires_ms", 0):
            print(f"http attempt 1 status 403 reason expired method {method} path {path} at_ms {now}")
            code = 3
        elif not (path == "/api" or path.startswith("/api/")):
            print(f"http attempt 1 status 403 reason path method {method} path {path} at_ms {now}")
            code = 3
        else:
            print(f"http attempt 1 status 200 method {method} path {path} at_ms {now} body upstream ok path {path}")
    elif args[:1] == ["broken"]:
        print("-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----", file=sys.stderr)
        code = 1
    else:
        print("The mode is not valid.", file=sys.stderr)
        code = 2
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    return code


if __name__ == "__main__":
    sys.exit(main())
