#!/usr/bin/env python3
"""Example agent for the orblx agent SDK.

The agent asks for one grant, waits for a human owner to approve it, and
calls the gateway. Then it checks a request outside the path scope and
the stop after the grant end. It prints `sdk ...` lines for the proof.
"""

import argparse
import logging
import sys
import time

from orblx_agent import AgentClient, CoordTarget

LIMIT_MS = 1000


def main() -> int:
    parser = argparse.ArgumentParser(description="orblx example agent")
    parser.add_argument("--coord", required=True)
    parser.add_argument("--state", default="/var/lib/orblx")
    parser.add_argument("--agent", default="sdkbot")
    parser.add_argument("--node", required=True)
    parser.add_argument("--service", default="api")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--path", default="/api")
    parser.add_argument("--ttl", type=int, default=20)
    parser.add_argument("--out", required=True)
    parser.add_argument("--approve-wait", type=float, default=120)
    parser.add_argument("--log", default=None, help="SDK debug log file")
    args = parser.parse_args()

    if args.log:
        logging.basicConfig(filename=args.log, level=logging.DEBUG,
                            format="%(asctime)s %(name)s %(levelname)s %(message)s")

    client = AgentClient(CoordTarget(coord=args.coord, state=args.state), agent=args.agent)
    grant_id = client.request_grant(args.node, args.service, args.port, args.ttl, path=args.path)
    print(f"sdk grant_id {grant_id} state pending", flush=True)

    grant = client.wait_for_approval(grant_id, args.out, wait=args.approve_wait, poll=2)
    print(f"sdk grant_issued {grant.grant_id} approver {grant.approver} expires_ms {grant.expires_ms}", flush=True)

    ok = client.call(grant, f"{args.path}/items")
    print(f"sdk call status {ok.status} body {ok.body}", flush=True)
    if not ok.ok:
        return 1

    post = client.call(grant, f"{args.path}/items", method="POST", body="hello sdk")
    print(f"sdk post status {post.status} body {post.body}", flush=True)
    if not post.ok:
        return 1

    outside = client.call(grant, "/admin")
    print(f"sdk out_of_scope status {outside.status} reason {outside.reason}", flush=True)
    if outside.status != 403 or outside.reason != "path":
        return 1

    last_ok_start = 0
    while True:
        reply = client.call(grant, f"{args.path}/items")
        if reply.ok:
            last_ok_start = reply.at_ms
        else:
            delta = reply.done_ms - grant.expires_ms
            print(f"sdk expiry first_deny_ms {reply.done_ms} expires_ms {grant.expires_ms} "
                  f"last_ok_start_ms {last_ok_start} deny_after_end_ms {delta} reason {reply.reason}",
                  flush=True)
            if reply.reason != "expired" or delta > LIMIT_MS or last_ok_start >= grant.expires_ms:
                return 1
            break
        if time.time() * 1000 > grant.expires_ms + 10_000:
            print("sdk expiry no deny", flush=True)
            return 1
        time.sleep(0.05)

    print("sdk agent_ok", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
