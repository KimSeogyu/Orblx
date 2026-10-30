# W25-10 HA subnet routers

Two orblx nodes can advertise the same subnet route.
The client sends the traffic for that route to one active router.
When the active router stops, the client moves the route to the other router. No person must do a step.
A router that comes back does not take the route back. Thus the route does not flap.

Marks: **[C]** = shown in the container proof on one Linux host. **REAL** = shown on real hosts.
This change has no REAL result. All results below are [C].

## Design

The coordinator did not change.
It already published each approved route for each node, so two routers with the same route were already in the signed netmap.
The old client rejected that netmap (`RouterError::Ambiguous`).

| Part | Change |
|---|---|
| `crates/orblx-datapath/src/router.rs` | A subnet prefix has a list of routers, sorted by name. An overlay address still has one owner. A subnet route cannot take an overlay address. |
| `crates/orblx-datapath/src/ha.rs` | `RouteSelector`: the active router for each HA route. `RouteAudit`: the `route-failover` audit chain. |
| `crates/orblx-datapath/src/node.rs` | The TUN reader asks the selector for each packet to an HA route. The keepalive interval is 250 ms (was 1 s). |
| `crates/orblx-audit/src/config.rs` | New config action `route-failover`, code 35 (W25-13 took 34). |

Selection rules:

1. A router is healthy when the node has a session with it and received a frame (data or keepalive) from it in the last 1000 ms (`HA_DEAD_AFTER`, 4 keepalive intervals).
2. The active router stays while it is healthy.
3. When the active router is not healthy, the first healthy router in name order becomes active.
4. When no router is healthy, the active router stays.
5. A router that becomes healthy again does not take the route back (no failback).

The selection uses only local data: the session table and the time of the last received frame.
It adds no frame, no netmap field, and no crypto.
It does not use BGP, VRRP, a kernel routing daemon, or a new crate.
The client log has one line for each selection: `The HA route CIDR uses ROUTER. The router before was OLD.`

Each move from one router to another writes one record to `route-audit.jsonl` in the node state directory.
The first selection writes no record.
The record has the action `route-failover`, the actor (the SPIFFE ID of the client), the target (the route), and the detail `from OLD to NEW old_silent_ms N` (`no-session` when the old router has no session).
The chain uses the hash chain of `orblx-audit`. `orblx audit verify-config --file route-audit.jsonl` checks it.
A separate thread writes the records (queue of 64). The datapath does not wait for the disk.

The router side did not change.
Each router forwards the route with kernel forwarding and `iptables` MASQUERADE (W18), and its packet filter uses its own signed grants (W24-A).
Thus the port ACL and the UDP 53 gate apply on each router.

## Policy

Each router needs approval. A router that advertises the route without approval is not in the client netmap for that route, and it gets no `subnets` grant rows.

Use `autoApprovers.routes` for an HA route with port rules:

```hujson
"autoApprovers": {
  "routes": {
    "10.88.125.0/24": [
      "spiffe://orblx.local/node/router-a",
      "spiffe://orblx.local/node/router-b",
    ],
  },
},
```

Note: `routeApprovals` approves one exact CIDR. The router grants get a `subnets` row only when the policy approves a prefix that contains the row destination.
Thus with `routeApprovals` for `10.88.125.0/24`, a rule to `10.88.125.5/32` gives the router no row, and the router filter drops the traffic.
This behavior is from W24-A. This change does not change it. `docs/w24-port-acl.md` says that `routeApprovals` also gives rows. That is correct only for a rule whose destination is the exact approved CIDR.

## Proof [C]

`scripts/proof/ha-routers.sh` (Docker Compose `scripts/proof/compose.ha-routers.yml`, policy `scripts/proof/ha-routers.hujson`).
The proof takes the W25-5 box proof lock (`scripts/proof/proof-lock.sh`).

| Host | Label | Role |
|---|---|---|
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` | [C] | Coordinator. Policy file mount |
| `router-a`, `router-b` | [C] | Subnet routers for `10.88.125.0/24` (LAN `10.88.125.2`, `10.88.125.3`) |
| `client` | [C] | `--accept-routes`. `group:humans` |
| `guest` | [C] | `--accept-routes`. No rule |
| `target` | [C] | LAN host `10.88.125.5`. UDP 9000 and 9001, TCP 8080, 8081, and 8090 (echo). No orblx process |
| `landns` | [C] | LAN nameserver `10.88.125.53` |

The routers masquerade. Thus the target sees the LAN address of the router, and the proof knows which router carried each datagram.
The proof kills a router with `docker kill` (SIGKILL, no clean stop).
The proof uses a release build. With a debug build on a loaded host, the overlay queued the replies (ping RTT avg 21 ms, bursts of up to 3.8 s) before and after the kill. With the release build, the RTT avg was 0.63 ms.

### Results [C]

Branch head c33d30a (main c32d46f), release build, 5 runs.
Log: `/workspace/orblx-w18-proof/w25ha-routers-full4.log` (03:09:21 to 03:14:42 KST, 31 Oct 2026). Other orblx proof containers: 0 at the start, 0 at the end.

| Gate | Result [C] |
|---|---|
| 1. Both routes need approval | Only router-a approved: router-b got 0 FORWARD bytes, and the target got 0 datagrams while router-a was down. After both approvals, the client netmap has both routers for `10.88.125.0/24`. |
| 2. Failover (limit 5000 ms, target 2000 ms) | 1015, 1028, 1012, 1000, 992 ms. 5/5 at or below 2000 ms. |
| 2. Max gap of the UDP stream (10 ms interval) | 982, 1001, 987, 976, 964 ms |
| 2. Ping loss (`ping -i 0.05`, 9 s) | 17/171, 17/169, 17/168, 17/171, 17/171 |
| 2. Audit | +1 `route-failover` record for each kill. Example: `{"actor":"spiffe://orblx.local/node/client","target":"10.88.125.0/24","action":"route-failover","detail":"from router-a to router-b old_silent_ms 1001"}`. The chain verifies. |
| 3. Failback | router-a came back. 0 route changes and 0 records in 60 s. All 5892 datagrams came through router-b. |
| 4. Port ACL on router-b | TCP 8080 allowed. TCP 8081 and UDP 9001 (no rule): 0 FORWARD bytes, 3 packet-deny records. Guest TCP 8080: timeout. |
| 4. UDP 53 on router-b | With the rule: 1 answer (`10.88.24.20`), 57 bytes. Without the rule: no answer, 0 bytes, 0 queries at the nameserver, 1 deny record. |
| 5. TCP flow | The flow does not survive. It reconnected 1107 ms after the kill (the read timed out at 1105 ms). |
| 6. Secrets | 0 lines in all container logs with a token value, a key line, or `PRIVATE KEY` (19 patterns, 403 log lines). |
| Leak | 0 packets from the client and the guest to `10.88.125.0/24` on the underlay interface. |
| Ping before the kills | max 2.117 ms. Baseline 0/95 lost, RTT avg 1.098 ms. |

The failover time is about `HA_DEAD_AFTER` (1000 ms): the client moves the route at the first packet after 1000 ms with no frame from the active router.

An earlier run on head f2887a7 (before the merge of #92) had the same result: failover 989 to 1074 ms, TCP reconnect 1125 ms (log `w25ha-routers-full3.log`).


### W23-4 gates [C]

`scripts/proof/nat-realism.sh` with `ORBLX_NATR_POLICY=scripts/proof/nat-realism-acl.hujson` (the filter is on), release build, branch head b145e54, 1 run.
Log: `/workspace/orblx-w18-proof/w25ha-b145e542-natr-branch-run1.log` (lock 03:55:48 to 04:01:38 KST). Other orblx proof containers: 0.

| prc direct Mbit/s | prc relay Mbit/s | sym relay Mbit/s | prc relay / direct RTT avg ms | sym relay / direct RTT avg ms | lost |
|---|---|---|---|---|---|
| 1405.71 (W24 median 1112.65) | 1341.03 (1269.68) | 1386.52 (1136.20) | 1.035 / 0.551 | 0.954 / 0.551 | 0/50, 0/50 |

The relay RTT is within direct + 1 ms. The steady ping max was 1.525 ms or less (limit 100 ms).

## Limits

- Since W25-6 (#92), the node applies a new netmap with no restart, and it prints the new HA routes. The proof still restarts the client after it approves router-b. Thus the proof does not show the HA change with no restart.
- An old client rejects a netmap with two routers for one route (`RouterError::Ambiguous`). Update the clients before you approve a second router.
- An old router sends a keepalive each 1 s. With such a router, an idle link can be older than 1000 ms, and the client can move the route. Update the routers and the clients together.
- No failback. After a failover, the route stays on the new router until that router fails.
- A TCP flow does not survive a failover. The new router has no conntrack entry, and its MASQUERADE address is different. The application must connect again.
- The client moves the route on the first packet after the active router is not healthy. Thus the move needs traffic.
- At most 2 routers for each route are in scope. The code accepts more, but the proof checks 2.
- No load balancing. One router carries all traffic for a route.
- No app connectors.
- IPv4 only.
