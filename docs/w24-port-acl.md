# W24-A port ACL in the datapath

The policy can allow or deny traffic by protocol and port for each principal.
The receiving node enforces the policy in the datapath.

Marks: **[C]** = shown in the container proof on one Linux host. **REAL** = shown on real hosts.
This change has no REAL result. All results below are [C].

## Policy

The `acls` list of the HuJSON policy (W18-5) gives the allowed flows.
Each rule has `src`, `proto` (`tcp`, `udp`, or `icmp`), and `dst` (`principal:ports`).
An ICMP destination must use the port `*`.
A destination can also be an IPv4 address or CIDR behind a subnet router, for example `10.88.24.53/32:53` (a plain address is a /32).
`0.0.0.0/0` is an exit route. The policy rejects it as an ACL destination.
An agent source cannot use a subnet destination.

| Policy | Datapath |
|---|---|
| The policy has an `acls` list (also an empty list). | Default deny. The receiving node drops each packet to its overlay address that no rule allows. |
| The policy has no `acls` key. | Old behavior. The node does not check the protocol or the port. |

The coordinator compiles the rules into the signed receiver grants of each node (W18-5).
The grants now have the field `filter`. The field is true when the policy has an `acls` list.
The grants also have the field `subnets`: the subnet rows whose destination is inside a route that the policy approves for this node (`autoApprovers` or `routeApprovals`).
The node reads `grants.signed.json` again each second, so a policy change gets to the filter without a restart.

## Datapath rules

- The filter checks each packet from a peer that has the overlay address of this node as its destination.
  The check uses the SPIFFE ID of the peer session (the mTLS identity), the IP protocol, and the destination port.
- A reply to a flow that this node started passes. The filter keeps a flow table (idle time 180 s, at most 65 536 flows).
- An ICMP error passes only when the packet in the error is from a flow that this node started.
- A fragment after the first fragment has no port. The filter drops it when the filter is on.
- A packet to a subnet route that this node forwards needs a `subnets` row: source SPIFFE ID, protocol, destination address inside the row CIDR, and destination port.
  Else the node drops it and writes a `packet-deny` record (the `detail` has the destination address).
  The node gets its routes from `orblx up` (the approved routes, or `--advertise-routes` without a coordinator).
- A packet to an exit route (`0.0.0.0/0`) or to another address keeps the old behavior.
- The filter is in both datapaths: `orblx up` (`crates/orblx-datapath/src/node.rs`) and `orblx nat run` (`crates/orblx-edge/src/nat_run.rs`).

## Deny audit

The node writes the drops to the config audit chain `packet-audit.jsonl` in the node state directory, action `packet-deny`.
The chain uses the hash chain of `orblx-audit`. It does not add a new crypto design.

- At most one record for each source, protocol, and port in 10 s.
- At most 5 records in one second.
- A separate thread writes the records. The queue holds 64 records. When the queue is full, the datapath does not wait.
- The `detail` of each record has `unwritten_before N`: the number of drops that the node did not write since the last record.
  Thus the sum of the records and the `unwritten_before` values accounts for the drops.

## Revoke to datapath drop

`orblx admin revoke-all` (W24-D) adds the SVID of the principal to the coordinator deny list.

W25-1 (#77) is on main. It gives the revoke path below. This change adds one check to it.

| Step | Code |
|---|---|
| `orblx up` fetches the deny list | each 500 ms from the start of the fetch (W25-1) |
| The datapath reads `deny.json` | each 100 ms. The node applies the file only when its bytes change, and closes the sessions of the denied peers (W25-1). |
| A session that completes its handshake during the change | W24-A: `run_link` checks the deny list under the link lock before it adds the session, so the session does not stay open. |

The node lock allow list is still set again each 10 s.

## Proof

`scripts/proof/datapath-acl.sh` ([C], 3 nodes a, b, c and a coordinator, Docker on one host).
The policy is `scripts/proof/datapath-acl.hujson`: a may reach b on TCP 8080, UDP 9000 and 9500, and ICMP.
c may reach b on TCP 8080 only. No rule lets b open a flow to a or c.

Log: `/workspace/orblx-w18-proof/w24acl-branch-51b943e8-datapath-acl-run1.log` (branch head 51b943e8 on main 5b5bb3e). The run printed `proof_ok`.

| Gate | Check | Result [C] |
|---|---|---|
| 1. With an ACL list, the default is deny. | b has no rule to a: `b tcp 100.64.0.1:8080 timeout`, `ping b 100.64.0.1 fail`. c has no ICMP rule: `ping c 100.64.0.2 fail`. | pass |
| 2. Allowed ports work. Denied TCP and UDP ports get 0 bytes. | a and c to b TCP 8080 `connected reply ok`. a to b UDP 9000 `reply yes`. a and c to b TCP 8081 `timeout`. a to b UDP 9001 `reply none`. Listener on b: `tcp8081 0 udp9001 0`. | `denied_app_bytes 0` |
| 3. Each deny is audited with a rate limit. | a sends UDP to 200 denied ports (9100-9299). | `spray_denied 200 spray_records 11`. `unwritten_before` accounts for the other drops. `audit_verify ok`. |
| 4. Without an ACL list, the old behavior stays. | The proof removes the `acls` key. TCP 8081, UDP 9001, b to a TCP, and all pings pass. | `audit_records_no_acl 15 15` (no new record). The ACL list then comes back and TCP 8081 is dropped again. |
| 5. The datapath drops the revoked principal 1 s or less after revoke-all. | a sends UDP to b port 9500 each 20 ms. That port has no check of its own. c runs `orblx admin revoke-all a`. | `revoke_drop_ms 56` (limit 1000). `stamp_rx_after_revoke_done 3`. |

`revoke_drop_ms` is the receive time of the last datagram from a at b minus `revoke_done_ms`.

### Subnet route [C]

`scripts/proof/split-dns.sh` Gate 5 (W24-F stack: a router with the route 10.88.24.0/24, the corp.lan nameserver 10.88.24.53 behind it, node a accepts routes).
The router has the signed grants. The policy `scripts/proof/split-dns.hujson` lets `group:humans` use UDP to `10.88.24.53/32:53` and TCP to `10.88.24.20/32:80`.
The proof counts the forwarded bytes with an iptables FORWARD rule on the router (`-d 10.88.24.53 -p udp --dport 53`) and the queries in the nameserver log.

Log: `/workspace/orblx-w18-proof/w24acl-reb-1755055b-split-dns-run1.log`. The run printed `proof_ok`.

| Case | Result [C] |
|---|---|
| The policy allows UDP 53. a asks 10.88.24.53 for db.corp.lan. | `rcode 0 answers 1 address 10.88.24.20`. `allowed_fwd_bytes 57`, `allowed_landns_queries 1`. |
| The proof removes the UDP 53 rule. The router reads the new signed grants (no restart, no automatic fetch). a asks again. | `TimeoutError: timed out`. `denied_fwd_bytes 0`, `denied_landns_queries 0`, `audit_packet_deny_udp53 1`: `{"action":"packet-deny","actor":"spiffe://orblx.local/node/a","target":"udp/53","detail":"src 100.64.0.2 dst 10.88.24.53 proto udp port 53 unwritten_before 0"}`. `audit verify-config` ok. |
| TCP 80 to 10.88.24.20 still has a rule. | `db-ok`. |

Gates 1 to 4 of the W24-F proof also pass with the router filter on.

### W23-4 gates [C]

`scripts/proof/nat-realism.sh` with `ORBLX_NATR_POLICY=scripts/proof/nat-realism-acl.hujson` (the filter is on), release build, 3 runs on branch head 1755055b (main 130fe35).

| Run | prc direct Mbit/s | prc relay Mbit/s | sym relay Mbit/s | prc relay / direct RTT avg ms | sym relay / direct RTT avg ms | lost |
|---|---|---|---|---|---|---|
| run2 | 1112.65 | 1277.52 | 930.65 | 0.926 / 0.574 | 0.425 / 0.574 | 0/50, 0/50 |
| run3 | 1378.90 | 1269.68 | 1136.20 | 0.910 / 0.368 | 0.827 / 0.368 | 0/50, 0/50 |
| run4 | 1096.84 | 1071.13 | 535.71 | 0.927 / 0.384 | 0.434 / 0.384 | 0/50, 0/50 |
| median | 1112.65 (W22 1094) | 1269.68 (W22 1128) | 1136.20 (W22 1113) | all within direct + 1 ms | | |

Logs: `/workspace/orblx-w18-proof/w24acl-reb-1755055b-natr-branch-run{2,3,4}.log`.
The box had other workers (load 4 to 6). One ping in run2 had a max of 100.809 ms (avg 2.593 ms, 0/50 lost) during an SVID renewal.
An earlier set of 3 runs (branch d4c9b9e0 against main 76c90ac, same hour) had relay medians below W22 on both the branch (prc 860, sym 1018) and main (prc 914, sym 978). Logs: `w24acl-d4c-*-natr-*.log`.

## Changes to other proofs

A policy with an `acls` list now turns on the filter.
Thus the proof policies `admin.hujson`, `oidc.hujson`, and `w18-names.hujson` get the rules that their proofs need.
`file-send.sh`, `revoke-all.sh`, and `w18-names.sh` get small changes for the same reason.
`nat-realism.sh` can set a policy with `ORBLX_NATR_POLICY`. The W23-4 gates in this change run with `scripts/proof/nat-realism-acl.hujson`, so the filter is on in the measured path.

## Limits

- `orblx nat run` (the NAT lab datapath) has the packet filter, but it does not read `deny.json`.
  The revoke time above is for `orblx up`.
- IPv4 only. The overlay is IPv4.
- Subnet routes: the router checks only the packets from the overlay to the subnet.
  A subnet host cannot open a flow to an overlay client when the client has the filter on and no rule from the router allows it (same as before).
  An overlay client gets the replies of the subnet host because the router does not check the packets from the subnet.
- Exit routes are not in the port ACL.
- The policy `tests` list checks principals only. It does not check subnet destinations.
- The router gets new grants when its `grants.signed.json` changes. This change does not add an automatic grant fetch to `orblx up` (W25-6).
- The filter does not track TCP state. A flow that this node started stays open for replies for 180 s after its last packet.
- When the flow table is full (65 536 flows), a new outbound flow is not recorded, and its replies are dropped.
- The proof does not measure the filter cost at high flow counts.
- The proof runs on one host with other workers. The load was not measured during each run.
