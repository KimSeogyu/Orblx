# W25-1 Node sharing to another user

Gap matrix row 38. The owner shares one node, or one node and some ports, with a guest of another user.
The guest nodes see only the shared node. The other nodes of the owner do not see the guest nodes.

Marks: **[C]** = shown in the container proof. **REAL** = shown on a real host (Linux host, Docker engine, `cargo test`).
This change has no [C]-free REAL network result. The unit tests are REAL.

## Policy

```hujson
"guests": ["oidc:bob"],
"shares": [
  {"dst": "spiffe://orblx.local/node/b:8080", "proto": "tcp", "with": ["oidc:bob"]},
],
```

| Field | Rule |
|---|---|
| `guests` | A list of `oidc:SUBJECT`. Each entry is one guest user (one tenant). A policy without `guests` has one tenant. Then all nodes see all nodes, as before. |
| `shares[].dst` | One node SPIFFE ID with a port part: `:*`, `:PORT`, `:A-B`, or a comma list. The node cannot be a guest of its own share. |
| `shares[].proto` | `tcp`, `udp`, or a number. No proto means TCP and UDP. |
| `shares[].with` | `oidc:SUBJECT` (all nodes of that guest user) or one node SPIFFE ID (a share back to one node). An `oidc:` guest must be in `guests`. |

The policy refuses:

- An unknown field in a share.
- A guest SPIFFE ID in another trust domain. That needs a federated trust bundle, which is a new trust design. This version does not support it.
- A guest that is not a node, a node shared with itself, an empty `with`, and more than 1024 share lines.
- An OIDC subject that is empty, longer than 128 bytes, or has `:`, a new line, or a control character.

Each pair of (dst, guest) is one share line, for example `spiffe://orblx.local/node/b tcp 8080 with oidc:bob`.

## Tenants and what each node sees

- A node whose store owner (`oidc:SUBJECT`, set at OIDC enroll) is in `guests` is in the tenant of that guest.
- All other nodes are in the home tenant.
- A node sees a peer when both are in the same tenant, or when a share gives one of them to the other.

The coordinator uses this rule in three places for each node:

| Output | Rule |
|---|---|
| Netmap | Peers that the node does not see are not in the netmap. A peer in another tenant gets no routes and no exit node. |
| Grants (`grants.signed.json`) | Policy ACL grants and reach entries do not cross a tenant. Only a share crosses: the shared node gets one grant for each guest node, with the share ports and protocols. Sources that the node does not see are removed. |
| Deny list (`deny` op) | The coordinator adds the SPIFFE IDs of the nodes that the caller does not see to the global deny list. The version is the global version plus the config record count, so it increases at each share change. |

The deny list of a node is now per node. The nodes already fetch it each 500 ms (W24-D).
After a share is removed, the next fetch puts the shared node on the deny list of each guest node, and the guest node on the deny list of the shared node.
Each node then closes the open session with the denied peer, and the session check refuses a new session.

## Audit records

The coordinator compares the share lines of the old and the new policy when the policy file changes.

| Change | Records |
|---|---|
| One share line added | Exactly 1 record `share` (code 30). Digest before = empty, after = SHA-256 of the line. |
| One share line removed | Exactly 1 record `unshare` (code 31). Digest before = SHA-256 of the line, after = empty. |
| Other rules changed | 1 record `policy-replace` (as before). The rules digest does not include `shares`. |
| Only shares changed | No `policy-replace` record. |
| First load | 1 record `policy-load` (as before). No share records. |

Actor = `spiffe://orblx.local/coord/coord` (the coordinator reads the file; the file has no signer). Target = the shared node URI. Detail = the share line.
A share with two guests in `with` is two share lines, so it writes two records.
Codes 26 to 29 are the W25-3 API token actions in main.

No new crypto design. The change uses the existing policy file, deny list, signed grants, and config audit chain.

## Files outside the scope

The brief scope is the policy, coordinator, and sharing files. These files are outside that scope:

| File | Change | Why |
|---|---|---|
| `crates/orblx-audit/src/config.rs` | Adds the actions `share` (30) and `unshare` (31). | Gate 5 needs one record of each kind. |
| `crates/orblx-datapath/src/node.rs` | The deny tick is 100 ms (was 10 s). The node lock check stays at 10 s. The node applies the deny list only when the text of `deny.json` changes. Then it replaces the endpoint deny list and closes each open session whose peer SPIFFE ID is in the list (new `close_denied_links`). | Session control, not the packet path. The per-frame check denies only ticket nonces. Without this, an open session stays after the unshare (proof run 1 failed for this reason). The dial task tries again, so a share again restores the session with no restart. |
| `crates/orblx-cli/src/up.rs` | The deny fetch starts each 500 ms. The fetch time is not added to the interval. | With the fetch time added, one run took 1120 ms (run 5) and failed the 1 s gate. |

The packet path (`payload_from_data`, the packet filter of track A) is not changed.

## Limits

- **Port enforcement needs track A.** The coordinator gives the shared node a grant for TCP 8080 only. Before the W24-A packet filter (track A, not merged) is in main, the datapath does not use these grants.
  Thus guest node g reaches b:9090 (not shared), and shared node b reaches guest node g. The proof prints both as `port_check ... reached`.
  The proof gates them when `ORBLX_SHARE_PORT_GATE=1`. Run it with that value after track A merges.
- Gate 3 is met for the other owner nodes (a -> g is refused: g is not in the netmap of a and is on its deny list).
  For the shared node b, the grants do not allow b -> g, but the datapath enforces this only with track A.
- A guest in another trust domain is refused (see above).
- The share records use the coordinator as actor, not the owner, because the policy file has no signer.
- Each node deny fetch makes the coordinator reload the node store and the policy file. W25-2 measures the cost at 50 nodes.

## Proof [C]

Script: `scripts/proof/node-share.sh`. Compose project `orblx-w25a-node-share` (`scripts/proof/compose.node-share.yml`).
Policy: `scripts/proof/node-share.hujson`. HTTP helper: `scripts/proof/share-get.py`. Byte counter: `scripts/proof/share-sink.py`. The script prints `proof_ok` at the end.

Setup: the [C] test OIDC issuer, the coordinator with `[oidc]`, owner nodes `owner`, `a`, `b` (token enroll), and guest nodes `g`, `g2` (OIDC enroll, subject `bob`).
Nodes b and g2 serve HTTP on TCP 8080 and 9090. Node g serves TCP 8080.

1. g connects to b:8080.
2. The netmap of g has only b and g2. g -> a:8080 and g2 -> a:8080 are refused.
   Node a counts the bytes from each source on TCP and UDP 7070 (`scripts/proof/share-sink.py`).
   g and g2 each send 65536 bytes on TCP and 65536 bytes on UDP to a:7070. Node a must count 0 bytes from g and g2.
   A control send from g to g2:7070 (same tenant) must count more than 0 bytes, so the counter works.
3. The netmap of a has only b (not g or g2). a -> g:8080 and a -> g2:8080 are refused, although the ACL has a -> g:*.
4. The script removes the share with one rename of the policy file. A probe on g runs g -> b:8080 each 50 ms (timeout 0.2 s) until the first failure.
   Hold probes run a -> b:8080 and g -> g2:8080 each 100 ms for 8 s. deny_ms = the time from the rename to the end of the first failed GET (an upper limit). Limit 1000 ms.
5. The unshare writes exactly 1 record. The share again writes exactly 1 record. The script checks `audit share 1 unshare 1 policy_replace 0`, then `orblx audit --verify`.
   Then it measures the time until g -> b:8080 works again, with no restart.
6. The logs have no enroll token, no ID token, and no `PRIVATE KEY`.

### Results [C]

Head `a4d899d` (branch `w25-node-sharing` with main `76c90ac`). Debug build. Log: `/workspace/orblx-w18-proof/w25a-node-share-branch-a4d899d.log`.

| Gate | Result [C] |
|---|---|
| 1. The guest reaches the shared node and port | g -> b:8080 and g2 -> b:8080: `HTTP/1.0 200 OK`. |
| 2. The guest reaches no other node | g -> a:8080 and g2 -> a:8080 refused. Node a counted **0 bytes from g and 0 bytes from g2** (65536 TCP + 65536 UDP each). Control g -> g2:7070: 131072 bytes. The netmap of g is `b,g2`. |
| 3. The owner nodes do not reach the guest nodes | a -> g:8080 and a -> g2:8080 refused. The netmap of a is `b,owner`. Node `owner` is enrolled but does not run in the proof, so a is the other running owner node. |
| 4. The share is audited | Unshare: 1 `unshare` record. Share again: 1 `share` record. 0 `policy-replace`. `verify ok`. |
| 5. Unshare blocks access within 1 s | **unshare_deny_ms 791** (limit 1000). Hold probes a -> b:8080 and g -> g2:8080: 0 failures. |
| Share again | g -> b:8080 works again after 1498 ms, with no restart. |
| Secrets | 0 enroll tokens, 0 ID tokens, 0 `PRIVATE KEY` in the logs. |

Earlier runs of the same proof: head `2c69734` deny 604 ms, restore 1334 ms (`w25a-node-share-branch-2c69734.log`); head `34b2753` deny 411 ms, restore 3220 ms.

W23-4 performance gates (release nat-realism, `scripts/proof/nat-realism.sh`, prefix `orblx-w25a-natr-`).
The runs alternate between this branch and main `76c90ac` in the same time window. Other workers ran 15 to 29 proof containers on the same host at that time.
Logs: `/workspace/orblx-w18-proof/w25a-{branch-a4d899d,base-main-76c90ac}-run{1,2,3}-release-nat-realism.log`.

| Value (Mbit/s or ms) | Branch run 1 / 2 / 3 | Branch median | main median (same window) | W22 |
|---|---|---|---|---|
| Direct throughput (prc_prc) | 1126.04 / 1093.16 / 1193.02 | **1126.04** | 826.27 | 1094 |
| Relay throughput (prc_prc) | 1028.94 / 1173.07 / 1159.23 | **1159.23** | 1004.54 | 1128 |
| Relay throughput (sym_sym) | 1056.05 / 895.20 / 1103.68 | **1056.05** | 1043.09 | 1113 |
| Relay RTT avg prc / direct avg | 0.957/0.505, 0.837/1.105, 0.814/0.584 | | | relay <= direct + 1 |
| Relay RTT avg sym / direct avg | 0.896/0.505, 0.991/1.105, 0.827/0.584 | | | relay <= direct + 1 |
| Lost pings | 0/50 in each relay RTT check | | | 0/50 |

The relay RTT gate and the loss gate pass in each run. The direct and prc relay medians are above W22.
The sym relay median (1056.05) is below W22 (1113). The main median in the same window is 1043.09, also below W22. The branch does not change the packet path. Thus the difference comes from the host load, not from this change.
One branch run (run 2) had a ping max of 28.867 ms, with 15 other proof containers running.

## Run the proof

```sh
ORBLX_PROOF_NET_HOOK=/path/to/fix-container-egress.sh ./scripts/proof/node-share.sh
ORBLX_SHARE_PORT_GATE=1 ./scripts/proof/node-share.sh   # after track A merges
```

The script uses `sudo -n` for Docker when the user is not root. `PROOF_KEEP=1` keeps the containers for debug.
