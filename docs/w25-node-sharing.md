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

W25-1 did not change the packet path (`payload_from_data`). W25-1b (below) changes the packet filter of W24-A.

## W25-1b: The share scope follows the port ACL

Before W25-1b, a guest node got the share ports only in the signed grants. The W24-A packet filter (`crates/orblx-datapath/src/filter.rs`) is on only when the policy has an `acls` list.
Without `acls`, guest node g reached b:9090 (not shared), and shared node b reached guest node g.

W25-1b uses the W24-A filter for each peer in another tenant. **The policy format does not change.**

| Part | Change |
|---|---|
| Signed grants (`ReceiverGrants`) | New field `guarded`: the SPIFFE IDs of the peers in another tenant that the node sees through a share. The coordinator sets it in `filtered_grants`. The field is not written when it is empty, so a policy without `guests` gives the same grants as before. The grant check refuses a `guarded` entry that is not a SPIFFE ID or that repeats. |
| Packet filter | The filter is on when `filter` is true or `guarded` is not empty. With `filter` false (no `acls`), the filter checks only the packets from a `guarded` peer. Peers in the same tenant pass as before. A packet from a `guarded` peer needs a grant (the share ports). A packet from a `guarded` peer to an address that is not the overlay address of the node (a route) needs a subnet grant. Replies to the flows that the node opened still pass. |
| Audit | A dropped packet writes a `packet-deny` record (code 32) to `packet-audit.jsonl`, with the W24-A rate limits (1 record for each source, proto and port in 10 s; 5 records each second). Actor = the source SPIFFE ID. Target = `tcp/PORT` or `udp/PORT`. |
| `orblx up` | The log line is `The packet filter is on for shared peers. ...` when only `guarded` turns the filter on. A grants refresh prints the line again when the state changes. |

Both directions are closed. The shared node b has the guest nodes in `guarded` and allows only the share ports. Each guest node has b in `guarded` and has no grant for b, so b -> g is dropped.

Compatibility: `ReceiverGrants` refuses unknown fields. A node from before W25-1b refuses grants with `guarded`. This occurs only when the policy has `guests` and a share, so update the nodes before the coordinator when a policy has shares.

## Limits

- A guest in another trust domain is refused (see above).
- The share records use the coordinator as actor, not the owner, because the policy file has no signer.
- Each node deny fetch makes the coordinator reload the node store and the policy file. W25-2 measures the cost at 50 nodes.

## Proof [C]

Script: `scripts/proof/node-share.sh`. Compose project `orblx-w25a-node-share` (`scripts/proof/compose.node-share.yml`).
Policy: `scripts/proof/node-share.hujson`. HTTP helper: `scripts/proof/share-get.py`. Byte counter: `scripts/proof/share-sink.py`. The script prints `proof_ok` at the end.

Setup: the [C] test OIDC issuer, the coordinator with `[oidc]`, owner nodes `owner`, `a`, `b` (token enroll), and guest nodes `g`, `g2` (OIDC enroll, subject `bob`).
Nodes a, b, g, and g2 serve HTTP on TCP 8080. Node b also runs a byte counter on TCP and UDP 9090.

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
7. (W25-1b) Port scope: node b counts the bytes from each source on TCP and UDP 9090 (not shared). g sends 65536 bytes on TCP and on UDP to b:9090. Node b must count 0 bytes from g.
   A control send from a (same tenant) to b:9090 must count more than 0 bytes. b's `packet-audit.jsonl` must have exactly 1 `packet-deny` record with actor g and target `tcp/9090`, and `orblx audit verify-config` must print `ok` for it.
   `g -> b:9090` and `b -> g:8080` must be refused. `ORBLX_SHARE_PORT_GATE=0` turns off these gates.

`ORBLX_SHARE_POLICY` selects the policy file. `scripts/proof/node-share.hujson` (default) has an `acls` list. `scripts/proof/node-share-noacl.hujson` has no `acls` list, so only `guarded` turns on the filter.

### Results W25-1b [C]

Head `80a507f` (branch `w25-share-port-acl` with main `372138c`). Debug build. Two runs, one for each policy:
`/workspace/orblx-w18-proof/w25a1b-node-share-branch-80a507f-acl.log` (`node-share.hujson`, with `acls`) and
`/workspace/orblx-w18-proof/w25a1b-node-share-branch-80a507f-noacl.log` (`node-share-noacl.hujson`, no `acls`).

| Gate | With `acls` [C] | No `acls` [C] |
|---|---|---|
| 1. A shared user reaches only the shared ports | g -> b:8080 and g2 -> b:8080 `200 OK`. g -> b:9090 refused. g -> a:8080 refused. | Same. |
| 2. g -> b:9090: 0 bytes, 1 `packet-deny` record | **0 bytes** from g (65536 TCP + 65536 UDP sent). Control a -> b:9090: 65536 bytes (TCP; the ACL a -> b allows TCP only). **1** record actor g, target `tcp/9090` (also 1 for `udp/9090`). `verify-config ok`. | **0 bytes** from g. Control a -> b:9090: 131072 bytes. **1** record actor g, target `tcp/9090` (also 1 for `udp/9090`). `verify-config ok`. |
| Shared node to guest | b -> g:8080 refused. | b -> g:8080 refused. |
| 3. Unshare blocks access in <= 1000 ms | **unshare_deny_ms 516**. Hold probes: 0 failures. Share again: 1354 ms, no restart. | **unshare_deny_ms 457**. Hold probes: 0 failures. Share again: 1727 ms, no restart. |
| 4. Secrets and audit chain | 0 enroll tokens, 0 ID tokens, 0 `PRIVATE KEY`. Coordinator chain `verify ok`; share 1, unshare 1, policy-replace 0. | Same. Coordinator chain `verify ok` (8 records). |

Unit tests (REAL, `cargo test`): `filter_tests::guarded_peer_gets_only_its_grants_without_an_acl_list` and `share_test` (the `guarded` lists of b, g, and a, before and after the unshare).

NATR_RESULTS

### Results W25-1 [C]

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
ORBLX_SHARE_POLICY=$PWD/scripts/proof/node-share-noacl.hujson ./scripts/proof/node-share.sh
```

The script uses `sudo -n` for Docker when the user is not root. `PROOF_KEEP=1` keeps the containers for debug.
