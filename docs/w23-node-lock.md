# W23-1 node lock

With node lock, a node accepts a new peer only when a trusted owner key signed that peer.
The coordinator can add a node to the netmap, but the coordinator cannot make other nodes trust it.
The change adds no new crypto design. It uses ed25519 signatures over domain-separated text, as the netmap and endpoint signatures do.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts. This change has no REAL result.

## Parts

| Part | Where | What it does |
|---|---|---|
| Owner key | owner host, file mode 0600 | ed25519 seed. `orblx lock keygen --out FILE` writes FILE and FILE.pub. The coordinator never gets the private key. |
| Node signature | netmap peer field `lock_sig` | The owner signs `orblx-node-lock-v1`, node name, SVID URI, and overlay IP. |
| Lock update | netmap field `lock` | A chain of owner-signed `rotate` and `remove` updates. Each update has `version`, `prev` (hash of the last update), `signer`, and the new key set. |
| Node pin | node file `node-lock.json` | `orblx lock trust --pub-file ...` pins the first key set out of band. |
| Coordinator store | coordinator file `node-lock-store.json` | Key set, update chain, and node signatures. The coordinator checks each signature before it stores it. |

## Rules on the node

1. Without `node-lock.json`, the node works as before.
2. The node applies each update with `version` = current + 1, `prev` = current head, and a signer from the current key set. It refuses other updates and refuses a fork.
3. `rotate` replaces the signer key with one new key. `remove` removes one key. The key set cannot become empty. The limit is 16 keys.
4. The node removes each peer from the netmap when no current key signed the peer name, SVID URI, and overlay IP.
5. The QUIC endpoint closes a new connection from a peer outside the locked netmap after the leaf check and before the ticket exchange. The log line is `Node lock refused the peer URI`.
6. The node reads the allow list again every 10 s and at start.

## Commands

| Command | Use |
|---|---|
| `orblx lock keygen --out FILE` | Make an owner key. Prints the fingerprint only. |
| `orblx lock trust --pub-file F... --state DIR` | Pin keys on a node. |
| `orblx lock status --state DIR` | Show the node key set and version. |
| `orblx lock init --pub-file F... --coord ADDR` | Turn on node lock on the coordinator (policy owner only). |
| `orblx lock sign NODE --key-file F --coord ADDR` | Sign one node. |
| `orblx lock rotate --key-file OLD --new-key-file NEW --coord ADDR` | Rotate a key and sign the nodes of the old key again with the new key. |
| `orblx lock remove --pub-file F --key-file SIGNER --coord ADDR` | Remove a key. |
| `orblx lock show --coord ADDR` | Show the coordinator key set and signed nodes. |

The commands print 16-hex-digit key fingerprints. They do not print keys or signatures.

## Audit

The coordinator config audit chain has 4 new actions: `lock-init`, `lock-sign`, `lock-rotate`, and `lock-remove`.
The detail has the version, the key count, and fingerprints. `orblx admin audit` checks the chain.

## Proof

Script: `scripts/proof/node-lock.sh`. Compose project `orblx-w23a-node-lock`. It prints `proof_ok` at the end.

Nodes: `a`, `b`, `c` (signed with K1), `ak2` (signed with K2), and `arogue` (no signature). The node with the lower name dials. Thus `arogue` dials `b` and `c`.

1. The owner makes K1, K2, and K3 in the owner volume. The key file mode is 600.
2. `lock init` with K1 and K2. The owner signs `a`, `b`, `c` with K1 and `ak2` with K2.
3. The coordinator approves `arogue` and puts it in the netmap. The coordinator refuses a signature for `arogue` from untrusted K3.
4. Nodes `a`, `ak2`, `b`, `c` pin K1 and K2. `arogue` has no node lock.
5. All nodes start. The script checks paths, TCP to port 8080 on the overlay IP, and refuse log lines.
6. The owner rotates K1 to K3 (the tool signs `a`, `b`, `c` again with K3), then removes K2 with K3.
   The coordinator refuses an update signed by the old K1.
7. Nodes fetch the netmap, apply versions 1 and 2, and restart. `ak2` (K2 only) is now refused.
8. The coordinator chain verifies. The script greps all logs and state files for the owner key seeds and enroll tokens.

### Result (2026-10-30 14:52 KST, log `w23-1-node-lock-branch.log`)

| Check | Result |
|---|---|
| [C] Coordinator netmap for `arogue` | has `a ak2 b c owner`. The coordinator added it |
| [C] Locked netmaps of `a`, `ak2`, `b`, `c` | no `arogue` |
| [C] `arogue` QUIC sessions | refused 78 times (`b` 39, `c` 39). No path. TCP in both directions times out |
| [C] Signed nodes | paths direct. TCP `a`->`c`, `c`->`a`, `ak2`->`b` give HTTP 200 |
| [C] Bad signature for `arogue` (K3 before rotate) | refused by the coordinator |
| [C] Update signed by K1 after the rotate | refused by the coordinator |
| [C] After rotate and remove, node key set | version 2, 1 key (K3) |
| [C] After restart | `a`, `b`, `c` direct, HTTP 200. `ak2` refused 69 times, `arogue` refused 68 times. TCP from both times out |
| [C] Coordinator chain | `verify ok`, 22 records: lock-init 1, lock-sign 7, lock-rotate 1, lock-remove 1 |
| [C] Secret grep | owner seeds 0, enroll tokens 0, `PRIVATE KEY` 0. No owner key file on the coordinator |

The values of the run on main are in the PR report.

## Caveats

- The signature covers the node name, SVID URI, and overlay IP. It does not cover the TLS key, because the coordinator issues node keys. A bad coordinator can issue a new SVID for a signed name. Node lock stops new names, not a stolen name.
- The first key set comes out of band (`lock trust`). A node without `node-lock.json` trusts the coordinator as before.
- A running node gets new updates when it fetches the netmap (`orblx coord netmap` or `up` with a route flag). The allow list stops new sessions. This change does not close an open session at once. The proof restarts the nodes.
- The coordinator node `owner` has no signature in the proof. Nodes drop it from the mesh peers. Admin calls go to the coordinator and do not use the mesh.
- No REAL run.
