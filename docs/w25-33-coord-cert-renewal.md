# W25-33: the coordinator renews its own leaf

Status: code fix, two Rust tests, and a soak script. The Docker proofs did not run yet
(section 6). The base of the line numbers in section 1 is main `130af38`.

## 1. Root cause

| Label | Fact | Evidence |
|---|---|---|
| [C] code | The coordinator issues its own leaf one time, at open, with the life `MAX_USER_TTL` (900 s). | `crates/orblx-coord/src/state.rs:272` (main), `state.rs:270` (rc.2 `b9cae9c1`) |
| [C] code | The QUIC server gets this leaf one time, with `with_single_cert`. No code replaces it. | `crates/orblx-coord/src/tlsutil.rs:46`, `crates/orblx-coord/src/server.rs:47` |
| [C] code | Each node checks the coordinator leaf in each coordinator call: enroll, renew, netmap, deny, policy, admin, agent grant. | `CoordServerVerifier::verify_server_cert`, `tlsutil.rs:179-189` |
| [C] code | The check accepts a leaf until `not_after + MAX_SKEW` (60 s). | `crates/orblx-identity/src/clock.rs:40` |
| [C] code | A peer does not check the coordinator leaf. A peer checks only the leaf of the other node. | `bind_session`, `crates/orblx-datapath/src/quic.rs:654-668` |
| [C] code | The node renews its own leaf at two thirds of its life. A failed renewal only retries. | `renew_loop`, `crates/orblx-datapath/src/node.rs:1955-2015`; `renew_unix`, `node.rs:2079` |
| REAL box, [C] containers | Run `w25t-tr-fix3-ttl900-e47b4df1.log`: renewal 1 at about 600 s passes. Renewal 2 at about 1200 s fails ("coord handshake failed" on the coordinator, "The SVID renewal failed ... The coordinator request failed." on node c). At 1560.3 s each node refuses each peer: "The leaf check failed. The end time has passed." | `/workspace/orblx-w18-proof/w25t-tr-fix3-ttl900-e47b4df1.log` lines 183-267 |

Chain of events (900 s lives, t = 0 at the coordinator start):

1. The coordinator leaf ends at t = 900. The nodes accept it until t = 960 (skew).
2. The node renews at t = 600 (leaf to t = 1500). The coordinator leaf is still good.
3. The node renews at t = 1200. The coordinator leaf ended at t = 960. The TLS handshake fails.
   The node retries, and each retry fails.
4. The node leaf ends at t = 1500. At t = 1560 (end + skew), each peer refuses it.

The peer refusal is not a direct effect of the coordinator leaf. It comes from the failed node
renewal. The direct effect is that each coordinator call fails after t = 960: renew, netmap,
enroll of a new node, deny-wait, and admin.

## 2. Fix

The coordinator renews its own leaf at two thirds of its life (600 s of 900 s). The rule is the
same as for the node leaf.

| Part | Change | Place (this branch) |
|---|---|---|
| Issue | `issue_coord_svid` calls the same `MiniCa::issue` with the same CA, the same SPIFFE ID (`spiffe://orblx.local/coord/<name>`), and the same life. | `state.rs:2063` |
| Due rule | `renew_coord_svid_if_due` issues a new leaf when `now >= not_before + 2/3 life`. | `state.rs:633`, `state.rs:2075` |
| Hot swap | The QUIC server uses `LiveCert`, a `ResolvesServerCert` that gives the live leaf to each new handshake. `install` replaces the leaf. An open connection keeps its session. | `tlsutil.rs:35-128` |
| Tick | `coord_cert_tick` checks each 1 s. It installs a new leaf and prints `coord svid renewed, new expiry N`. At start the server prints `coord svid expiry N`. No line has key text. | `server.rs:49-52`, `server.rs:93-140` |
| Test hook | `set_coord_svid_ttl` (test build only). It accepts 1 s through `MAX_USER_TTL`. It cannot make the life longer. | `state.rs:618` |

Not changed: the CA, the trust bundle, the wire format, the node verifier, the leaf check, the
skew, the coordinator life (900 s), and the node code. There is no restart and no node-side
grace. There is no crypto change.

## 3. Tests

| Test | What it shows |
|---|---|
| `coordinator_leaf_renews_at_two_thirds_from_the_same_ca` | No new leaf at 5 s of 9 s. A new leaf at 6 s, with the life 9 s. The old trust bundle accepts the new leaf as `spiffe://orblx.local/coord/coord`. A life above 900 s is refused. |
| `nodes_renew_across_coordinator_cert_ends` | Coordinator leaf life 10 s, node leaf life 60 s, run 95 s. A probe node calls the coordinator each 1 s and renews at 2/3. Nodes a and b run a session and renew two times. Node c stays offline across many coordinator rotations, then starts at 50 s, renews, and sends packets to a. Gates: 0 probe failures, 0 node renewal failures, 3 or more coordinator leaf ends crossed, the run passes the first end + `MAX_SKEW`, a and b have 3 or more leaf expiries, c has 2 or more, packets in both directions, the largest gap 2 s or less. |

Results (REAL box, `cargo test`, KST 2026-10-31):

| Build | Result |
|---|---|
| Fix (before the merge of main `130af38`) | PASS, 95.5 s. `coord_cert_ends_crossed 15`, `probes 84 probe_fail 0`, `node_renew_fail 0`, expiries a 3 b 3 c 3, ca 140 ac 140, `max_gap_ms 647`, 0 `coord handshake failed` lines. |
| main `819c33a` + the test and the test hook only (no tick, no `LiveCert`) | FAIL (exit 101), 95.3 s. `coord_cert_ends_crossed 1`, `probe_fail 21`, `node_renew_fail 11`, 32 `coord handshake failed` lines. |

## 4. Docker proof plan (not run)

All runs: the box proof lock, `proof_compose_clean`, a frozen worktree of this branch with the
head of PR #124 (`w25-26-ticket-proof`, which has #117) merged in. The lives are the defaults:
node leaf and ticket 900 s, coordinator leaf 900 s. The host is REAL. The coordinator and the
nodes are [C] containers.

| Run | Command | Time | Gates |
|---|---|---|---|
| P1: gate c | `sudo SOAK_S=0 SOAK_COORD_ENDS=3 SOAK_REVOKE=1 scripts/proof/coord-cert-soak.sh` | about 37 min | ticket-renewal.sh `proof_ok` (0 refusals, 0 lost peers, gap lines, no restart, revoke, 0 contended samples); 3 or more coordinator leaf ends (t = 900, 1500, 2100); 2 or more ticket ends (TR_ENDS = 3); 0 `coord handshake failed`. |
| P2: gate d and the late node | new script `coord-cert-rotation.sh` (not written yet) | about 20 min | See the steps below. |
| P3: gate e soak | `sudo SOAK_BIN=<release orblx> scripts/proof/coord-cert-soak.sh` | about 2 h 7 min | P1 gates, `soak_run_s >= 7200` from the coordinator start, about 12 coordinator leaf ends. |

P2 steps (t = 0 at the coordinator start):
1. Enroll owner, a, and d. Start them. Each lists its peers.
2. t = 30: stop d (`docker compose stop d`). d is offline.
3. t = 600: the coordinator renews its leaf (`coord svid renewed`).
4. t = 620: start d. Gate: d logs "The node renewed the SVID" in 60 s, and d pings owner and a
   with 0% loss. d was offline across the rotation.
5. t = 970 (after the first coordinator leaf end + skew): enroll the late node e and start it.
   Gate: the enroll passes, and e pings owner, a, and d with 0% loss. On main this enroll fails.
6. Gates for the whole run: 0 `coord handshake failed`, 0 refusals, 0 contended samples.

## 5. Soak script and sweep lines (gate e)

`scripts/proof/coord-cert-soak.sh` runs `scripts/proof/ticket-renewal.sh` (PR #124) under the
proof lock. It follows the coordinator log (read only) and adds the gates for the coordinator
leaf. Without PR #124 it stops with exit 2.

| Env | Default | Meaning |
|---|---|---|
| `SOAK_S` | 7200 | Least run time from the coordinator start, in seconds. |
| `SOAK_COORD_ENDS` | 3 | Least coordinator leaf ends crossed. |
| `SOAK_BIN` | debug build | The orblx binary (`TR_BIN`). |
| `SOAK_PROJECT`, `SOAK_IMAGE`, `SOAK_NET` | `orblx-ccsoak`, `orblx-ccsoak:local`, `172.28.49` | Compose names. |
| `SOAK_REVOKE` | 0 | `TR_REVOKE` for ticket-renewal.sh. |

The script sets `TR_SVID_TTL` to `MAX_USER_TTL` from clock.rs. It sets `TR_ENDS` so that the run
lasts `SOAK_S` s or more (12 for 7200 s).

Lines for the files of PR #119 (`w25-27-coord-tickets`):

`scripts/proof/sweep-manifest.txt`:

```
gate|coord-cert-soak|coordinator leaf soak: 2 h or more at the default lives from the coordinator start, 0 refusals, 0 lost peers, 0 coord handshake failures, 3 or more coordinator leaf ends (W25-33)|coord-cert-soak
proof|coord-cert-soak|scripts/proof/coord-cert-soak.sh|SOAK_BIN=@BIN@ SOAK_PROJECT=orblx-rc3sw-ccsoak SOAK_IMAGE=orblx-rc3sw-ccsoak:local|orblx-rc3sw-ccsoak:local|^proof_ok coord-cert-soak$
```

`docs/matrix-rows.txt`: no new line. A `gate` line has no row of its own, and the sweep fails
when the gate fails. If the PO wants the soak under row 29 too, change the manifest line to
`partial|29|Key / SVID rotation UX|svid-renew nat-realism coord-cert-soak`. The rows file line
`29|partial|Key / SVID rotation UX` stays the same.

## 6. Open items

- The Docker runs P1, P2, and P3 did not run. The PO schedules them.
- P2 needs a new script.
- ticket-renewal.sh gate 4b (200 ms per ticket end) failed in run `fix3-ttl60-e47b4df1`
  (gaps to 389 ms). That is a W25-26 item. The soak uses gate 4b without change, so the soak can
  fail on it.

## 7. rc.2 and 0 netmap peers (read only)

The rc.2 tag `b9cae9c1` lists 0 netmap peers in ticket-renewal.sh because its policy parser
refuses `"proto": "icmp"` in `scripts/proof/ticket-renewal.hujson` ("policy load failed: The
policy protocol is tcp or udp."), so the coordinator has no good policy. ICMP came with #80
(`d153c70`), after rc.2. Main does not show it: run `main3-ttl60-e47b4df1` lists 3 peers on each
node.
