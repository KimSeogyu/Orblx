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
| `ff08725` (probe in its own task) | PASS. 15 ends crossed, 0 probe failures, 0 node renewal failures, `max_gap_ms 298`, `max_send_gap_ms 278`. |
| `ff08725` + the merge of #124 `c6fe5db` (has #117) | PASS. 15 ends crossed, `max_gap_ms 339`, `max_send_gap_ms 320`. |

### 3.1 The largest packet gap (647 ms) [REAL]

The gap is a result of the test, not of the data path or of the renewal.

- In the first test, the loop that sends the packets also waited for the probe call to the
  coordinator. A probe call took up to 332 ms, and the loop sends one packet each 200 ms. The
  largest gap between two sends (`max_send_gap`) was 547 ms, and the largest receive gap was
  549 ms. The two values agree, so the sender caused the gap.
- The largest gap overlapped a probe call. It also overlapped a ticket-end window
  ([end - 2 s, end + 2 s]) and a coordinator rotation window. The gaps with no probe call in them
  were 261 ms or less.
- Commit `ff08725` runs the probe in its own task. The test now prints the largest gap for each
  window kind:

| Window | Largest gap (ms) |
|---|---|
| any (`max_gap`) | 298 |
| sender cadence (`max_send_gap`) | 278 |
| ticket end, [end - 2 s, end + 2 s] | 273 |
| coordinator leaf rotation | 278 |
| node renewal (W25-11 window) | 256 |

The largest gap is now equal to the send cadence. It is not in a ticket-end, renewal, or
rotation window. The test sends a packet each 200 ms, so it cannot measure a 200 ms gate. The
W25-26 gate of 200 ms for each ticket end is gate 4b of `ticket-renewal.sh` (pings each 50 ms).
P1 and P3 use that gate without change.

## 4. Docker proof plan

All runs: the box proof lock, `proof_compose_clean`, a frozen worktree of this branch with the
head of PR #124 (`w25-26-ticket-proof`, which has #117) merged in. The lives are the defaults:
node leaf and ticket 900 s, coordinator leaf 900 s. The host is REAL. The coordinator and the
nodes are [C] containers.

| Run | Command | Time | Gates |
|---|---|---|---|
| P1: gate c | `sudo SOAK_S=0 SOAK_COORD_ENDS=3 SOAK_TR_ENDS=4 scripts/proof/coord-cert-soak.sh` | about 50 min | ticket-renewal.sh `proof_ok` (0 refusals, 0 lost peers, gap lines, no restart, revoke, 0 contended samples); 3 or more coordinator leaf ends (t = 900, 1500, 2100); 2 or more ticket ends (TR_ENDS = 3); 0 `coord handshake failed`. |
| P2: gate d and the late node | `sudo RT_BIN=<release orblx> scripts/proof/coord-cert-rotation.sh` | about 25 min | See the steps below. |
| P3: gate e soak | `sudo SOAK_BIN=<release orblx> scripts/proof/coord-cert-soak.sh` | about 2 h 7 min | P1 gates, `soak_run_s >= 7200` from the coordinator start, about 12 coordinator leaf ends. |

P2 steps (`scripts/proof/coord-cert-rotation.sh`, t = 0 at the coordinator start). It uses
`compose.ticket-renewal.yml` and `ticket-renewal.hujson` of PR #124 (exit 2 without them), the
proof lock, `proof_compose_clean`, and the default lives:
1. Enroll owner, a, and b. Start them. Each lists 2 peers. Ping owner and a for all of the run.
2. Stop b (`docker compose stop b`). b is offline.
3. t = 600: the coordinator renews its leaf (`coord svid renewed`). The script checks that the
   leaf of b is not expired, then starts b.
4. Gate d1: b logs "The node renewed the SVID" in 90 s, and its expiry increases.
   Gate d2: b pings owner and a, and they ping b, 5 pings each with 0% loss.
5. t = first coordinator leaf end + skew + 5 s: enroll the late node c and start it.
   Gate d3: all nodes list 3 peers, and c pings each node with 0% loss. On main this enroll fails.
6. Run to first coordinator leaf end + skew + 240 s.
7. Gates for the whole run: 0 refusals, 0 `coord handshake failed`, 0 `coord svid renewal
   failed`, 1 or more renewals, no restart of the coordinator, owner, or a, 0 lost peer samples
   for owner and a, the secret scan, 0 contended samples. The script prints
   `proof_ok coord-cert-rotation`.

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

The PO made the soak a REQUIRED row of the rc.3 sweep. The rows-file format and the manifest
are on PR #119 (`w25-27-coord-tickets`), so the lines are in the stacked draft PR #129 (base
`w25-27-coord-tickets`):

`docs/matrix-rows.txt`:

```
66|shipped|Coordinator certificate renewal (2 h soak, W25-33)
```

`scripts/proof/sweep-manifest.txt`:

```
row|66|Coordinator certificate renewal (2 h soak, W25-33)|coord-cert-soak
proof|coord-cert-soak|scripts/proof/coord-cert-soak.sh|SOAK_BIN=@BIN@ SOAK_PROJECT=orblx-rc3sw-ccsoak SOAK_IMAGE=orblx-rc3sw-ccsoak:local ORBLX_SWEEP_PROOF_TIMEOUT=9000|orblx-rc3sw-ccsoak:local|^proof_ok coord-cert-soak$
```

The default time for each proof (`ORBLX_SWEEP_TIMEOUT`, 3600 s) stops a 2 h soak. PR #129 adds
the proof ENV word `ORBLX_SWEEP_PROOF_TIMEOUT=N`. It sets the time of that proof only. A bad
value is a setup error (exit 2).

The manifest and the rows file agree, so the sweep does not exit 2. Before this PR merges,
`--plan` on #129 exits 1 (`Plan FAIL: rows 66`, no script at the commit). Merge order: #128,
#119, #129. The PO adds row 66 to the Page.

## 6. Open items

- The Docker runs P2, P1, and P3 are in the box proof lock queue (results in the PR).
- Merge conflict with #117: #117 adds the field `RenewedLeaf.ticket`. The test helper
  `counted_renewer` in `renew_test.rs` makes a `RenewedLeaf` without it. The PR that merges
  second must add `ticket: None,`. The proof worktree has this change only for the proof runs.
- ticket-renewal.sh gate 4b (200 ms per ticket end) failed in run `fix3-ttl60-e47b4df1`
  (gaps to 389 ms). That is a W25-26 item. The soak uses gate 4b without change, so the soak can
  fail on it.

## 7. rc.2 and 0 netmap peers (read only)

The rc.2 tag `b9cae9c1` lists 0 netmap peers in ticket-renewal.sh because its policy parser
refuses `"proto": "icmp"` in `scripts/proof/ticket-renewal.hujson` ("policy load failed: The
policy protocol is tcp or udp."), so the coordinator has no good policy. ICMP came with #80
(`d153c70`), after rc.2. Main does not show it: run `main3-ttl60-e47b4df1` lists 3 peers on each
node.
