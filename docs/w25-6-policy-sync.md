# W25-6 Automatic policy and peer sync

This change makes `orblx up --coord` apply each coordinator change with no restart and no manual fetch.
A change can be a policy file change (ACL, split DNS, routes), a revoke, or a new peer.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the subnet router, node `a`, node `b`, the 50 load identities, and the Docker networks are [C].

The change adds no new crypto design. The coordinator signs the netmap and the grants with the
existing netmap key. The node verifies each reply with the pinned netmap key, as at enroll.

## 1. Coordinator: `policy-wait`

- New operation `policy-wait`. It is a long poll with an ETag, the same model as `deny-wait` (W25-2, #86).
- The ETag is the SHA-256 digest of the signed netmap, the signed grants, the endpoints,
  the approved and advertised routes, the exit approval, and the deny list ETag of the caller.
- When the ETag of the caller is not the current ETag, the coordinator replies at once.
  Otherwise it holds the request for 20 s or until the ETag changes.
- The coordinator checks for a change each 100 ms (`STAMP_TICK`). The check reads only the file
  metadata of the state files and the policy file. Thus a held request costs almost no CPU.
- The reply holds the signed netmap, the signed grants, the endpoints, the deny list, and the new ETag.

## 2. Node: `orblx up --coord`

- The policy thread asks `policy-wait` first. If the coordinator does not know the operation,
  the thread uses `deny-wait` and asks `policy-wait` again after 30 s.
- When the ETag changes, the node writes `deny.json` first. Then it writes the netmap, the grants,
  and the endpoints, each with a rename. It prints `The node applied a new policy from the coordinator.`
- A node that runs with its own `--netmap` file keeps that file. Only the deny list changes for that node.
- The datapath reads the files and applies them with no restart:
  - `deny.json`: each 100 ms (W25-1). A revoke closes the sessions of the denied peer.
  - Grants: each 1 s.
  - Split DNS: each 1 s. The DNS proxy uses the new table at once. The node then refreshes the
    system resolver in a background task. Before this change, the node ran `resolvectl` first,
    and the new answers waited for that command (up to 5 s for each call).
  - Netmap peers (new): each 250 ms. The node replaces the router table, installs the kernel routes
    of the new prefixes, adds the new peers to the status, and starts a link task for each new peer.
    A peer that leaves the netmap loses its routes. The deny list and the node lock stop its sessions.
- `orblx coord netmap --watch` uses the same client. It prints `policy_update UNIX_MS` for each change.

## 3. Results

Proof: `scripts/proof/policy-sync.sh`. The script takes the box proof lock (`proof-lock.sh`, W25-5).
The build is release. Branch run: commit `d8c7d3ae`, 2026-10-31 01:44 to 01:48 KST,
log `w256-br2-d8c7d3ae-policy-sync-run3.log` in the proof log directory. Result: `proof_ok`.
The lock sampler saw other orblx containers in all 86 samples (max 7, load1 max 2.84).

| Gate | Label | Limit | Measured |
|---|---|---|---|
| 1. Policy change to the new DNS answer on node `a` (remove `corp.lan`) | [C] | 2000 ms | 272 ms |
| 1. Policy change to the new DNS answer on node `a` (add `corp.lan` again) | [C] | 2000 ms | 234 ms |
| 1. Node `a` applied a new policy (stage, remove / add) | [C] | - | +120 ms / +202 ms |
| 1. The DNS table follows the new netmap (stage, remove / add) | [C] | - | +265 ms / +233 ms |
| 4. Late peer `b`: first ICMP reply on `a`, from `docker compose up b` | [C] | 2000 ms | 1066 ms |
| 4. Late peer `b`: first ICMP reply on `a`, from the container start | [C] | - | 855 ms |
| 4. Late peer `b`: first ICMP reply on `a`, from the start of the enroll | [C] | - | 1731 ms |
| 4. Restarts of `a` and the router | [C] | 0 | 0 |
| 3. Coordinator CPU, 50 `policy-wait` clients, no change, 60.3 s | [C] | < 5% of one core | 1.38% |
| 3. Coordinator CPU, 50 clients, one change each 10 s, 60.4 s | [C] | < 5% of one core | 4.35% |
| 3. Policy updates that the 50 clients got in the change window | [C] | >= 300 | 300 |
| 3. CPU of one client (no change / change) | [C] | - | 0.037% / 0.070% |
| 2. Last datagram from `a` at the router after `revoke_done_ms` | [C] | 1000 ms | 230 ms |
| Logs with `PRIVATE KEY` | [C] | 0 | 0 |

No node restarted, and the script did not run a manual netmap fetch on a node.
The late peer gate is a Docker measurement. The unit test `a_peer_that_enrolls_later` is extra.

### More runs: final branch head and main

Gate 3 measures CPU on a release build (`ORBLX_SYNC_PROFILE` default `release`) in all runs in this section.
A debug build is not the build that ships (see "Failed runs and causes").

- Branch run 4: commit `2540a869` (the final head of #92). Lock held 01:58:22 to 02:01:39 KST.
  Log `w256-br2-2540a869-policy-sync-run4.log`. Result: `proof_ok`.
  The lock sampler saw other orblx containers in 97 of 97 samples (max 6, load1 max 2.85).
- Main run 1: commit `c32d46f8` (main after the #92 merge). Lock held 02:26:52 to 02:29:49 KST.
  Log `w256-main-c32d46f8-policy-sync-run1.log`. Result: `proof_ok`.
  The lock sampler saw no other orblx container (0 of 87 samples, load1 max 2.61).

| Gate | Label | Limit | Branch run 4 | Main run 1 |
|---|---|---|---|---|
| 1. Policy change to the new DNS answer (remove / add) | [C] | 2000 ms | 313 / 1083 ms | 248 / 219 ms |
| 1. Node `a` applied a new policy (stage, remove / add) | [C] | - | +124 / +113 ms | +186 / +181 ms |
| 1. The DNS table follows the new netmap (stage, remove / add) | [C] | - | +298 / +1079 ms | +228 / +213 ms |
| 4. Late peer `b`: first ICMP reply on `a`, from `docker compose up b` | [C] | 2000 ms | 947 ms | 835 ms |
| 4. Late peer `b`: from the container start / from the start of the enroll | [C] | - | 698 / 1604 ms | 595 / 1742 ms |
| 4. Restarts of `a` and the router | [C] | 0 | 0 | 0 |
| 3. Coordinator CPU, 50 clients, no change (release build) | [C] | < 5% of one core | 1.34% | 1.34% |
| 3. Coordinator CPU, 50 clients, one change each 10 s (release build) | [C] | < 5% of one core | 4.17% | 4.20% |
| 3. Policy updates that the 50 clients got in the change window | [C] | >= 300 | 300 | 300 |
| 3. CPU of one client (no change / change) | [C] | - | 0.029% / 0.068% | 0.034% / 0.075% |
| 2. Last datagram from `a` at the router after `revoke_done_ms` | [C] | 1000 ms | 284 ms | 276 ms |
| Logs with `PRIVATE KEY` | [C] | 0 | 0 | 0 |

The gate 3 value with one change each 10 s is near the limit (4.17% to 4.35% in three runs).
The host, the Docker engine, and the clock that the script reads are REAL. All the measured values are [C].

Other checks on the branch:

- REAL: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  and `cargo test --workspace` pass (rustc 1.99.1).
- [C] W23-4 NAT realism (`nat-realism.sh`, release, `nat-realism-acl.hujson`) on `431e1fef`:
  `proof_ok` (log `w256-br2-431e1fef-natr-run1.log`). The commits after `431e1fef` change only
  the policy sync proof files.

### Failed runs and causes

- Run 1 (`431e1fef`): gate 3 stopped at the enroll of the load identities.
  Cause: the coordinator needs one endpoint at enroll, and the script gave none.
  Fix: the load container has the fixed address 172.30.126.9, and each identity gives its own port.
- Run 2 (`7d1bebfa`, debug build): gate 3 failed. Coordinator CPU 99.60% with no change.
  Cause: the debug build. Each client asks again after the 20 s hold, with a new QUIC and TLS
  handshake, and the coordinator signs the netmap for each reply. In a debug build these steps are slow.
  A host check with 10 debug clients showed a burst of 127 CPU ticks (1.27 s) for each 20 s cycle.
  The same host check with 50 release clients showed 82 ticks in 60 s (1.37%).
  Fix: the proof uses the release build by default (`ORBLX_SYNC_PROFILE`). The gate limit did not change.

## 4. First dial to a late peer (W25-6b)

A peer can enroll, and so be in the netmap of node `a`, before its UDP listener is up.
`orblx up` enrolls first and then starts the listener, so a real user can hit this order.
Node `a` dials the new peer at once. Before this change, one QUIC attempt had a 3 s limit,
and QUIC sends the Initial packet of an attempt again only after about 1 s and then 2 s more.
When the peer started to listen more than about 1 s after the dial, the attempt timed out,
the node waited 1 s, and then it started a new attempt. The unit test
`a_peer_that_enrolls_later_is_reachable_in_two_seconds` measured 2852 ms in CI and 5560 ms in a soak.

The fix is in the dial path and the accept path of the node:

- For 10 s after a dial task starts, and after a session ends (`FAST_DIAL_WINDOW`), one dial
  attempt starts a new QUIC attempt each 250 ms (`FAST_DIAL_PROBE`), with at most 12 attempts.
  The earlier attempts stay open, so a slow handshake on a long path can still finish.
  The first session or the first error ends the dial attempt.
- In this window, the node waits 250 ms after a failed dial attempt. After the window, the node
  used one QUIC attempt at a time and waited 1 s. W25-28 (section 7) changed the time after the window.
- The accept loop does not pause after an error of one connection. Before, it paused 200 ms
  after each failed handshake. When the dialer stopped its 12 attempts at the 3 s limit, the
  listener paused 12 times (2.4 s) before it accepted the next attempt.
- The 3 s limit of one dial attempt and the 2 s limit of the tests did not change.

New tests (in `crates/orblx-coord/src/renew_test.rs`):

- `a_late_listener_is_reachable_in_two_seconds_after_it_starts`: node `a` runs and dials `b`.
  Node `b` starts 0 ms, 1500 ms, and 4500 ms later. The delay is the test condition.
  Each case must reach `b` 2 s or less after `b` starts (the time includes the start of `b`).
- `late_listener_soak` (ignored, run with `--ignored`): 50 runs with delays from 0 ms to 5000 ms,
  spread evenly (step 102 ms). The test prints one line for each run and fails when one run fails.
- `a_dial_to_a_peer_that_listens_late_ends_soon_after_it_listens`: `connect_probed` alone.

Measurements (REAL: `cargo test` on the Linux host, debug build, 127.0.0.1, rustc 1.99.1):

| Check | Label | Old dial path | New dial path |
|---|---|---|---|
| `a_late_listener_is_reachable_in_two_seconds_after_it_starts`, 0 / 1500 / 4500 ms late | REAL | FAIL: 58 / 2567 / 571 ms | pass: 59 / 59 / 58 ms |
| `late_listener_soak`, 50 runs, 0 ms to 5000 ms late | REAL | 11 of 50 FAIL (1020 ms to 2040 ms late, 2011 ms to 3031 ms) | 0 of 50 FAIL, max 571 ms, mean 199 ms |
| One QUIC attempt, the peer listens 1.2 s after the dial starts | REAL | ends at 3028 ms, 1826 ms after the peer listens | - |
| `a_dial_to_a_peer_that_listens_late_ends_soon_after_it_listens` | REAL | - | ends at 1282 ms, 79 ms after the peer listens |
| `a_peer_that_enrolls_later_is_reachable_in_two_seconds`, 20 runs in a loop | REAL | - | 20 of 20 pass, 296 ms to 577 ms |

"Old dial path" is `node.rs` from main `ce1dcb79` with the new tests. The one-attempt row is a temporary
test that the change does not keep. A first version of the fix without the accept loop change
had 3 of 50 soak failures (2755 ms to 2959 ms late, up to 2728 ms). The accept loop change removed them.

## 5. Start of the late peer gate (W25-6c)

### 5.1 Problem

The gate of `a_peer_that_enrolls_later_is_reachable_in_two_seconds` started when the test
called the enroll of b. The time to the first packet then included the start-up of b
before its UDP listener started. That time is not a dial or datapath time.

REAL: renew-soak run 41120080246, job 124284271149 (`ubuntu-latest`, #91 head a3e5cd6), 2026-10-31 KST:

| Time (KST) | Event |
|---|---|
| 05:02:56.501 | The coordinator enrolled b. |
| 05:02:56.926 | Node a added b from the new netmap. |
| 05:02:58.959 | Node b started (2.46 s after the enroll). |
| 05:02:59.196 | Node b accepted a (0.24 s after the start of b). |
| 05:02:59.222 | The first packet came to b: 3298 ms after the enroll. The gate failed. |

### 5.2 Change

- `NodeRequest::on_listen` (optional hook). The node takes the time at once after the bind of its
  UDP socket. The node logs the time: `The node <name> listener started at unix_ms <ms>.`
  Then the node calls the hook with the same time (`ListenEvent`), before it accepts or dials.
  The node daemon (`orblx up`) sets `None`.
- The gate starts at the listener start event of b. The limit is 2 s. There are no retries,
  no sleeps and no tolerance.
- The test prints two report-only lines, `enroll_to_listener_ms` and `enroll_to_first_packet_ms`,
  and the gate line `listener_to_first_packet_ms ... limit_ms 2000`.
- Negative tests. The delays are only in the test code.
  - `the_late_peer_gate_fails_when_the_peer_stops_after_its_listener_starts`: the hook of b
    stops for 2.5 s after the listener start. The gate must fail.
  - `the_late_peer_gate_passes_when_the_listener_of_the_peer_starts_late`: the test waits 2.5 s
    after the enroll, before b starts. The gate must pass, and `enroll_to_listener_ms` must be 2.5 s or more.

### 5.3 Results

REAL: `cargo test -p orblx-coord --lib renew_test -- --nocapture` on the Linux box, debug build,
2026-10-31 KST. Log: `/workspace/orblx-w18-proof/w256c-local-renew_test-run1.log`.

| Test | enroll to listener | enroll to first packet | listener to first packet (gate) | Result |
|---|---|---|---|---|
| gate | 208 ms | 574 ms | 365 ms | pass |
| stop 2.5 s after the listener start | 198 ms | 2772 ms | 2574 ms | gate fails, as required |
| delay 2.5 s before the listener start | 2736 ms | 2798 ms | 62 ms | gate passes, as required |

The start-up time from the enroll to the listener start is task W25-21.

## 6. Limits

- A changed endpoint list of a peer that the node already dials does not restart that dial task.
  In the fast dial window, the dial task uses the endpoints from the netmap at the time it started.
  After the window, a netmap change makes the dial task read the new endpoints of the peer (W25-28).
- The coordinator reply is the full view of the node. The view is small (one netmap and one grant set).

## 7. Dials to a dead peer after the fast window (W25-28)

### 7.1 Problem

After the fast dial window, the node dialed a dead peer again 1 s after each failed 3 s attempt.
In the fast window, each peer started 4 QUIC attempts per second, and the peers did not share a limit.

Measurements before the change (REAL, W25-6b measurement on the Linux host, debug build, 127.0.0.1;
the dead peers are UDP sockets that do not answer):

| Check | Before |
|---|---|
| One dead peer | fast attempts until 12.9 s, then 1 handshake each 4 s |
| 50 dead peers, packets per second in 0-10 s / 10-20 s / after 20 s | 643 / 252 / 73 |

### 7.2 Change

- After the fast window, the dial task of a peer waits. It dials the peer again only when:
  - the node has outbound traffic to the peer and no session to it (the TUN read loop wakes the dial task),
  - the netmap file changes (the dial task then reads the new endpoints of the peer), or
  - 60 s (`IDLE_REDIAL`) pass with no other wake.
  Each such dial is one QUIC attempt per endpoint (3 s limit), then the Relay path if the node has one.
- In the fast window, all peers of the node share one budget (`ProbeBudget`) for the QUIC attempts:
  12 attempts per second (`PROBE_RATE`), at most 4 at a time (`PROBE_BURST`).
  The first attempt of each dial task to each endpoint does not use the budget, so the first dial
  to a peer does not wait. One peer alone still gets an attempt each 250 ms.
- The node logs each dial and each failure, as before. The node also logs the end of the fast window
  (`The fast dial window to <peer> ended. ...`) and each dial after it with the reason
  (`The node dials <peer> again. The reason is <outbound traffic | a netmap change | the idle timer>.`).
- `HelloEndpoint::connect_probed_limited` is `connect_probed` with a callback that allows or skips each attempt.

### 7.3 Tests

New tests in `crates/orblx-coord/src/dial_test.rs` (real nodes on 127.0.0.1). A handshake is one QUIC
Initial destination connection ID at a dead peer. The fast window ends at 10 s; the last fast attempt can
run to 13 s.

- `a_dead_peer_gets_at_most_one_dial_per_minute_after_the_fast_window`: one dead peer for 300 s
  (`ORBLX_DEAD_PEER_SECS` sets another time). After 13 s, two handshakes must be 60 s or more apart.
- `outbound_traffic_dials_an_idle_peer_and_the_first_packet_arrives`: peer `b` starts after the fast window.
  For 3 s, node `a` must not dial `b`. Then the test sends packets to `b`; the first packet must arrive in 1 s or less.
- `a_netmap_change_dials_an_idle_peer_in_one_second`: as above, but `b` listens on a new port. The test
  writes the new netmap file; node `a` must have a direct session to `b` in 1 s or less.
- `fifty_offline_peers_stay_at_or_below_100_packets_per_second`: 50 dead peers and one live peer `b`.
  The packets to the dead peers in 0-10 s must be 1000 or less (100 per second as the mean of the window).
  The first packet to `b` must arrive in 500 ms or less. The test prints the packets of each second.

### 7.4 Results

REAL: `cargo test` on the Linux host, debug build, 127.0.0.1, rustc 1.99.1, 2026-10-31 KST.
"main" is `d9704cfb` with the new tests only (the dead-peer test ran 90 s there).

| Check | main | This change |
|---|---|---|
| Dead peer, handshakes after 13 s | 20 in 77 s, 4 s apart: FAIL | 4 in 287 s, at 73 / 136 / 199 / 262 s, 63 s apart: pass |
| Outbound traffic after the window, first packet | FAIL: `a` dialed `b` with no traffic | 58 ms: pass |
| Netmap change after the window, session | FAIL: no session in 5 s (old endpoint) | 276 ms: pass |
| 50 dead peers, packets in 0-10 s (mean per second) | 6356 (635.6): FAIL | 633 (63.3): pass |
| 50 dead peers, packets of each second 0-10 s | 200 to 1070 | 24 to 163 (busiest: second 1 132, second 3 163) |
| 50 dead peers, first packet to the live peer | 153 ms | 76 ms |
| `late_listener_soak`, 50 runs, 0 ms to 5000 ms late | - | 0 of 50 FAIL, max 638 ms, mean 206 ms |

The busiest seconds come from the QUIC resends (at about 1 s and 3 s)
of the 50 first attempts. These attempts do not use the budget, so that the first dial to a live peer does not wait.

