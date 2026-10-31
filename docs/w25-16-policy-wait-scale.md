# W25-16 Policy wait: one connection for each node, and a signature only for a changed netmap

This change lowers the coordinator CPU of `policy-wait` (W25-6). The poll interval does not change
(hold 20 s, change check each 100 ms). The coordinator signs each changed netmap, as before.
The change adds no new crypto design. It uses the existing netmap key and the existing signing code.

Labels:

- **REAL**: the Linux host, the Docker engine, the clock that the scripts read, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the load identities, the nodes, the router, and the Docker networks are [C].

All times are KST.

## 1. Changes

### 1.1 One QUIC connection for each node

- The client type `PolicyWaiter` keeps one QUIC connection to the coordinator. Each wait is a new
  stream on that connection. `orblx up --coord` and `orblx coord netmap --watch` use it.
- The waiter opens a new connection after an error, or when the node certificate or the trust bundle changes.
- The coordinator serves many streams on one connection. It authenticates the peer leaf certificate
  for each request, as before.
- The datapath dial path of W25-6b (#103, `connect_probed`) is a different path. It does not use
  the coordinator client. The late peer gate (gate 4 below) tests the two paths together.

### 1.2 A netmap signature only when the netmap changes

- The coordinator keeps the signed view of each node in a cache. The key of the cache is the digest
  of the node files, the policy generation, and the digest of the node lock store.
- When the key changes, the coordinator signs the view of each node again with the existing
  `sign_netmap` and `sign_grants` code. It does not skip a node. The coordinator then verifies
  each signature over the same bytes, as before.
- When the key does not change, the coordinator sends the cached signed view. The view is the same,
  so a new signature is not necessary.
- The coordinator reads the node files, the lock store, and the published routes one time for each
  key change, not one time for each node.
- The coordinator encodes the JSON of the view one time for each key change. A reply adds only the
  deny list and the ETag to these bytes. The unit test
  `the_cached_policy_reply_is_the_json_of_the_full_reply` makes sure that the bytes are the same as the bytes of the full reply.

### 1.3 A short reply at the end of an idle hold

- New request field `unchanged_ok`. The waiter sets it only when it has the checked view of the ETag
  that it sends, with the same trust bundle and the same node certificate.
- When the hold ends and the ETag did not change, the coordinator replies with only the deny list
  and the ETag. The waiter then gives the view that it has.
- When the ETag changed, the coordinator always sends the full signed view.
- An old coordinator ignores the field and sends the full view. An old client does not send the field.

### 1.4 Check that each changed netmap gets a new signature

The kill rule says: no skipped netmap signatures. These checks cover it:

- REAL, unit test `each_change_gives_the_view_of_a_new_signature`: three nodes. Steps: endpoint change,
  policy change (tags, ACL, auto approvers), route approval, exit approval, expiry, an outside edit
  of `nodes.json`, and a policy change again. After each step, the cached digest and the signed netmap
  are the same as those of a new coordinator with no cache on the same directory. The digest of each step
  is not the digest of the step before it.
- REAL, unit test `a_policy_waiter_keeps_one_connection_for_all_waits`: a new peer, a revoke, and an
  idle hold on one connection. The idle hold gives the same signed view and ETag.

## 2. Results

The policy proofs (2.1 and 2.2) ran on branch commit `df4b2b21` (main `538b1541` merged in: #111 FIFO lock,
#114 clean state, #102 user approval). The sym proof ran on `df4b2b21` (known failure, 2.3.1) and then
one time on `5da44502` (main `1459cc27` merged in: #91 SVID renewal gap fix and #93), with
the release build, under the box FIFO proof lock. Each compose proof started with
`proof_compose_clean` (#114) and printed `clean`. Each node got its certificate and ticket from the
coordinator through the normal enroll path (`orblx coord enroll --token-file`). No lab ticket is used.
The logs are in `/workspace/orblx-w18-proof/`.

### 2.1 Coordinator CPU (`scripts/proof/policy-scale.sh`)

Log `w25r-br-df4b2b23-policy-scale-run1.log`, lock held 2026-10-31 11:11:40 to 11:17:44 KST. Result: `proof_ok`.
The lock sampler saw no other orblx container (0 of 179 samples, load1 max 8.26).
Each window is 60 s. The load identities run `orblx coord netmap --watch` (the `PolicyWaiter` client).

| Measure | Label | Limit | Measured |
|---|---|---|---|
| Coordinator CPU, 50 nodes, no change | [C] | 0.5% of one core | 0.20% |
| Coordinator CPU, 50 nodes, one change each 10 s | [C] | 2% of one core | 0.55% |
| Coordinator CPU, 200 nodes, no change | [C] | - | 0.53% |
| Coordinator CPU, 200 nodes, one change each 10 s | [C] | - | 2.78% |
| Projected CPU, 500 nodes, one change each 10 s (line through 50 and 200) | [C] | 10% of one core | 7.24% |
| Projected CPU, 500 nodes, no change | [C] | - | 1.19% |
| UDP sockets of the load clients (50 / 200 nodes) | [C] | one for each node | 51 / 201 (the node sockets and 1 other) |
| Policy updates that the clients got (50 / 200 nodes, change window) | [C] | each change | 300 / 1200 |
| Wait failures | [C] | 0 | 0 |
| Logs with `PRIVATE KEY` | [C] | 0 | 0 |

An earlier run on `141a048f` (log `w25r-br-141a048f-policy-scale-run1.log`, 08:09:28 to 08:15:39 KST,
`proof_ok`, clean state) gave 0.22% / 0.55% (50 nodes), 0.63% / 3.22% (200 nodes), and 8.56% projected.
We did not run 500 nodes in containers. The projection uses the measured 50 and 200 node points.

Before this change (previous owner of W25-16 and the W25-6 runs on main):

| Measure | main `690558da` policy-sync (other worker log) | branch `dc2fc7cb` (before the CPU work) | branch `141a048f` | branch `df4b2b21` |
|---|---|---|---|---|
| 50 nodes, no change | 1.38% | 0.28% | 0.22% | 0.20% |
| 50 nodes, one change each 10 s | 4.10% | 0.59% | 0.55% | 0.55% |
| 200 nodes, no change | - | 1.19% | 0.63% | 0.53% |
| 200 nodes, one change each 10 s | - | 4.41% | 3.22% | 2.78% |
| Projected 500 nodes, change | - | 12.05% (fail) | 8.56% | 7.24% |

### 2.2 Policy sync gates (`scripts/proof/policy-sync.sh`)

Log `w25r-br-df4b2b23-policy-sync-run1.log`, lock held 2026-10-31 12:32:09 to 12:35:24 KST. Result: `proof_ok`.
The lock sampler saw no other orblx container (0 of 96 samples).

| Gate | Label | Limit | main `690558da` | main `87ffc333` | main `a5a38013` | branch `141a048f` | branch `df4b2b21` |
|---|---|---|---|---|---|---|---|
| G1 policy change to new DNS answer, remove / add | [C] | 2000 ms | 356 / 1134 ms | 269 / 252 ms | 256 / 1124 ms | 292 / 290 ms | 319 / 124 ms |
| G2 revoke drop | [C] | 1000 ms | 302 ms | 194 ms | 251 ms | 7 ms | 47 ms |
| G4 late peer, from compose up | [C] | 2000 ms | 206 ms | 307 ms | 841 ms | 310 ms | 316 ms |
| G4 late peer, from enroll start | [C] | - | 970 ms | - | - | 923 ms | 950 ms |
| G3 coordinator CPU, 50 nodes, idle / change | [C] | 0.5% / 2% | 1.38% / 4.10% | 1.41% / 4.31% | - | 0.22% / 0.48% | 0.22% / 0.53% |

The main columns come from logs of other workers in `/workspace/orblx-w18-proof/`
(`w25k-main-690558da-policy-sync-run1.log`, `w256-main3-87ffc333-*`, `w25n-main-a5a38013-*`).
G1, G2, and G3 are better than each main run. G4 from compose up is in the range of the main runs
(206 to 841 ms). From the enroll start, G4 is better than main (950 ms against 970 ms).
On the branch, the node applies a new policy 121 ms (remove) and 43 ms (add) after the change.

### 2.3 NAT realism and the sym gate (`scripts/proof/sym-throughput.sh`)

#### 2.3.1 Head `df4b2b21`: known failure (counted)

Log `w25r-br-df4b2b23-sym-throughput-run1.log`, run logs in `w25r/sym-df4b2b23/`. Lock held 2026-10-31
12:56:42 to 13:29:21 KST. Result: exit 1, no `proof_ok`. The sampler saw no other orblx container
(0 of 962 samples).

| Run | Label | Result | Max ping ms (path) | sym_sym relay Mbit/s |
|---|---|---|---|---|
| 1 | [C] | ok | 1.590 (prc_prc_relay) | 1413.64 |
| 2 | [C] | exit 1 | sym_sym steady ping 248.197 (limit 200), 0/50 lost | - (the run stopped before the bulk) |
| 3 | [C] | ok | 4.600 (prc_prc_direct_i0.23) | 1374.30 |
| 4 | [C] | ok | 1.550 (sym_sym_relay) | 1397.36 |
| 5 | [C] | ok | 1.870 (sym_sym_relay) | 1275.60 |

- The median of the 4 bulk runs is 1385.83 Mbit/s (floor 1113). The sym gate needs 5 bulk runs.
  Thus the gate failed. This failure stays counted. We did not run the proof again on this head.
- Cause (W25-29 method, REAL host data): the sym_sym steady ping ran from about 13:08:31.4 to
  13:08:41.3 KST. Seq 19 went out at about 13:08:35.0. The shared disk probe
  (`w25-29-fsprobe-perrun.tsv`, a write and rename each 100 ms on `/workspace`) has one slow probe in
  that window: a rename of 780.1 ms from 13:08:34.504 to 13:08:35.284 KST. The 248 ms reply is the time
  from the send of seq 19 to the end of that stall. This matches the W25-29 cause: the NAT router thread
  writes `status.txt` synchronously, so a disk stall stops the TUN reads. The W25-29 fix is not on main.
  This change does not touch the NAT router or the relay.

#### 2.3.2 Head `5da44502` (main `1459cc27` merged in)

Log `w25r-br-5da44502-sym-throughput-run1.log`, run logs in `w25r/sym-5da44502/`. Lock held 2026-10-31
14:21:15 to 14:56:23 KST. Result: exit 0. Each of the 5 nat-realism runs started with
`proof_compose_clean` (`clean`) and printed `proof_ok`. The sampler saw no other orblx container
(0 of 1036 samples, load1 max 8.95). This is the only sym run on this head.

| Run | Label | Result | Max ping ms (path) | sym_sym relay Mbit/s |
|---|---|---|---|---|
| 1 | [C] | ok | 3.680 (sym_sym_relay) | 1084.10 |
| 2 | [C] | ok | 1.610 (sym_sym_relay) | 1359.09 |
| 3 | [C] | ok | 1.560 (prc_prc_relay) | 1370.99 |
| 4 | [C] | ok | 1.640 (prc_prc_relay) | 1363.82 |
| 5 | [C] | ok | 1.630 (sym_sym_relay) | 1416.43 |

- sym gate: 5 runs with a 30 s bulk, median 1363.82 Mbit/s. The W22 floor is 1113. Result: ok.
- serial-rtt gate: each max ping is below 20 ms, and 0 packets are lost. Thus no steady-ping gap above
  200 ms occurred on this head.
- W23-4 natr: ok in each run.
- Contention (REAL sampler): each `proof_contention` line of this proof has `contended_samples 0` and
  `unknown_samples 0` (sym-throughput 1036, serial-rtt 1037, nat-realism runs 230, 202, 202, 202, 202 samples).
  The policy-scale (179), policy-sync (96), and `df4b2b21` sym (962) lines also have 0 contended and 0 unknown.

### 2.4 Code checks

- REAL: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  and `cargo test --workspace` pass on the box.
- REAL: `python3 -m unittest discover -s scripts/proof/tests`: 78 tests pass on `df4b2b21`.
- REAL: on `5da44502` the proof script tests are 87 (main added tests).
- CI on `df4b2b21`: run 41153985811 (Linux, macOS, Docker) success; startup-cost 41153985795 success.
- CI on `5da44502`: run 41169483881 (Linux, macOS, Docker) success; startup-cost 41169483668 success.

### 2.5 Host profile (REAL, not a proof)

An in-process release test on the box (a scratch test, not in the PR) timed one policy change
with 500 nodes. Before the CPU work, signing all views took about 1078 ms and the reply JSON about 183 ms.
After it, about 700 ms and 9 ms. The signature count did not change: one netmap signature and one
grant signature for each node for each change.


## 3. Scale limits and notes

- Each change signs the netmap of each node again, and each netmap lists all nodes. Thus the work
  for one change is O(N^2) for N nodes. This is necessary: each changed netmap gets a new signature.
- The maximum message size is 256 KB (`MAX_MESSAGE`, not changed). A reply with 500 nodes was about 180 KB in the host profile.
  Thus a coordinator with about 700 nodes or more reaches the limit. This limit was there before this change.
- The coordinator still checks each change each 100 ms, and the hold is still 20 s.
