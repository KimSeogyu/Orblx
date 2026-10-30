# W25-21 Node start-up cost from the enroll call to the listener start

W25-21 does not block rc.3. It measures the time from the enroll call of a node to the start
of its listener, by phase, and gives an idle-box gate for it. It does not change the datapath,
the handshake, the keys, or the SVID check. It adds no pre-start and no cache.

Marks:

- **REAL**: the Linux box (8 CPUs), the GitHub-hosted ubuntu and macOS runners, `cargo test`
  on them, the in-process coordinator and the node code (`run_memory_node`, real UDP sockets on
  127.0.0.1, real files with fsync).
- **[C]**: none. There are no containers. The node uses the in-memory TUN of the tests.

## 1. Problem

On #91 head a3e5cd6 (renew-soak job 124284271149), the late-peer test failed with 3298 ms.
The log has these times (seconds in that minute):

| Time | Event |
|---|---|
| 56.501 | The coordinator prints "enrolled b" |
| 58.959 | Node b prints its start text (after `prepare_node`) |

So 2.46 s were spent after the coordinator sent the enroll reply and before node b was
ready. That log has no phase times, so it cannot show where the 2.46 s went.
W25-6c (#112) moved the gate start to the listener start of b. W25-21 measures the phases.

## 2. Phases

The test harness (`renew_test.rs`) and the node (`ListenEvent`, `StartPhases`) give one time
for each phase boundary (`Instant`, 0.1 ms resolution in the lines):

| Phase | From | To | Where |
|---|---|---|---|
| token | enroll start | the coordinator made the token | harness |
| enroll_call | token | the enroll reply, minus close_wait | client |
| close_wait | the enroll reply | the close and the endpoint idle wait (up to 2 s) | client `close_and_wait` |
| write_state | enroll done | ~18 state files written, each with `sync_all` | `EnrollResult::write_state` |
| netmap_read | | `netmap.json` read | harness |
| leaf_config | | node leaf config built | harness |
| harness_wait | | the spawn of the node (test delay only, else 0) | harness |
| spawn_to_node | spawn | `run_memory_node` entered | node |
| prepare | | `prepare_node` done | node |
| to_bind | | before `bind_node` | node |
| bind | | listener started (`ListenEvent.at`) | node |
| total | enroll start | listener started | = enroll_to_listener |

close_wait comes from a test-only task-local (`client::CLOSE_WAITS`, `#[cfg(test)]`). With
`ORBLX_TRACE_COORD=1`, each coordinator call also prints
`orblx coord_call close_wait_ms X rtt_ms Y` (no request or response data).

## 3. Results

All numbers are medians / p95 / max in ms, nearest rank.

### 3.1 Idle box gate (REAL, FIFO proof lock)

`scripts/proof/startup-cost.sh` on 9bccf33, 10 runs, lock held 2026-10-31 06:09:43 to
06:09:47 KST. Load average at start 2.88 (8 CPUs). The other-container count was "unknown"
(the script ran without root, so `docker ps` failed). Log:
`/workspace/orblx-w18-proof/w25u-startup-cost-idle-run2.log`. Result: proof_ok.

| Phase | median | p95 | max |
|---|---|---|---|
| token | 1.0 | 4.1 | 4.1 |
| enroll_call | 74.9 | 84.4 | 84.4 |
| close_wait | 94.0 | 107.9 | 107.9 |
| write_state | 7.3 | 13.1 | 13.1 |
| netmap_read | 0.0 | 0.0 | 0.0 |
| leaf_config | 0.2 | 0.3 | 0.3 |
| spawn_to_node | 0.1 | 0.3 | 0.3 |
| prepare | 0.4 | 0.5 | 0.5 |
| to_bind | 0.0 | 0.0 | 0.0 |
| bind | 1.3 | 2.8 | 2.8 |
| **total (enroll_to_listener)** | **181.0** | **207.4** | **207.4** |

Gate: median ≤1000 ms. **PASS (181 ms).** The median is not above 2000 ms, so there is no
rc.3 alert.

### 3.2 Busy runner (report only)

Run 41127171043 (workflow `startup-cost.yml`, head 9bccf33, 2026-10-31 05:56 to 06:11 KST).
Each ubuntu shard runs the orblx-coord tests 4 times with `--nocapture`. Run 1 also runs
`startup_cost_runs` (20 starts) next to them, and every shard printed
`load_running_at_measure_end yes`. All load runs exited 0. There are no reruns.
Logs: `/workspace/orblx-w18-proof/w25u-busy2-*-s*-*.log`.

| Set (ubuntu, 5 shards) | n | median | p95 | max |
|---|---|---|---|---|
| startup_cost_runs under the test load | 100 | 251.1 | 396.8 | 3410.2 |
| late_peer gate case, in the loaded test process | 20 | 277.7 | 568.4 | 623.1 |
| late_peer stop_after_listen case | 20 | 291.0 | 392.1 | 396.1 |

| Phase (ubuntu startup_cost_runs, n=100) | median | p95 | max |
|---|---|---|---|
| token | 0.8 | 3.7 | 112.2 |
| enroll_call | 107.4 | 177.6 | 602.4 |
| close_wait | 102.7 | 169.4 | 359.0 |
| write_state | 8.0 | 42.3 | 2658.2 |
| bind | 1.0 | 2.8 | 5.1 |
| other phases | ≤0.4 | ≤0.5 | ≤1.1 |

The two slow runs (ubuntu, `startup_ms` lines):

| Shard / run | token | enroll_call | close_wait | write_state | total |
|---|---|---|---|---|---|
| s4 run 2 | 41.7 | 416.4 | 292.4 | **2658.2** | 3410.2 |
| s1 run 1 | 112.2 | 602.4 | 87.9 | **866.4** | 1670.3 |

macOS (1 shard, report only, no macOS claim): startup_cost_runs n=20 median 172.0, p95 252.6,
max 277.5. Most of it is close_wait (median 120.8).

An earlier busy run (41125708438, head e73c376, 20 runs per OS, ms resolution) gave ubuntu
median 284, p95 315, max 328, and macOS median 179, p95 291, max 350.

## 4. Findings

1. On an idle box, the start-up from the enroll call to the listener takes about 0.18 s. The
   node part (spawn, prepare, bind) is below 3 ms.
2. close_wait is the largest single phase (about 0.1 s, 52% of the idle median). After the
   reply, the client closes the QUIC connection and waits for the endpoint drain
   (`wait_idle`, 3 × PTO, cap 2 s). This wait is the same in all three coordinator call paths.
3. The only phase seen at the 2.46 s scale is write_state: 2658 ms in 1 of 100 busy runs.
   `write_state` writes ~18 files, and each one gets `sync_all` before its rename. Under the
   disk load of the parallel tests, fsync takes up to seconds. This is a likely cause of the
   2.46 s on a3e5cd6. That log has no phase times, so this is not proven for that run.
4. The late-peer gate (listener to first packet, ≤2000 ms) is not affected by these phases,
   since #112 starts it at the listener start.

## 5. Options (not done; for a PO decision)

- close_wait: do not wait for the drain after the reply (the coordinator already answered).
  Saves about 0.1 s per coordinator call. It changes the close of the client, not the handshake.
- write_state: fewer fsyncs (for example, one fsync of the directory after all renames, or no
  duplicate files `cert.pem`, `key.pem`, `bundle.pem`). That is a durability and file-layout
  change, so it needs a decision.

## 6. How to run

- Idle gate: `scripts/proof/startup-cost.sh` (env `ORBLX_STARTUP_RUNS`, default 10;
  `ORBLX_STARTUP_OUT`). One run under the box FIFO proof lock. Prints proof_ok on a pass.
- Busy report: `.github/workflows/startup-cost.yml` (on pull requests that change node.rs,
  client.rs or renew_test.rs, and on demand).
- Direct: `ORBLX_STARTUP_RUNS=10 cargo test -p orblx-coord --lib startup_cost_runs -- --ignored --nocapture`.

## 7. Limits

- The node runs with the in-memory TUN of the tests. A real TUN open is not in these phases.
- The box run is not fully idle: the load average was 2.88 and the container count was unknown.
- The busy p95 values come from GitHub-hosted runners. They change from run to run.
