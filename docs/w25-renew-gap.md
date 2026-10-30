# W25-11 Packet gap at SVID renewal

This change removes the packet gap that a node SVID renewal caused on the direct path.
It adds no new crypto design. The handshake and the key schedule do not change.

Labels:

- **REAL**: the Linux host, the Docker engine, `cargo test` on that host, and the GitHub Actions runners
  (`ubuntu-latest`, `macos-latest`).
- **[C]**: a container. The coordinator, node `a`, node `b`, and the Docker network of the box proof are [C].

## 1. Root cause

There are two causes. Both cause the datapath to stop. Neither cause is in the test.

### 1.1 Break-before-make at a renewal

When the leaf changes, the node dials a new QUIC session to the peer.
Before this change, the acceptor canceled the old link when it accepted the new session.
The old session thus stopped before the dialer had the new session.

Timeline, Linux REAL, `cargo test`, `ORBLX_TRACE_RENEW=1`, before the fix
(`/workspace/orblx-w18-proof/w25-k-trace-linux-prefix-20ms.log`):

| Time (KST) | Node | Event |
| --- | --- | --- |
| 2026-10-30 23:03:58.732 | a, b | `renew_start` |
| 23:03:59.006 | a | `renew_applied`, `send_rekey_req`, `reconnect cause=local_renew` |
| 23:03:59.024 | b | accepts the new session: `link_up gen=3`, `link_cancel_old old_gen=1` |
| 23:03:59.025 | a | old session `gen=2` ends: `recv_err ... connection lost` |
| 23:03:59.032 | a | `dial_done ms=26`, `link_up gen=4` |
| 23:03:59.040 | a | `first_tx` on the new link (first packet on the new key) |
| 23:03:59.073 | a | reconnect for the renewal of node b: `cause=peer_rekey_req` |

The probe then saw gaps of 154 ms (a to b) and 195 ms (b to a) at 23:03:59.797 and 23:03:59.861 KST.

### 1.2 Blocking file I/O on the packet runtime

The node wrote and renamed `status.txt` on the runtime thread that moves the packets:
each second, and at each link change and renewal. The node also read `deny.json` on that thread each 100 ms.
On the CI runners one `status.txt` write took up to 333 ms (Linux, job 124128674833)
and 174 ms (macOS, job 124128674637) (`slow_io` trace, run 41074986885).
During that time the runtime did not move packets.
A renewal writes the status file, so this stall comes at a renewal too.

## 2. Fix

1. A replaced link is retired, not canceled (`RetiredLink`).
   It gets no new packets. It sends the packets in its queue, ends its send stream,
   and stops when both directions drain. The new link carries the new packets at once (make-before-break).
2. The receive is cancel-safe. A canceled read does not lose a packet.
3. The rekey signals of one renewal coalesce into one reconnect. The reconnect does not wait 2 s.
4. One OS thread (`orblx-status`) writes `status.txt` (`StatusFile`). A newer text replaces a text that is not written yet.
   The last `down` text is written when the node stops.
5. The node reads `deny.json` on a blocking thread (`spawn_blocking`).
6. The node reads the netmap file of the W25-6 peer watch (each 250 ms) on a blocking thread (`spawn_blocking`).

The fix adds no sleep and no retry. The test limits do not change.

## 3. Test and proof

- `renew_test::session_stays_up_for_three_svid_lifetimes` sends a probe each 20 ms in each direction.
  It fails when a gap in the window from 1 s before to 3 s after a renewal is more than 200 ms.
  It also traces runtime stalls (`stall`) and the stalls of a plain OS thread that sleeps 5 ms in a loop (`os_stall`).
- Linux is the gate. `ci.yml` runs the test in `cargo test --workspace`.
  `.github/workflows/renew-soak.yml` runs `cargo test -p orblx-coord` 4 times in each of 5 shards (20 runs).
  All the coordinator tests run in parallel, as in `ci.yml`. A failed run fails the shard. There are no reruns.
- macOS is a report only. The macOS job of `ci.yml` skips the test in the test step and runs it in a report step
  that prints the summary and the probe stalls and does not fail. The macOS shards of `renew-soak.yml` print each run
  and do not fail.
- `scripts/proof/renew-gap.sh` [C] runs serial box runs under the proof lock.
  `node-a` pings `100.64.0.2` each 50 ms. The leaf life is 30 s, so each node renews each 20 s.
  `runN.samples.tsv` has the W25-5 format: each ping sample and the nearest renewal.
  `runN.host.tsv` has the host CPU load each second.
  A run passes when no ping within 5 s of a renewal is lost or is more than 20 ms.

## 4. Results

Times are KST. "Renewal max gap" is the largest probe gap in the window from 1 s before to 3 s after a renewal.
The claim of this change is: the renewal gap is 200 ms or less on Linux.

### 4.1 Linux soak (REAL `ubuntu-latest`, 20 runs, no reruns)

| Run | Code | Result | Renewal max gap |
| --- | --- | --- | --- |
| 41071838763 | before the fix, new test | 20/20 | 104 ms |
| 41075302928 | 7cceaaa | 20/20 | 93 ms |
| 41081409325 | c3af70f (main merged) | 20/20 | 69 ms |
| 41086516186 | dd5eec0 | 20/20 | 106 ms |
| 41094354119 | ee56381 (main #97, #98 merged) | 20/20 | 70 ms |
| 41099476815 | e356060 (main #92, #99 merged) | 18 pass, 1 fail, 1 not run (see 4.1.1) | 295 ms |
| 41103974113 | 0892f5c (status read on a blocking thread) | renew_test 17 pass, 3 not run (see 4.1.2) | 117 ms |

#### 4.1.2 A shard stopped because of another test

REAL, job 124228220291, shard 4, run 1. The renewal test passed (renewal max gap 48 ms).
The W25-6 test `a_peer_that_enrolls_later_is_reachable_in_two_seconds` failed (5560 ms, limit 2 s),
so the shard stopped and runs 2 to 4 did not start. The renewal test passed in all 17 runs that ran.
That test is not part of this change. Its fix is in a separate PR.

#### 4.1.1 The failed Linux run is a gap in the test loop

REAL, job 124213770543, shard 2, run 3 (`w25-k-soak-e356-ubuntu-s2-124213770543.log`), KST 2026-10-31:

| Time (KST) | Event |
| --- | --- |
| 02:40:25.012 | b `renew_start` (the renew call runs on a blocking thread) |
| 02:40:25.220 | a `renew_start` |
| about 02:40:25.374 to 02:40:25.647 | the test loop reads `status.txt` of node a: `slow_io op=status_read ms=273` |
| 02:40:25.658 | `gap dir=ba ms=294` ends |
| 02:40:25.659 | `gap dir=ab ms=295` ends |
| 02:40:25.662 | b `renew_applied`, then the new links come up (make-before-break) |

- The test loop sends the probes and also read `status.txt` on the same task with a blocking read.
  During the 273 ms read, the loop sent no probes. The gap of 294 ms and 295 ms is in both directions at the same time.
- The probes after the read arrived after about 11 ms in both directions, on the old link, before `renew_applied`.
  Thus the datapath did not stop.
- The runtime stall probe and the OS-thread probe saw no stall (0 ms), because other threads ran.
- The blocking read was in the test since #39. Slow reads also occur in earlier soaks (up to 837 ms),
  but they failed a run only when they occurred in a renewal window.
- Fix: the test reads `status.txt` on a blocking thread (`spawn_blocking`) and takes the result when the read is
  complete. The loop never waits for the read. The limit (200 ms), the probe interval (20 ms) and the window do not
  change. The fix adds no retry and no sleep.

### 4.2 Box proof ([C], 10 serial runs under the proof lock)

`scripts/proof/renew-gap.sh`, c3af70f code, from 2026-10-31 00:42 KST
(`/workspace/orblx-w18-proof/w25-k-rg-10b`, log `w25-k-renew-gap-10runs-b.log`):

- 15000 pings, 0 lost. Each run has 4 renewals of each node.
- The largest ping within 5 s of a renewal: 19.4 ms (run 9). The other runs: 1.50 ms to 15.5 ms.
- The host was idle: the mean CPU busy percent of each run was 1 to 5 (`runN.host.tsv`).
- Result: `renew_gap_gate ok runs 10 limit_ms 20.0` and `proof_ok renew-gap runs 10`.

An earlier set of 10 runs (7cceaaa, `w25-k-rg-10`) failed in runs 1, 4, 5 and 10 (21.2 ms to 63.3 ms).
The 1 min load at the start of those runs was 3.58 to 7.41. In the other runs it was 1.78 or less.
In those runs a spike of the same size also came 9.9 s after a renewal and 2.9 s before a renewal.
The node traces show no node event at the spikes. That set does not meet the idle condition.

### 4.3 The status writer adds no stall

7cceaaa moves the `status.txt` write to its own thread and the `deny.json` read to a blocking thread.
The runtime stall of the test on Linux (max and median of the 20 runs of each soak):

| Run | Code | Runtime stall max | Runtime stall median | OS-thread stall max |
| --- | --- | --- | --- | --- |
| 41074986885 | before 7cceaaa (status write on the runtime) | 46 ms | 20 ms | 7 ms |
| 41075302928 | 7cceaaa | 51 ms | 19 ms | 6 ms |
| 41081409325 | c3af70f | 30 ms | 18 ms | 6 ms |
| 41086516186 | dd5eec0 | 52 ms | 21 ms | 8 ms |


### 4.4 macOS report (no claim)

The macOS runs are data only. Each failed macOS run of the new test:

| Job | Code | Gap | Gap start to `renew_start` | OS-thread stall max (sum in the gap) | Runtime stall max |
| --- | --- | --- | --- | --- | --- |
| 124128674181, run 1 | before 7cceaaa | 201 ms | +1.04 s | 191 ms (191 ms) | 194 ms |
| 124129761509, run 1 | 7cceaaa | 226 ms | +1.69 s | 194 ms (194 ms) | 135 ms |
| 124168988572, run 2 | dd5eec0 | 729 ms | +2.69 s | 430 ms (703 ms) | 547 ms |
| 124168988494, run 2 | dd5eec0 | 388 ms | -1.19 s | 332 ms (332 ms) | 289 ms |
| 124196116316, run 2 | ee56381 | 409 ms | +2.44 s | 336 ms (336 ms) | 335 ms |

- In each failed run the OS-thread probe stalled 191 ms or more in the gap. A plain OS thread cannot run at that time,
  so the packet runtime cannot run.
- The gap of job 124168988494 ends 0.8 s before `renew_start`. It is in the window only because the window starts 1 s
  before a renewal. It is not a renewal gap.
- In job 124168988572 and job 124168988494 the shard stopped after the failed run 2, so runs 3 and 4 did not start
  (`set -euo pipefail`). The failed runs ended normally after 192.35 s and 191.78 s. There was no hang and no timeout.
- In job 124196116316 (run 41094354119) run 2 failed. The job is report only, so runs 3 and 4 ran and the job passed.
- The original failure was job 124091852497 (run 41064382223): a gap of 2804 ms after the third renewal,
  before the fix. That job had no OS-thread probe.

## 5. Logs

All logs are in `/workspace/orblx-w18-proof/`:

- Root cause: `w25-k-trace-linux-prefix-20ms.log`.
- I/O stall: `w25-k-soak-ioprobe-*.log` (run 41074986885).
- Soak: `w25-k-soak-fix2-*.log` (run 41075302928), `w25-k-soak-final-*.log` (run 41081409325),
  `w25-k-soak-dd5e-*.log` (run 41086516186).
- Box proof: `w25-k-renew-gap-10runs-b.log`, `w25-k-rg-10b/`.
