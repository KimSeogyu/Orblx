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

The fix adds no sleep and no retry. The test limits do not change.

## 3. Test and proof

- `renew_test::session_stays_up_for_three_svid_lifetimes` sends a probe each 20 ms in each direction.
  It fails when a gap in the window from 1 s before to 3 s after a renewal is more than 200 ms.
  It also traces runtime stalls (`stall`) and OS-thread stalls (`os_stall`).
- `.github/workflows/renew-soak.yml` runs `cargo test -p orblx-coord` 4 times in each of 5 shards,
  on Linux and on macOS (20 runs each). All the coordinator tests run in parallel, as in `ci.yml`. There are no reruns.
- `scripts/proof/renew-gap.sh` [C] runs serial box runs under the proof lock.
  `node-a` pings `100.64.0.2` each 50 ms. The leaf life is 30 s, so each node renews each 20 s.
  `runN.samples.tsv` has the W25-5 format: each ping sample and the nearest renewal.
  A run passes when no ping within 5 s of a renewal is lost or is more than 20 ms.

## 4. Results

Times are KST. "Renewal max gap" is the largest probe gap in the window from 1 s before to 3 s after a renewal.

### 4.1 CI soak (REAL runners, 20 runs for each OS, no reruns)

| Run | Code | Linux | macOS |
| --- | --- | --- | --- |
| 41071838763 | before the fix, new test | 20/20, renewal max gap 104 ms | 2 of 16 finished runs fail (260 ms, 603 ms) |
| 41075302928 | 7cceaaa (fix) | 20/20, renewal max gap 93 ms | 19/20, 1 fail (226 ms, see 4.3) |
| 41081409325 | c3af70f (fix, main merged) | 20/20, renewal max gap 69 ms | 20/20, renewal max gap 188 ms |

The original failure was job 124091852497 (run 41064382223, macOS): a gap of 2804 ms after the third renewal.

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

### 4.3 Limit on macOS CI

The test has a probe on an OS thread (`os_stall`) that sleeps 5 ms in a loop.
On the macOS runner this thread sleeps up to 438 ms too long (run 41081409325).
In job 124129761509 it stalled when the renew test was the only test that ran.
The packet runtime stalls at the same time and for the same length.
Thus the remaining macOS gaps come from the runner, not from the datapath. The renewal itself has no gap in the traces.
The fail in run 41075302928 (job 124129761509, run 4) is such a stall:
a 226 ms gap in the two directions at 00:17:19.124, 1.9 s after `renew_start` and 1.4 s after the last `link_up`,
with a 194 ms `os_stall` at the same time.
A stall of this length in a renewal window can make the macOS soak fail again. The limit stays 200 ms.

## 5. Logs

All logs are in `/workspace/orblx-w18-proof/`:

- Root cause: `w25-k-trace-linux-prefix-20ms.log`.
- I/O stall: `w25-k-soak-ioprobe-*.log` (run 41074986885).
- Soak: `w25-k-soak-fix2-*.log` (run 41075302928), `w25-k-soak-final-*.log` (run 41081409325).
- Box proof: `w25-k-renew-gap-10runs-b.log`, `w25-k-rg-10b/`.
