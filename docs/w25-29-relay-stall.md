# W25-29: the router thread does not write the status file

## 1. Problem

On 97049038, one serial-rtt run (gate 2, run 8) had a 628 ms stall on the
prc_prc relay path after the direct-to-relay switch. The proof ran alone (no
other orblx container). The ping lost 0 packets. The replies for seq 35, 36
and 37 came in 3 ms. Thus the packets waited and then went out as a burst. The
path did not drop them.

## 2. Cause (best-supported hypothesis)

`orblx-nat-router` is the only thread that reads the TUN device. Before this
change, it wrote the status file itself (`fs::write` of `status.txt.tmp`, then
`rename` to `status.txt`) each 500 ms and on each path change. The state
directory `/var/lib/orblx` is a docker volume on the host ext4 disk. All cargo
targets on the host use the same disk.

A slow write or rename stops the TUN reads. The kernel keeps the packets in the
TUN queue. When the write ends, the router reads them all at once. This is the
shape of the 628 ms stall.

The orblx contention samples do not see this: they count only orblx
containers, not disk work of other processes.

Evidence on the same disk (`w25-29-fsprobe.tsv`, one write and rename each
100 ms on `/workspace`, 2026-10-31 08:57 to 10:05 KST, 37498 probes):

| Probe result | Count |
|---|---|
| Write and rename 5 ms or more | 30 |
| Slowest rename | 959.4 ms (09:57:03 KST) |
| Other renames above 40 ms | 47.5, 74.1, 45.8 ms |

No slow probe fell in a ping window of a counted run. Thus this data shows that
the disk can stop a synchronous rename for up to 959 ms. It does not prove that
a rename caused the 628 ms stall.

The relay audit write, `Hold`, and reattach are ruled out: audit is off in
nat-realism, and a reattach loses packets.

## 3. Change

- New `crates/orblx-edge/src/status_file.rs`: `StatusFile`.
  - `post(text)` keeps the newest text. It does not touch the disk.
  - `run(stopped)` runs in the new thread `orblx-nat-status`. It writes the
    newest posted text.
  - `write_now(text)` writes in the caller thread. The node uses it only once,
    before the other threads start.
- `Hub::write_status` now calls `post`. The router thread does not wait for the
  disk.

The status file content and its name do not change.

## 4. Tests

| Test | Result |
|---|---|
| `a_blocked_status_write_does_not_stop_the_poster` (FIFO at `status.txt.tmp`, the write waits) | slowest of 100 posts 13 us; the file gets the newest text |
| `a_blocked_status_write_stops_a_caller_that_writes_itself` (negative, the old way) | `write_now` waits 300 ms, the full hold |
| `cargo test -p orblx-edge` | 68 passed, 0 failed |

Log: `w25-29-fix-edge-tests.log`.

## 5. Gate (A)

The gate is 30 serial-rtt switch runs on this branch, each alone, 0 above
200 ms. The runs are not done yet. The results go in this section.

## 6. Limits

- The cause is a hypothesis. The disk stalls are measured; a stall at the same
  time as a ping stall is not measured.
- One 45.3 ms spike (relay prc_prc seq 1, 2026-10-31 09:56:26 KST, run 12 of the
  extra 20 runs on 97049038) had no slow disk probe and no host PSI peak near
  it. This change may not remove that kind of spike.
