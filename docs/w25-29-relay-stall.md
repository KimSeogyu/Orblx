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

## 5. Where the loop runs (shipped or lab)

The router loop is in the shipped `orblx` binary. It is not the default node path.

| Fact | Evidence |
|---|---|
| `orblx nat` is a CLI subcommand of the `orblx` binary | `crates/orblx-cli/src/main.rs:22`, `:56`, `:191-192`, `:302-303` |
| `orblx nat run` calls `run_nat_node` | `crates/orblx-cli/src/nat.rs:137-157`; help text `:287` |
| `run_nat_node` starts the `orblx-nat-router` thread | `crates/orblx-edge/src/nat_run.rs:179`, `:281-282` (`router_loop` at `:1569`) |
| No feature gate or `cfg` hides the subcommand | `crates/orblx-cli/Cargo.toml`, `crates/orblx-cli/src/main.rs:22` |
| The release builds this binary and puts it in the tarball | `.github/workflows/release.yml:48`; `scripts/release/package.sh:41` |
| The systemd unit runs `orblx up`, not `orblx nat run` | `scripts/orblxd.service:8` |
| The node image runs `orblx up` by default; other commands go to the binary | `docker/entrypoint.sh` (header), `:26` (`exec /usr/local/bin/orblx "$@"`); `docker/Dockerfile:42-43` |
| A user doc names `orblx nat run` | `docs/w20-nat-followup.md:5`, `docs/w20-nat-realism.md:33` |

Thus a user who runs `orblx nat run` from a release gets this loop. The default
daemon (`orblxd.service`) and the default image command do not run it.

A related point that this change does not fix: `orblx up` also writes
`status.txt` with a blocking `write_atomic` from tokio tasks
(`crates/orblx-datapath/src/node.rs:1636-1671`). It does this on a 1 s tick
(`:695-705`) and, on a path change, in the session receive callback
(`:1474`, `note_rx` at `:1603-1616`). The runtime is multi-thread (`:379`).
This path was not measured in W25-29.

## 6. Gate (A)

The gate is 30 serial-rtt switch runs on this branch, each alone, 0 above
200 ms. The runs are not done yet. The results go in this section.

## 7. Limits

- The cause is a hypothesis. The disk stalls are measured; a stall at the same
  time as a ping stall is not measured.
- One 45.3 ms spike is unexplained. It was relay prc_prc seq 1, the first
  packet of the relay ping right after the direct-to-relay switch, at
  2026-10-31 09:56:26 KST, in run 12 of the extra runs on 97049038. The run was
  alone (0 of 154 contention samples). No disk probe of 5 ms or more and no
  host PSI peak was near it (the 959.4 ms rename was at 09:57:03, outside a
  ping window). In the other 21 runs on 97049038, seq 1 of this ping was
  0.316 to 0.917 ms. This change may not remove that kind of spike.
