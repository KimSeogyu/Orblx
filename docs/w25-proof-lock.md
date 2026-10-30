# W25-5 box proof lock

This change makes the RTT and throughput proofs run one at a time on one host.
It changes scripts only. It does not change datapath code, crypto, or the wire format.

Marks: **[C]** = shown in the container proof. **REAL** = shown on the real host (the Linux box), for example the lock file, the load average, and the container count. Every node, router, coordinator and relay in the proofs is a [C] container. This change has no result on more than one real host.

## Why

The W23-4 RTT gate must not show a ping spike over 20 ms. Many workers run container proofs on the same box at the same time. The working idea is that host contention can cause such spikes. This change removes contention between the proofs that use the lock, and it records the contention that stays (other proofs that do not use the lock yet).

## Changes

| Item | Change | Mark |
|---|---|---|
| `scripts/proof/proof-lock.sh` (new) | One box-wide `flock` lock. The lock waits; it does not fail. While it waits, it prints the holder. It prints a `proof_context` line (time, load average, other orblx containers) at queue, start and end, and a `proof_contention` line at the end. | REAL |
| `scripts/proof/nat-realism.sh` | Takes the lock before the first container starts. Releases it in the EXIT trap after cleanup. | REAL |
| `scripts/proof/perf-watch.sh` | Takes the lock. The child `nat-realism.sh` sees `ORBLX_PROOF_LOCK_HELD` and does not take it again. | REAL |
| `scripts/proof/serial-rtt.sh` (new) | Holds the lock for N release `nat-realism.sh` runs (default 10) and prints one table row per run. Stops on the KILL condition. | REAL, [C] |
| `scripts/proof/serial-rtt-table.py` (new) | Makes the table from the run logs with the `perf-summary.py` parser. `--gate` and `--kill-check` modes. | [C] |
| `scripts/proof/tests/test_proof_lock.py`, `test_serial_rtt_table.py` (new) | Unit tests. Linux CI runs them. | REAL (CI) |
| `.github/workflows/ci.yml` | `bash -n` also checks `proof-lock.sh` and `serial-rtt.sh`. | REAL (CI) |

## Scope

| Proof | Uses the lock | Reason |
|---|---|---|
| `nat-realism.sh` | Yes | It runs the W23-4 RTT gate (`ping_rtts` lines, relay avg <= direct avg + 1 ms, 0/50 lost) and the throughput lines. |
| `perf-watch.sh` | Yes | It calls `nat-realism.sh`. |
| `serial-rtt.sh` | Yes | It calls `nat-realism.sh` N times under one hold. |
| `nat.sh`, `subnet.sh`, W18 and other proofs | No | They send 3 reachability pings. They have no RTT or throughput gate. |

## Use

Source the file, then take the lock:

```bash
. "$ROOT/scripts/proof/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take "LABEL" "OWN_CONTAINER_PREFIX" ...
```

The own container prefixes are not counted as "other" containers.

| Env | Default | Meaning |
|---|---|---|
| `ORBLX_PROOF_LOCK` | `/workspace/.orblx-proof.lock` when `/workspace` is a writable directory, else `${TMPDIR:-/tmp}/orblx-proof.lock` | The lock file. The holder record is `${lock}.holder`. |
| `ORBLX_PROOF_LOCK_NOTE_SECS` | 30 | How often a waiter prints the holder. |
| `ORBLX_PROOF_SAMPLE_SECS` | 2 | How often the sampler counts other orblx containers and reads the load average. |
| `ORBLX_PROOF_LOCK_HELD` | set by the holder | The holder pid. A child proof skips the lock only when the holder record names this pid and the pid runs. |
| `ORBLX_SERIAL_RUNS` | 10 | `serial-rtt.sh` run count. |
| `ORBLX_SERIAL_OUT` | `target/serial-rtt` | `serial-rtt.sh` output directory (`runN.log`, `runN.exit`, `serial-rtt.md`). |
| `ORBLX_SERIAL_SPIKE_MS` | 20 | The max ping limit for the gate and the KILL check. |

Log lines (REAL):

```text
proof_context LABEL phase queued|start|end time ISO load L1/L5/L15 other_orblx_containers N groups NAME:n,...
proof_lock LABEL waiting at ISO, file FILE, holder: label=... pid=... user=... cwd=... since=...
proof_lock LABEL still waiting at ISO, holder: ...
proof_lock LABEL acquired at ISO after MS ms, file FILE
proof_contention LABEL samples N contended_samples M unknown_samples U max_other_orblx_containers K max_load1 L
proof_lock LABEL released at ISO
```

A run is "contended" when any sample saw another orblx container. It is "alone" only when every sample saw 0 other containers and no sample was unknown.

## Gate 1: two proofs started at the same time (REAL lock, [C] proof)

Two release `nat-realism.sh` runs started at 20:22:33 KST from the same worktree: `orblx-w25f-natr1` (subnets 172.29.125 and 10.125) and `orblx-w25f-natr2` (172.29.126 and 10.126).
Logs: `/workspace/orblx-w18-proof/w25f-gate1-first.log` (natr1) and `w25f-gate1-second.log` (natr2).

| Time (KST) | Event |
|---|---|
| 20:22:33.102 | natr1 queued (load 1.20/1.99/3.67, 18 other orblx containers) |
| 20:22:33.108 | natr1 waiting |
| 20:22:33.112 | natr2 acquired the lock after 9 ms |
| 20:23:03.112 to 20:27:03.151 | natr1 "still waiting" every 30 s, holder `label=nat-realism:orblx-w25f-natr2 pid=3498071 user=root` |
| 20:27:46.081 | natr2 `proof_ok`, phase end |
| 20:27:46.088 | natr2 released |
| 20:27:46.092 | natr1 acquired after 312987 ms |
| 20:32:57.350 | natr1 `proof_ok`, phase end |
| 20:32:57.357 | natr1 released |

Result: the runs did not overlap. natr1 acquired the lock 4 ms after natr2 released it. Both printed `proof_ok` and exit 0. **PASS**.

Note: the first "waiting" line at 20:22:33.108 printed an old holder record (`natr1`, pid 3092719, from an earlier attempt that was stopped by a kill). The new holder writes its record just after `flock` returns, so a waiter can read the old record for a moment. The holder print now adds `(stale record, pid not running)` when the pid in the record does not run.

An earlier attempt (19:57 to 20:21 KST, logs `w25f-gate1-hung-*.log`) hung: the contention sampler was a job of the proof shell, and the `wait` in the throughput step waited for it. The sampler now runs detached, and a unit test checks that a holder that calls `wait` ends.

## Gate 2: 10 serial runs of the W23-4 gates (REAL host, [C] proof)

Command (from the worktree, release build):

```bash
sudo -n env ORBLX_SERIAL_RUNS=10 ORBLX_SERIAL_OUT=/workspace/orblx-w18-proof/w25f-gate2b \
  ORBLX_NATR_PREFIX=orblx-w25f-natr1- ORBLX_NATR_PROJECT=orblx-w25f-natr1 ORBLX_NATR_IMAGE=orblx-w25f-natr:local \
  ORBLX_NATR_PUB=172.29.125 ORBLX_NATR_LAN=10.125 ./scripts/proof/serial-rtt.sh
```

The max ping is the max over the 4 gate paths (50 pings each, 200 pings for each run). "Contended" means that at least one sample of the run saw another running orblx container. Other workers ran proofs that do not use the lock (the lock is not on main yet), so every run in both attempts is contended. No run was alone on the box.

### Attempt 1: FAIL (contended)

20:33:16 to 21:23:31 KST. Logs: `/workspace/orblx-w18-proof/w25f-gate2-serial.log`, `w25f-gate2/runN.log`.

| Run | Result | Max ping ms (path) | Median direct | Median direct 0.23 s | Median prc relay | Median sym relay | Lost | Sym relay Mbit/s | Max load1 | Contention | Max ping vs nearest SVID renewal | Start | All paths |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | ok | 4.390 (sym_sym_relay) | 0.204 | 0.381 | 0.383 | 0.441 | 0/200 | 1153.73 | 2.98 | contended (max 18 other, 161/161 samples) | - | 2026-10-30T20:33:16.917+0900 load 2.20/2.54/3.13 other 8 | yes |
| 2 | ok | 1.590 (sym_sym_relay) | 0.510 | 0.348 | 0.806 | 0.772 | 0/200 | 975.42 | 11.13 | contended (max 12 other, 151/153 samples) | - | 2026-10-30T20:38:48.816+0900 load 2.07/2.30/2.85 other 8 | yes |
| 3 | ok | 4.090 (prc_prc_direct_i0.23) | 0.549 | 0.290 | 0.180 | 0.962 | 0/200 | 1000.54 | 13.27 | contended (max 17 other, 155/155 samples) | - | 2026-10-30T20:44:06.832+0900 load 6.10/4.67/3.66 other 11 | yes |
| 4 | ok | 4.060 (prc_prc_direct) | 0.204 | 0.181 | 0.627 | 0.990 | 0/200 | 1212.24 | 8.66 | contended (max 22 other, 158/158 samples) | - | 2026-10-30T20:49:29.045+0900 load 4.70/5.40/4.45 other 8 | yes |
| 5 | ok | 11.600 (prc_prc_relay) | 0.502 | 0.478 | 0.828 | 0.911 | 0/200 | 1210.23 | 4.26 | contended (max 15 other, 152/152 samples) | - | 2026-10-30T20:54:54.564+0900 load 4.26/4.89/4.58 other 13 | yes |
| 6 | ok | 1.630 (prc_prc_relay) | 0.516 | 0.453 | 1.015 | 0.331 | 0/200 | 421.50 | 9.03 | contended (max 18 other, 152/152 samples) | - | 2026-10-30T21:00:05.525+0900 load 1.22/2.65/3.69 other 12 | yes |
| 7 | ok | 1.650 (prc_prc_relay) | 0.577 | 0.482 | 0.891 | 0.821 | 0/200 | 1146.71 | 8.41 | contended (max 18 other, 157/157 samples) | - | 2026-10-30T21:05:19.202+0900 load 7.54/4.45/4.00 other 18 | yes |
| 8 | ok | 6.130 (prc_prc_relay) | 0.520 | 0.528 | 0.261 | 0.201 | 0/200 | 375.77 | 14.14 | contended (max 27 other, 148/148 samples) | - | 2026-10-30T21:10:41.896+0900 load 3.75/3.99/3.95 other 8 | yes |
| 9 | ok | 32.700 (prc_prc_relay) | 0.281 | 0.266 | 0.485 | 0.515 | 0/200 | 781.40 | 11.08 | contended (max 21 other, 152/152 samples) | - | 2026-10-30T21:15:57.776+0900 load 8.37/7.31/5.37 other 13 | yes |
| 10 | exit 1 | 104.000 (prc_prc_relay) | 0.522 | 0.475 | 0.774 | - | 0/150 | - | 9.24 | contended (max 17 other, 66/66 samples) | - | 2026-10-30T21:21:15.669+0900 load 5.66/6.70/5.69 other 17 | no |

sym_sym_relay throughput all runs: 9 values, median 1000.54 Mbit/s, BELOW the W22 floor 1113; alone runs: no value

Runs 9 and 10 had one relay ping above 20 ms each:

- Run 9: `prc_prc_relay` seq 40, 32.700 ms, at 21:17:51.429 KST. Load1 max 11.08. Other orblx containers 13 to 21 (orblx-w24acl, orblx-w25a, orblx-w25g). The proof passed (relay avg gate).
- Run 10: `prc_prc_relay` seq 19, 104.000 ms. The relay avg was 2.831 ms, more than 1 ms above the direct avg 0.542 ms, so the proof failed (exit 1). Other orblx containers 15 to 17 (orblx-w24acl, orblx-w25a, orblx-w25h). Load1 max 9.24.

Both runs were contended, so the KILL condition (a spike while no other proof container runs) did not occur. These runs did not record the SVID renewal times (that record was added later).

### Attempt 2: PASS (contended)

21:24:36 to 22:18:45 KST. Logs: `/workspace/orblx-w18-proof/w25f-gate2b-serial.log`, `w25f-gate2b/runN.log`, `w25f-gate2b/runN.samples.tsv` (runs 7 to 10).

| Run | Result | Max ping ms (path) | Median direct | Median direct 0.23 s | Median prc relay | Median sym relay | Lost | Sym relay Mbit/s | Max load1 | Contention | Max ping vs nearest SVID renewal | Start | All paths |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | ok | 1.940 (sym_sym_relay) | 0.541 | 0.567 | 0.948 | 1.085 | 0/200 | 1149.20 | 3.63 | contended (max 9 other, 164/164 samples) | - | 2026-10-30T21:24:36.470+0900 load 1.26/4.57/5.11 other 5 | yes |
| 2 | ok | 4.330 (prc_prc_direct) | 0.630 | 0.611 | 0.988 | 0.861 | 0/200 | 1340.55 | 1.90 | contended (max 8 other, 162/162 samples) | - | 2026-10-30T21:30:12.981+0900 load 1.90/2.82/4.16 other 7 | yes |
| 3 | ok | 1.760 (sym_sym_relay) | 0.577 | 0.653 | 0.950 | 1.090 | 0/200 | 1170.20 | 1.75 | contended (max 5 other, 152/152 samples) | - | 2026-10-30T21:35:42.874+0900 load 0.68/1.41/3.12 other 5 | yes |
| 4 | ok | 8.040 (sym_sym_relay) | 0.522 | 0.627 | 0.921 | 0.323 | 0/200 | 310.61 | 13.88 | contended (max 13 other, 151/157 samples) | - | 2026-10-30T21:40:52.368+0900 load 0.79/1.08/2.48 other 5 | yes |
| 5 | ok | 1.770 (sym_sym_relay) | 0.415 | 0.608 | 0.788 | 0.978 | 0/200 | 739.52 | 10.69 | contended (max 11 other, 99/155 samples) | - | 2026-10-30T21:46:18.100+0900 load 10.14/5.93/3.98 other 2 | yes |
| 6 | ok | 1.920 (sym_sym_relay) | 0.598 | 0.562 | 0.198 | 0.982 | 0/200 | 1174.32 | 6.04 | contended (max 5 other, 119/162 samples) | - | 2026-10-30T21:51:36.857+0900 load 4.88/4.27/3.76 other 0 | yes |
| 7 | ok | 1.870 (prc_prc_relay) | 0.390 | 0.532 | 0.883 | 1.050 | 0/200 | 1187.11 | 8.36 | contended (max 13 other, 135/153 samples) | not recorded | 2026-10-30T21:57:09.737+0900 load 2.62/3.37/3.54 other 5 | yes |
| 8 | ok | 8.310 (prc_prc_relay) | 0.457 | 0.235 | 0.380 | 0.277 | 0/200 | 769.69 | 7.58 | contended (max 21 other, 155/155 samples) | not recorded | 2026-10-30T22:02:23.598+0900 load 2.28/3.32/3.48 other 13 | yes |
| 9 | ok | 12.100 (sym_sym_relay) | 0.270 | 0.390 | 0.305 | 0.304 | 0/200 | 199.49 | 20.10 | contended (max 8 other, 110/154 samples) | -81.2 s (orblx-w25f-natr1-a, 4 renewals) | 2026-10-30T22:07:45.798+0900 load 5.93/4.61/4.03 other 5 | yes |
| 10 | exit None | - | - | - | - | - | 0/0 | - | - | - | - | 2026-10-30T22:13:09.194+0900 load 7.65/8.51/5.89 other 8 | no |

sym_sym_relay throughput all runs: 9 values, median 1149.20 Mbit/s, at or above the W22 floor 1113; alone runs: no value

`serial_rtt gate ok: 10 runs, every max ping below 20.0 ms, 0 lost`. The highest max ping was 12.100 ms (run 9, load1 max 20.10). **PASS**, with the note that every run was contended.

### SVID renewal next to each ping sample (PO addition)

`nat-realism.sh` now prints:

- `ping_times KIND LABEL seq@epoch,...`: the time of each ping sample (from `ping -D`).
- `svid_renewal CONTAINER UTC_TIME`: each "The node renewed the SVID" line of each node, with the docker log time stamp. `stop_node` prints them before `docker rm`, and `cleanup` prints them for the containers that are left, then `svid_renewal_scan done`. The log text itself is not printed.

`serial-rtt-table.py` writes `runN.samples.tsv` (path, seq, ms, epoch, nearest renewal container, renewal epoch, delta s) and the column "Max ping vs nearest SVID renewal". "not recorded" means that the run used a script without the renewal scan.

Attempt 2 runs 1 to 6 have no sample times, runs 7 and 8 have sample times but no renewal scan, and runs 9 and 10 have both. In runs 9 and 10 the 4 renewals occurred only in the renewal case at the end of the proof (leaf life of 60 s). The max ping was 81.2 s (run 9) and 178.0 s (run 10) before the nearest renewal. In these runs, no spike was near a renewal.

### Sym relay throughput (PO addition)

The table has the `sym_sym_relay` TCP throughput (one 5 s sample for each run) and a summary against the W22 floor of 1113 Mbit/s. The summary does not change the gate result.

- Attempt 1: 9 values, median 1000.54 Mbit/s (contended).
- Attempt 2: 10 values, median 959.45 Mbit/s (contended). Values from 199.49 to 1340.55 Mbit/s.

Both medians are below 1113 Mbit/s, but every run was contended (max load1 up to 20.10). No run was alone on the box, so these values do not show a regression. The PO asked for this check in serial idle runs on main. Those runs come after the merge, and their result is reported apart from this document.

## Gate 3: no datapath code change (REAL)

`git diff --stat origin/main...HEAD` lists only `scripts/proof/`, `docs/w25-proof-lock.md` and `.github/workflows/ci.yml`. No file under `crates/` changed. **PASS**.

## Limits

- Only the proofs that use `proof-lock.sh` wait for each other. A proof from an older branch, or a proof that does not source the file, runs at the same time. The `proof_context` and `proof_contention` lines show these containers.
- The "other orblx containers" count includes every running orblx container, also idle stacks that send no traffic.
- The `/tmp` fallback: with `fs.protected_regular`, a non-root user cannot open a root-owned lock file in the sticky `/tmp`. On the box, the default is `/workspace/.orblx-proof.lock`. Use `ORBLX_PROOF_LOCK` to set one file for all users.
- macOS has no `flock`. There, the proof runs without the lock and prints that.
- A waiter can print an old holder record for a moment (see gate 1). It is marked `(stale record, pid not running)`.
- The sym throughput is one 5 s sample for each run.
