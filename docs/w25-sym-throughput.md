# W25-12: sym relay throughput on main against W22

Status: closed as noise. Main is not lower than the W22 commit. It is 25.0% higher.

Times are KST. The host is REAL (8 vCPU Intel Xeon, Linux, Docker). Every node, router,
coordinator and relay is a [C] container.

## Question

In the W25-5 serial runs on main `d0ddf7f`, the median sym relay throughput of the 9 runs alone on
the box was 1054.21 Mbit/s. The W22 value is 1113 Mbit/s. Each run had one 5 s sample, and the
range was 916.39 to 1306.48 Mbit/s. W25-12 checks if this is a real regression.

PO rule: the regression is real only if the 30 s median of main is more than 5% below the median of
the W22 commit, measured in the same session with at least 5 samples each.

## Method (REAL)

- Commits:
  - head: `cd6c8ee` (main at 00:30, with #89 `4ac56c1` Relay keepalive, #94 and #90).
  - w22: `739c3cb` (W22-5 #60, the W22 throughput change).
  - main-89: `4ac56c1` (#89 only). One run, see below.
- The proof scripts of main (`scripts/proof` of `4ac56c1`; head used its own) on the code of each
  commit, so the method is the same. `ORBLX_NATR_PROFILE=release`, `ORBLX_BULK_SECS=30`.
- One `nat-realism.sh` run for each sample. Each run holds the box proof lock
  (`/workspace/.orblx-proof.lock`) and records `proof_contention`.
- Session: 00:17 to 03:39 KST, 31 October 2026. head and w22 were measured round-robin from
  02:10 to 03:32 (head runs 2 and 3 before that).
- The CPU values are the `bulk_cpu sym_sym_relay` lines (percent of one CPU, 28 s window).
- Logs: `/workspace/orblx-w18-proof/w25l/`, progress note `w25l-progress.txt`, table
  `w25l-stats.txt`.

## Result [C]

sym_sym relay TCP throughput, 30 s for each sample:

| Commit | Runs | Median Mbit/s | p10 | p90 | Min | Max | Runs with no other orblx container |
|---|---|---|---|---|---|---|---|
| head `cd6c8ee` | 5 | **1263.29** | 1159.46 | 1331.01 | 1151.58 | 1348.05 | 2 |
| w22 `739c3cb` | 5 | **1010.96** | 652.18 | 1050.64 | 419.56 | 1066.40 | 5 |
| main-89 `4ac56c1` | 1 | 1239.07 | - | - | - | - | 1 |

p10 and p90 use linear interpolation. Head is (1263.29 - 1010.96) / 1010.96 = 25.0% above w22.

Each run:

| Run | Start | Sym Mbit/s | Contention | Max load1 | CPU node c / node d / relay |
|---|---|---|---|---|---|
| head a2 | 01:04:36 | 1263.29 | 1 other (idle coord of another worker), 213/213 samples | 8.27 | 138.8 / 133.4 / 110.5 |
| head a3 | 01:49:17 | 1171.29 | 6 other (w25ha), 203/203 samples | 4.34 | 126.7 / 116.3 / 101.6 |
| head a4 | 02:10:35 | 1305.46 | 1 other, 99/202 samples | 3.41 | 136.5 / 128.1 / 108.5 |
| head a6 | 02:30:21 | 1348.05 | alone | 3.21 | 139.2 / 132.8 / 110.8 |
| w22 a7 | 02:37:39 | 1027.01 | alone | 4.71 | 141.5 / 161.3 / 92.1 |
| head a8 | 02:46:19 | 1151.58 | alone | 6.81 | 130.4 / 120.5 / 105.0 |
| w22 a10 | 03:02:30 | 1001.10 | alone | 5.08 | 150.1 / 172.9 / 99.4 |
| w22 a11 | 03:17:10 | 1066.40 | alone | 6.01 | 148.0 / 170.0 / 96.9 |
| w22 a12 | 03:25:24 | 1010.96 | no other orblx container, but high load (not idle) | 8.69 | 144.1 / 168.8 / 95.6 |
| w22 a13 | 03:32:54 | 419.56 | no other orblx container, but high load (not idle) | 8.70 | 57.4 / 54.1 / 37.2 |
| main-89 a1 | 00:17:29 | 1239.07 | alone | 7.64 | 133.7 / 125.3 / 105.5 |

Runs not counted (logs kept): w22 a9 (785.34 Mbit/s; max load1 12.45 with no other orblx
container, and the box disk was full during the run), w22 a2 and a5 (ended while they waited for
the lock; no measurement).

## Discussion

- The limiter is the CPU of the sym nodes and the relay. On w22 the nodes use more CPU
  (node d 161 to 173%) for less throughput than on head (node d 116 to 133%). Head moves more bytes
  for each CPU second. This check does not name the change that did it.
- w22 a13 (419.56) is not an idle sample. No other orblx container ran, but load1 was 8.69 when it
  queued and 7.28 at its start (`proof_context` lines), on 8 vCPUs. The sym nodes and the relay got
  only 37 to 57% CPU during the bulk (other samples: 92 to 173%). Thus another process on the host
  took the CPU. The proof does not record which process. w22 a12 started with load1 2.04, and load1
  was 8.69 at its end (03:32:22). Its sym CPU was normal (144.1 / 168.8 / 95.6). The high load thus
  started near the end of a12 and continued into a13. a12 is marked as not idle because of its max
  load1.
- Medians with fewer samples (same data, no new runs):

  | Filter | head | w22 | head vs w22 |
  |---|---|---|---|
  | All complete samples | 1263.29 (n=5) | 1010.96 (n=5) | +25.0% |
  | Without w22 a13 | 1263.29 (n=5) | 1018.99 (n=4) | +24.0% |
  | No other orblx container | 1249.82 (n=2) | 1010.96 (n=5) | +23.6% |
  | No other orblx container and max load1 below 8 | 1249.82 (n=2: a6, a8) | 1027.01 (n=3: a7, a10, a11) | +21.7% |

  Every filter gives the same verdict. The strict filter has fewer than 5 samples for each commit.
- The head runs with contention (a2, a3, a4) are in the same range as the alone runs (a6, a8).
- The 1113 value of W22 came from 5 s samples on another day. In this session the W22 commit is
  below 1113, and head is above it.
- The 5 s samples of W25-5 (916.39 to 1306.48, no other orblx container) have a larger spread than the 30 s samples
  of head (1151.58 to 1348.05). One 5 s sample is not sufficient for a gate.

## Verdict

No regression. Main (`cd6c8ee`) is 25.0% above the W22 commit, which is outside the 5% band in the
good direction. W25-12 closes as noise. No bisect and no datapath change.

## Sym check change (W23-4 gate)

The W23-4 sym relay throughput check now uses the 30 s median:

```
./scripts/proof/sym-throughput.sh
```

- 5 release `nat-realism.sh` runs (`ORBLX_SERIAL_RUNS`, default 5), one after the other, under one
  hold of the proof lock (through `serial-rtt.sh`, so the ping gate is also checked).
- `ORBLX_BULK_SECS=30` for every bulk transfer.
- `serial-rtt-table.py OUT --sym-gate`: pass when at least 5 runs have a sym bulk of at least 29 s,
  and the median of these runs is at or above 1113 Mbit/s. The line gives the number of runs alone
  on the box. A short (5 s) sample is not counted.
- Time: about 8 minutes for each run when the lock is free.

The gate applied to the logs of this session (copied as `run1.log` to `run5.log`):

```
head: sym_gate ok: 5 runs of at least 29 s (2 alone), median 1263.29 Mbit/s (min 1151.58, max 1348.05), W22 floor 1113
w22:  sym_gate failed: 5 runs of at least 29 s (5 alone), median 1010.96 Mbit/s (min 419.56, max 1066.40), W22 floor 1113
```

## Also in this change

- `serial-rtt.sh` printed the summary line after each run (`| tail -1`). It now prints the row of
  the current run (`serial-rtt-table.py --last-row`).
- [W25-5 proof lock](w25-proof-lock.md) has the table of the serial runs on main after the merge.
