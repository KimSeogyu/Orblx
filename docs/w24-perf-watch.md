# W24-E CI perf watch

This document describes the perf watch job and gives its measured numbers. W24-E2 changed the CI gate from the avg to the median.

Labels:

- **REAL**: a real host (the local Linux host or a GitHub runner VM), the Docker engine, and `cargo test`.
- **[C]**: a container. All routers, nodes, the coordinator, and the relay are [C].

This document has no target numbers. Each number is a measured value from a log or an artifact named below.

## What the job does

- Workflow: `.github/workflows/perf-watch.yml`, job `release RTT and throughput gates (3 runs)`.
- It runs on push to `main` and on `workflow_dispatch` (input `runs`, default 3). It does not run on pull requests.
  One job takes about 20 minutes (3 runs of 5 to 8 minutes and one release build), so it does not block pull requests.
- Runner: `ubuntu-latest` (REAL VM). The proof stack is [C] on that VM.
- `scripts/proof/perf-watch.sh` runs `ORBLX_NATR_PROFILE=release scripts/proof/nat-realism.sh` 3 times.
  It runs every run, then `scripts/proof/perf-summary.py` reads the logs.
- The job fails when a run does not print `proof_ok`, or when a CI gate (W24-E2) does not pass in a run.
  A run fails when one of these is true:
  - the relay ping median is more than the direct ping median + 1 ms (prc relay path and sym relay path),
  - a ping is lost on a path (prc direct, prc direct at 0.23 s, prc relay, sym relay),
  - the TCP throughput of a path is missing or below 300 Mbit/s (W24-E3, `ORBLX_PERF_MIN_MBIT`),
  - more than 3 of 50 pings on a path are above 10 ms (`ORBLX_PERF_MAX_SPIKES`, `ORBLX_PERF_SPIKE_MS`).
- The job always reports, for each path and run: the ping median, p99 (linear interpolation), max,
  and the spike count (pings above 10 ms). It also reports the box avg gate (relay avg <= direct avg + 1 ms)
  as a record. The avg is not a CI gate, because one runner stall moves the avg of 50 pings (see below).
- In CI, `perf-watch.sh` sets `ORBLX_RELAY_SLACK_MS=1000` and `ORBLX_RTT_LIMIT_MS=1000` (the ping timeout, `-W 1`).
  Then the nat-realism avg checks cannot stop a run, and every path is measured.
- **The box merge gate does not change.** `nat-realism.sh` without these env vars keeps relay avg <= direct avg + 1 ms
  and direct avg <= plain avg + 5 ms.
- `nat-realism.sh` prints a `ping_rtts` line (every RTT of the 50 pings, sent and received) after each
  `direct_ping` and `relay_ping` line. It is a record only. No nat-realism gate reads it.
- Artifact: `perf-watch-<commit sha>`, kept 90 days. It has:
  - `perf-watch.json`: for each path (`plain`, `prc_prc_direct`, `prc_prc_relay`, `sym_sym_relay`)
    the values of each run, the median, the min and max (range) of the RTT avg, the ping median,
    the relay minus direct value, the TCP throughput, the lost count, and the 3 slowest pings of each run
    (seq, ms, time stamp). It also has the `ping_stats` of each run (median, p99, max, spikes, lost),
    the CI gate result and the failures of each run, the box avg gate result (report), and the outlier check.
  - `perf-watch.md`: the same numbers as tables. The job also writes it to the job summary.
  - `runN.log` and `runN.exit`: the full nat-realism log and the exit code of each run.
- Outlier check: a ping of 10 ms or more in the slowest pings is an outlier (`ORBLX_PERF_OUTLIER_MS`).
  The check is a record. It does not fail the job.

## Script changes

- `nat-realism.sh` prints `direct_ping prc_prc ... median_ms ... slowest ...` for the direct path,
  in the same form as the W23 `relay_ping` line. The gates and the limits did not change.
- `nat-realism.sh` and `compose.nat-realism.yml` take `ORBLX_NATR_PREFIX`, `ORBLX_NATR_PROJECT`,
  `ORBLX_NATR_IMAGE`, `ORBLX_NATR_PUB` and `ORBLX_NATR_LAN`. With them, a second proof stack can run on a shared host
  with other names and subnets. The defaults are the W20 names and subnets, so CI and old runs see no change.
- CI (`ci.yml`) checks the shell syntax of the new script and runs `scripts/proof/tests` (summary parser tests).
- No datapath code changed.

## Can a GitHub runner do the Docker NAT containers?

Yes. The branch run of the job (GitHub Actions run `41028910022`, commit `e32392ea`) ran the full nat-realism proof
3 times on `ubuntu-latest`. All 3 runs printed `proof_ok`.
REAL runner: AMD EPYC 7763, 4 vCPU, kernel `7.0.0-1017-azure`. It has `/dev/net/tun`, Docker, privileged containers,
and `sudo -n` for the bridge sysctl.

## Results

### GitHub runner (REAL VM, [C] stack), run 41028910022, 3 runs

Median (min - max). RTT in ms (50 pings at 0.2 s). TCP in Mbit/s (5 s).

| Path | RTT avg | ping median | relay - direct | TCP | lost |
|---|---|---|---|---|---|
| plain (no orblx) | 0.037 (0.036 - 0.038) | - | - | 15802.38 (15109.40 - 16198.93) | - |
| prc direct | 0.181 (0.178 - 0.188) | 0.180 (0.173 - 0.184) | - | 286.84 (270.80 - 289.36) | - |
| prc relay | 0.266 (0.261 - 0.277) | 0.265 (0.255 - 0.268) | +0.085 (+0.073 - +0.099) | 332.85 (332.24 - 334.84) | 0/50 in all runs |
| sym relay | 0.259 (0.258 - 0.265) | 0.253 (0.249 - 0.258) | +0.080 (+0.071 - +0.084) | 332.57 (331.98 - 336.18) | 0/50 in all runs |

Slowest ping on each path over the 3 runs: prc direct 0.253 ms, prc relay 0.473 ms, sym relay 0.370 ms.
The RTT gate passed on all runs. The largest relay minus direct value was 0.099 ms (gate 1 ms).

### Local shared host (REAL, [C] stack), commit e32392ea, 3 runs

REAL host: Linux x86_64, 8 vCPU (`Intel(R) Xeon(R) Processor`), kernel 6.12.
Other workers used the same host at the same time. The load was not measured.
Names `orblx-w24e-natr-*`, subnets `172.29.124.0/24` and `10.124.2x.0/24`.
Log: `/workspace/orblx-w18-proof/w24e-e32392ea-perf-watch.log`, run logs and JSON in `/workspace/orblx-w18-proof/w24e-e32392ea-perf-watch/`.

| Path | RTT avg | ping median | relay - direct | TCP | lost |
|---|---|---|---|---|---|
| plain (no orblx) | 0.042 (0.038 - 0.051) | - | - | 33974.81 (33960.84 - 35104.83) | - |
| prc direct | 0.500 (0.456 - 0.599) | 0.502 (0.438 - 0.637) | - | 1183.27 (917.65 - 1254.95) | - |
| prc relay | 0.827 (0.799 - 0.908) | 0.811 (0.684 - 0.960) | +0.309 (+0.299 - +0.371) | 664.50 (399.04 - 1405.17) | 0/50 in all runs |
| sym relay | 0.837 (0.605 - 1.067) | 0.778 (0.280 - 1.080) | +0.381 (+0.105 - +0.468) | 987.34 (953.28 - 1245.09) | 0/50 in all runs |

Slowest ping on each path over the 3 runs: prc direct 1.340 ms, prc relay 4.010 ms, sym relay 4.220 ms.
The prc relay throughput range (399 to 1405 Mbit/s) is wide. The host was shared, so this run does not show a regression or a gain.

### Main runs of commit c3c536ba (W24-E, avg gate), 2 failed jobs

REAL: GitHub runner VM (`ubuntu-latest`). [C]: the proof stack. Source: the artifact `perf-watch-c3c536ba...` of each run.
The logs have the median and the 3 slowest pings of each path, not every ping. In each run below the third slowest
ping is below 10 ms, so the spike count is exact.

**Push run 41035129472** (2026-10-30 18:40 KST): 1 of 3 runs failed.

| Run | exit | direct median | prc relay median | sym relay median | spikes (> 10 ms) | failure |
|---|---|---|---|---|---|---|
| 1 | 1 | 0.090 | 0.183 | 0.189 | sym relay seq49 46.7 ms | sym relay avg 1.125 ms > direct avg 0.094 + 1 ms |
| 2 | 0 | 0.122 | 0.192 | 0.167 | none | - |
| 3 | 0 | 0.143 | 0.211 | 0.252 | none | - |

One sym relay ping of 46.7 ms moved the sym relay avg of 50 pings from about 0.19 ms to 1.125 ms.
The median stayed at 0.189 ms. Lost: 0/50.

**Dispatch run 41037171843** (2026-10-30 18:57 KST): 3 of 3 runs failed.

| Run | exit | direct median | prc relay median | sym relay median | spikes (> 10 ms) | failure |
|---|---|---|---|---|---|---|
| 1 | 1 | 0.180 | 0.227 | not run | prc relay seq32 163 ms; direct (0.23 s) seq37 234 ms | prc relay avg 3.493 ms > direct avg 0.178 + 1 ms |
| 2 | 1 | 0.159 | 0.213 | 0.255 | direct seq46 166 ms; sym relay seq42 251 ms and seq43 43.4 ms | sym relay avg 6.145 ms > direct avg 3.478 + 1 ms |
| 3 | 1 | 0.180 | 0.233 | not run | prc relay seq26 80.1 ms; direct (0.23 s) seq9 22.7 ms | prc relay avg 1.834 ms > direct avg 0.187 + 1 ms |

The spikes were on the direct path and on the relay paths. In run2 the direct spike (166 ms) moved the direct avg to 3.478 ms.
The sym relay pings seq42 (251 ms) and seq43 (43.4 ms) have the same receive time stamp (17 us apart).
The direct (0.23 s) pings seq37 (234 ms) and seq38 (2.05 ms) of run1 also have the same receive time stamp.
So the replies waited and then came together. This agrees with a stall of the runner VM, not with a slow relay.
In each run, lost was 0/50 and each median was normal (direct 0.159 - 0.180 ms, relay 0.213 - 0.255 ms).
A failed run stops at the failed gate. So runs 1 and 3 have no sym relay numbers and no relay throughput after the failure.

**With the W24-E2 gate.** On these logs, each relay median is less than the direct median + 1 ms
(largest relay minus direct median: +0.109 ms, push run3 sym relay). No path has more than 2 pings above 10 ms. No ping was lost.
The W24-E2 gate does not stop a run at the avg check, so a new run also measures the paths after a spike.

### The 22.1 ms outlier

W23-4 branch run1 had one prc relay ping of 22.1 ms (seq 31).
In these 6 runs (3 on the runner, 3 on the local host) no ping was 10 ms or more.
The slowest ping was 4.220 ms (local, sym relay, run2 seq 5). The 22.1 ms outlier did not come back.
The job keeps checking it on each push to main (`outlier` in `perf-watch.json`).

## Open points and caveats

- **Runner numbers are not host numbers.** The runner has 4 vCPU. The direct TCP throughput there is about 290 Mbit/s,
  and about 1200 Mbit/s on the local 8 vCPU host. Compare a runner number only with other runner numbers.
- **Runner noise.** Each push gets a new runner VM. The CPU model and the neighbors can change.
- **[C] only.** All overlay numbers are containers on one host. There is no number for a real network.
- **Throughput floor (W24-E3).** The CI floor is 300 Mbit/s on each path. The PO set this number.
  REAL runner history: on an AMD EPYC 7763 runner (main run 41049508256, 130fe357) the prc direct TCP was
  256.39, 277.43 and 280.83 Mbit/s. That run passed with the old floor. It would fail with the 300 Mbit/s floor.
  On EPYC 9V45 and Xeon 8573C runners the lowest path was 473.53 Mbit/s (runs 41048025969, 41044075380).
