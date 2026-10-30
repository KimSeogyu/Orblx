# W24-E CI perf watch

This document describes the perf watch job and gives its first measured numbers.

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
- The job fails when a run does not print `proof_ok`, or when the RTT gate does not pass on every run.
  The RTT gate is the nat-realism relay gate: relay ping avg <= direct ping avg + 1 ms, and 0/50 pings lost,
  for the prc relay path and the sym relay path.
- Throughput is recorded, not gated. `tcp-bulk.py` must finish on each path, or nat-realism fails.
  No throughput floor is set, because the runner numbers and the local host numbers differ by about 4x (see below).
- Artifact: `perf-watch-<commit sha>`, kept 90 days. It has:
  - `perf-watch.json`: for each path (`plain`, `prc_prc_direct`, `prc_prc_relay`, `sym_sym_relay`)
    the values of each run, the median, the min and max (range) of the RTT avg, the ping median,
    the relay minus direct value, the TCP throughput, the lost count, and the 3 slowest pings of each run
    (seq, ms, time stamp). It also has the gate result of each run and the outlier check.
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
- **No throughput gate.** A floor can be set after the job has a history of runner numbers.
