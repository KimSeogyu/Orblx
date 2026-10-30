# W23-4 Receive path performance

This document gives the cause of the W22 receive path cost, the change, and the measured numbers.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test`.
- **[C]**: a container. All routers, nodes, the coordinator, and the relay are [C].

Host: one REAL Linux x86_64 host, 8 vCPU (`Intel(R) Xeon(R) Processor`), kernel 6.12.
All [C] containers share this host. Another worker used the same host on the same day for builds and proofs.
All numbers come from the logs in `/workspace/orblx-w18-proof/` on that host.
This document has no target numbers. Each number is a measured value.
The W22 medians (direct 1094, prc relay 1128, sym relay 1113 Mbit/s) are the minimum values from the brief.
W25-12: the sym relay check now uses the median of 5 runs with 30 s samples (`scripts/proof/sym-throughput.sh`, see [W25-12](w25-sym-throughput.md)). One 5 s sample is not sufficient.

## Cause

In W22, one packet went through these threads in each direction ([C] `orblx nat run`):

- Send side: `orblx-tun-read` -> `orblx-nat-tun-read` -> router -> `orblx-nat-send`.
- Receive side: `orblx-nat-direct` or `orblx-nat-relay` -> `orblx-nat-tun-write` -> `orblx-tun-write`.
- Relay server: receive thread -> `orblx-relay-send`.

Each arrow is a channel handoff. Each handoff wakes a sleeping thread.
For a ping, all threads sleep, so each hop adds one thread wake-up to the RTT.
The two `orblx-nat-tun-*` threads only moved packets between a channel and the TUN bridge threads.
They added two handoffs and one packet copy in each direction, and no other work.

The receive thread at 68-79 % CPU and the relay send thread at 72-77 % CPU are not saturated (below 100 %).
Most of their time is in the kernel UDP calls. They are not the RTT cost. The wake-ups are the RTT cost.

## What changed

- **TUN port (`orblx-datapath` `TunPort`).** The node opens the TUN device once and shares it between threads.
  On Linux, the router reads the TUN device directly and the receive path writes it directly.
  The `orblx-nat-tun-read` thread and the `orblx-tun-read` and `orblx-tun-write` bridge threads are not used by `orblx nat run`.
  On other systems, `TunPort` wraps the old TUN bridge.
- **Quiet flow inline path.** When no packet came in the last 1 ms on a path, the path is quiet.
  - The router seals a quiet batch and sends it on its own thread. It does not wake `orblx-nat-send`.
  - The receive loops write a quiet batch to the TUN device on their own thread.
  - The relay server sends a quiet batch on its receive thread when `orblx-relay-send` has no batch.
  A busy flow (bulk TCP) still uses the send thread and the TUN write thread, so two cores share the work.
  The inline path runs only when no other batch waits, so the packet order is kept.
- **Direct receive batch.** `orblx-nat-direct` receives with `recvmmsg(2)` (`recv_batch`) and writes one batch to the TUN.
- **Fewer wake-ups.** The router wakes the send thread only when it queued frames for it.
- **Gate.** `scripts/proof/nat-realism.sh` now uses a relay slack of 1 ms (W21 to W22: 2 ms). This is a stricter gate.
  The relay gate also prints the median and the 3 slowest pings (`relay_ping`).

There is no new crypto and no new handshake. The seal is the same ChaCha20-Poly1305 seal.

## Results

Release build, `ORBLX_NATR_PROFILE=release ./scripts/proof/nat-realism.sh`, 3 runs each, same host, same day.
Each run printed `proof_ok`, and each relay gate lost 0/50 pings.

Baseline: main `1d56291b` (before this change, relay slack 2 ms).
Logs: `w23-4-baseline-main-1d56291b-run{1,2,3}-release-nat-realism.log`.

Branch: `c697da09` (this change, relay slack 1 ms).
Logs: `w23-4-branch-c697da09-run{1,2,3}-release-nat-realism.log`.

### [C] TCP bulk throughput (Mbit/s, 5 s)

| Path | Baseline median | Baseline range | Branch median | Branch range | W22 median |
|---|---|---|---|---|---|
| prc direct | 1052.95 | 859.74 - 1096.52 | 1412.29 | 1411.43 - 1418.90 | 1094 |
| prc relay | 996.64 | 963.09 - 1120.44 | 1167.00 | 1132.42 - 1269.90 | 1128 |
| sym relay | 1025.11 | 1012.60 - 1086.15 | 1211.25 | 1136.86 - 1211.64 | 1113 |

The baseline on this host on this day was below the W22 medians on all three paths.
The branch median is above the W22 median on all three paths.

### [C] Ping RTT avg (ms, 50 pings at 0.2 s)

| Value | Baseline range | Branch range |
|---|---|---|
| direct | 1.142 - 1.569 | 0.650 - 0.660 |
| prc relay | 1.616 - 2.418 | 1.088 - 1.541 |
| prc relay - direct | +0.214 - +0.849 | +0.433 - +0.891 |
| sym relay | 1.843 - 1.966 | 1.001 - 1.083 |
| sym relay - direct | +0.360 - +0.701 | +0.351 - +0.423 |
| relay lost | 0/50 in all runs | 0/50 in all runs |

Branch per run (prc relay / direct / gate `direct + 1`):

- run1: 1.541 / 0.650 / 1.650. `relay_ping` median 1.105 ms. One ping (seq 31) was 22.100 ms.
- run2: 1.088 / 0.655 / 1.655. Median 1.145 ms. Slowest 1.780 ms.
- run3: 1.111 / 0.660 / 1.660. Median 1.170 ms. Slowest 1.480 ms.

The direct RTT fell by about 0.5 to 0.9 ms. The relay RTT fell by a similar amount.
The relay minus direct value did not fall. It is the cost of the relay hop (two more UDP hops and the relay server).

### [C] Thread CPU during prc bulk (run3, `bulk_cpu`, percent of one core)

| Thread | Baseline | Branch |
|---|---|---|
| node b `orblx-nat-direct` (direct receive) | 77.00 | 71.33 |
| node b `orblx-nat-relay` (relay receive) | 72.00 | 73.33 |
| relay `orblx-relay-send` | 76.00 | 82.33 |
| node b `orblx-nat-tun-read` | 10.33 | not used |
| node b `orblx-tun-read` / `orblx-tun-write` | 21.00 / 38.67 | not used |

The receive threads do the same work at higher throughput. The bridge threads are gone.

## Open points and caveats

- **Outliers.** Single slow pings still occur on [C] (branch run1: 22.1 ms on the prc relay gate;
  up to 56 ms in the switch tests). The cause is not known. The `relay_ping` line gives the seq and time stamp for the next check.
  With one such ping, the prc relay avg came within 0.109 ms of the gate. The gate was not relaxed.
- **Shared host.** Another worker used the same host on the same day. The load was not measured during each run.
- **[C] only.** The numbers are for containers on one host. There is no REAL network number.
- **Other systems.** On macOS, `TunPort` uses the old TUN bridge with one more thread. CI builds and tests it. No macOS throughput was measured.
