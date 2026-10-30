# W21-1 Relay performance

This document shows the W21-1 relay work, the measured numbers, and the proof.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test`.
- **[C]**: a container. All routers, nodes, the coordinator, and the relay are [C].

Host: one REAL Linux x86_64 host, 8 vCPU (`Intel(R) Xeon(R) Processor`), kernel 6.12.
All [C] containers share this host. Another worker ran other proofs on the same host at the same time.
All numbers in this document come from the logs in `/workspace/orblx-w18-proof/` on that host.
This document has no target numbers. Each number is a measured value.

## What changed

Before this change, the node relay loop in `orblx nat run` slept 2 ms in each round.

- The router thread put each relay frame in a queue.
- The relay loop sent the queue only after its sleep. Each frame waited 0 to 2 ms.
- The relay loop read the relay socket only after its sleep. Each received frame waited 0 to 2 ms.
- One ping round trip has two relay sends and two relay receives. This added about 4 ms to the RTT.

After this change:

- `RelayPipe::sender()` gives a `RelaySender`. The sender is a clone of the relay socket.
- The router thread sends each relay frame at once through the shared `RelaySender`.
  A mutex keeps the TCP records in order.
- The relay loop blocks in `poll(2)` on the relay socket (`RelayPipe::wait_readable`).
  It wakes when a frame arrives, or after 20 ms to send the hello and probe control frames.
  It does not sleep in a loop.
- The relay server TCP path has one writer thread for each connection.
  Before, a TCP connection wrote its queued records only after a 50 ms read timeout.
  Now the writer thread writes each record when it arrives.
- The two other relay bridges (`orblx-edge` `relay.rs` and `orblx-datapath` `relay_path.rs`) also slept 2 ms when idle.
  Now they block in `poll(2)` on the relay socket and the local socket (`RelayPipe::wait_readable_or`), with a 50 ms limit.

The change adds no new crate. `orblx-relay` uses `libc` for `poll(2)`. `libc` was already in the lock file.

## Proof script changes

`scripts/proof/nat-realism.sh` has these new steps:

- **Relay gate.** 50 pings at 200 ms on the relay path for `prc_prc` and `sym_sym`.
  The script fails if one ping is lost, or if the relay average RTT is more than the direct average RTT + 2 ms.
  `ORBLX_RELAY_SLACK_MS` sets the slack. The default is 2.
- **Throughput.** A TCP bulk transfer of 5 s with `scripts/proof/tcp-bulk.py`.
  The client sends zero bytes in 64 KiB blocks. The server counts the bytes.
  Plain: router-a to router-b on the [C] public network, with no orblx.
  Direct and relay: node to node through the overlay.
- **CPU during the bulk transfer.** The tool reads `utime + stime` from `/proc` for each orblx process and each thread name.
- **Idle CPU.** A 10 s sample with no ping and no bulk transfer.
  The relay server process and the node relay thread (`orblx-nat-relay`) must stay at 3 % of one core or less (`ORBLX_IDLE_CPU_PCT`).
  The whole node process must stay at 25 % or less (`ORBLX_NODE_IDLE_CPU_PCT`). This limit finds a spin. It is not a cost target.
- `ORBLX_NATR_PROFILE=release` builds the node image from a release binary. The default is the debug binary.

The image has no iperf3. The proof uses the Python TCP bulk tool. Python 3 is in the image.

## Results: RTT ([C], 50 pings at 200 ms)

| Build | Code | Direct avg | prc_prc relay avg | sym_sym relay avg | Relay lost | Log |
| --- | --- | --- | --- | --- | --- | --- |
| debug | before (`30d613b`) | 1.937 ms | 6.377 ms | 6.712 ms | 0/50 | `w21-1-baseline-30d613b-nat-realism.log` |
| debug | before (`30d613b`) | 2.077 ms | 6.569 ms | (stopped) | 0/50 | `w21-1-baseline-30d613b-gate-fails.log` |
| release | before (`30d613b`) | 1.232 ms | 6.032 ms | 6.143 ms | 0/50 | `w21-1-baseline-30d613b-release-nat-realism.log` |
| debug | after | 1.803 ms | 2.008 ms | 3.080 ms | 0/50 | `w21-1-dev2-nat-realism.log` |
| release | after | 1.277 ms | 1.381 ms | 2.163 ms | 0/50 | `w21-1-dev4-release-nat-realism.log` |

The second "before" run used the default slack of 2 ms.
The script stopped with `prc_prc relay RTT avg 6.569 ms is more than 2 ms above the direct avg 2.077 ms.` and exit 1.
This shows that `nat-realism.sh` fails when the relay gate fails.

The relay path adds two hops through the relay container. In the release build, the relay RTT is 0.1 ms to 0.9 ms above direct.
The `sym_sym` debug run had one ping at 59.5 ms (max). The other worker used the host CPU at the same time.
The average with that ping was 3.080 ms. The gate limit was 3.803 ms.

The PR head run is in the section "PR head proof".

## Results: switch gap ([C], 50 pings at 200 ms in each switch)

| Build | Switch | Detect | Lost | Max gap |
| --- | --- | --- | --- | --- |
| debug after | prc_prc direct to relay | 567 ms | 0/50 | 352 ms |
| debug after | prc_prc relay to direct | 455 ms | 0/50 | 209 ms |
| debug after | prc_sym direct to relay | 477 ms | 0/50 | 292 ms |
| debug after | prc_sym relay to direct | 597 ms | 0/50 | 207 ms |
| release after | prc_prc direct to relay | 505 ms | 0/50 | 321 ms |
| release after | prc_prc relay to direct | 617 ms | 0/50 | 210 ms |
| release after | prc_sym direct to relay | 519 ms | 0/50 | 345 ms |
| release after | prc_sym relay to direct | 632 ms | 0/50 | 207 ms |

All gaps are 1 s or less. The script fails a switch above 1 s.

## Results: throughput ([C], TCP bulk transfer, 5 s, one stream)

| Build | Code | Plain (no orblx) | prc_prc direct | prc_prc relay | sym_sym relay |
| --- | --- | --- | --- | --- | --- |
| debug | before | 34063.10 Mbit/s | 33.32 Mbit/s | 18.15 Mbit/s | 18.57 Mbit/s |
| release | before | 32278.48 Mbit/s | 803.52 Mbit/s | 106.52 Mbit/s | 97.10 Mbit/s |
| debug | after | 34074.89 Mbit/s | 31.51 Mbit/s | 33.81 Mbit/s | 31.53 Mbit/s |
| release | after | 33041.36 Mbit/s | 863.04 Mbit/s | 875.09 Mbit/s | 921.90 Mbit/s |

Each cell is one run. The runs on a shared host can change by about 10 %. Do not read a small difference as a result.

### CPU during the release bulk transfer (3 s sample, percent of one core)

| Code | Path | Sender router thread | Sender relay thread | Receiver relay thread | Receiver direct thread | Relay server |
| --- | --- | --- | --- | --- | --- | --- |
| before | prc_prc direct | 91.00 | 0.33 | 0.67 | 60.67 | 0.33 |
| before | prc_prc relay | 4.00 | 8.00 | 8.33 | - | 9.00 |
| after | prc_prc direct | 94.33 | - | - | 65.33 | 0.67 |
| after | prc_prc relay | 80.33 | 27.00 | 64.67 | - | 76.67 |
| after | sym_sym relay | 81.67 | 27.33 | 67.00 | - | 77.33 |

"-" means that the thread used 0 ticks. The full lines are `bulk_cpu` in the logs.

## Where the time goes

**Plain container networking (about 33 Gbit/s).** The kernel moves the bytes between two veth devices.
There is no encryption, no user-space copy, and no TUN device. TCP can use 64 KiB segments (GSO).

**Before, relay (release 106.52 Mbit/s and 97.10 Mbit/s).** The node CPU was low: the router thread used 4 %, and the relay thread 8 %.
The relay path did not use the CPU. It waited. The relay loop moved frames only once in each 2 ms round,
and the RTT on the relay path was about 6 ms. A single TCP stream cannot go faster than its window divided by the RTT,
and the wait in the queue was part of each RTT. This limited the throughput to about one eighth of the direct path.

**After, relay and direct (release 863 Mbit/s to 922 Mbit/s).** The sender router thread used 80 % to 94 % of one core.
For each packet, this one thread reads the packet from the TUN reader, seals it with ChaCha20-Poly1305, and sends one UDP datagram.
The thread handles one packet of up to 1500 bytes in each system call. There is no batch send and no GSO.
This single thread is the limit for one TCP stream, on the direct path and on the relay path.
On the relay path, the relay server used about 77 % of one core: one `recv` and one `send` for each datagram in one thread.
The relay server is the next limit.
The receiver relay thread used 65 % to 67 %. It opens each frame and gives the packet to the TUN writer.

**Debug build (about 30 Mbit/s on all overlay paths).** The debug binary has no optimization.
In the debug bulk transfer, the sender router thread and the receiver thread each used 85 % to 88 % of one core.
The seal and open code and the frame code are much slower without optimization. The relay path is not the limit.
Use the release numbers to compare paths.

**RTT.** The direct path RTT is about 1.2 ms to 2.0 ms. The bare veth RTT is 0.04 ms.
Most of the direct RTT is in user space: the TUN read, the router thread, the seal, the UDP send, and the same steps in the other node.
The direct receive loop still uses a 5 ms read timeout, and the router thread still wakes every 10 ms when it has no packet.
These timers do not add to the RTT of a ping, because a packet wakes each thread at once.

## Idle CPU ([C], 10 s sample, no ping and no bulk transfer)

| Build | Code | Node process | Node relay thread | Relay server |
| --- | --- | --- | --- | --- |
| debug | before | 9.20 % and 9.70 % | 1.50 % and 1.40 % | 0.60 % |
| release | before | 1.60 % and 1.70 % | 0.80 % and 0.80 % | 0.40 % |
| debug | after | 8.10 % to 8.90 % | 0.30 % to 0.40 % | 0.40 % to 0.50 % |
| release | after | 1.10 % to 1.30 % | 0.10 % to 0.30 % | 0.30 % to 0.40 % |

There is no spin. The relay thread wakes on a frame, or every 20 ms for the hello and probe frames.
When the node is idle, it still sends a hello every 50 ms and a probe every 100 ms on each path. This is the keepalive cost.
In the debug build, the thread `orblx-nat-publish` uses most of the idle node CPU (5.90 % to 6.50 %).
That thread sends the candidate update to the coordinator once each second. It is not part of the relay path.

## PR head proof

The gate and the proofs ran at the PR head `360bc861` (PR #54). Later commits on the branch change only this document.

- REAL: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` gave exit 0
  (`pr54-360bc861-fmt.log`, `pr54-360bc861-clippy.log`, `pr54-360bc861-test.log`).
- [C] `scripts/proof/nat-realism.sh` (debug build, default gates) printed `proof_ok` (`pr54-360bc861-nat-realism.log`).
- [C] `scripts/proof/nat.sh` printed `proof_ok` (`pr54-360bc861-nat.log`).

Lines from `pr54-360bc861-nat-realism.log`:

```text
rtt plain_avg_ms 0.042 direct_avg_ms 1.834 direct_i0.23_avg_ms 1.805
relay_rtt prc_prc relay_avg_ms 2.246 direct_avg_ms 1.834 slack_ms 2 lost 0/50 relay_gate ok
relay_rtt sym_sym relay_avg_ms 2.289 direct_avg_ms 1.834 slack_ms 2 lost 0/50 relay_gate ok
switch prc_prc direct_to_relay detect_ms 592 lost 0/50 max_gap_ms 435
switch prc_prc relay_to_direct detect_ms 509 lost 0/50 max_gap_ms 201
switch prc_sym direct_to_relay detect_ms 545 lost 0/50 max_gap_ms 362
switch prc_sym relay_to_direct detect_ms 747 lost 0/50 max_gap_ms 228
throughput plain bytes 14598995968 seconds 5.001 mbit_s 23351.48
throughput prc_prc_direct bytes 18612224 seconds 5.101 mbit_s 29.19
throughput prc_prc_relay bytes 20840448 seconds 5.391 mbit_s 30.93
throughput sym_sym_relay bytes 20512768 seconds 5.308 mbit_s 30.92
idle_cpu prc_prc_relay orblx-natr-a thread pid 1 name orblx-nat-relay ticks 5 cpu_pct 0.50
idle_cpu prc_prc_relay relay cpu pid 1 ticks 4 hz 100 seconds 10 cpu_pct 0.40 cmd orblx relay
idle_cpu sym_sym_relay relay cpu pid 1 ticks 5 hz 100 seconds 10 cpu_pct 0.50 cmd orblx relay
```

The plain number in this run (23351.48 Mbit/s) is lower than in the other runs (about 33000 Mbit/s).
The other worker used the host at the same time. The plain path uses the host CPU and has no orblx code.

CPU during the debug bulk transfer at the PR head (3 s sample, percent of one core):
the sender router thread used 86.00 % (direct) and 87.67 % (relay).
The receiver direct thread used 85.33 %, and the receiver relay thread used 87.67 %.
The relay server used 7.00 %. Both node threads are near one full core. The debug build is CPU-bound in the node.

## Caveats

- All nodes, routers, and the relay are [C] containers on one REAL host. The numbers are for this host only.
- One TCP stream for 5 s for each cell. The proof does not measure many streams.
- The proof uses the relay UDP transport. The relay server TCP writer change has unit tests (`tcp_forwards_the_same_bytes`, `tcp_sender_keeps_order_and_wait_readable_wakes`),
  but this proof does not measure the TCP transport.
- The `orblx-edge` and `orblx-datapath` relay bridges have the same `poll(2)` change. This proof does not measure them.
- The host was shared with another worker. Some pings had a high max RTT (`sym_sym` debug: 59.5 ms).
- `poll(2)` uses `libc` and Unix file descriptors. CI builds and tests the change on Linux and macOS.
