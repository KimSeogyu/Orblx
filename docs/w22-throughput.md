# W22-5 Throughput

This document shows the W22-5 send path work, the measured numbers, and the new limit.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test`.
- **[C]**: a container. All routers, nodes, the coordinator, and the relay are [C].

Host: one REAL Linux x86_64 host, 8 vCPU (`Intel(R) Xeon(R) Processor`), kernel 6.12.
All [C] containers share this host. Another worker ran builds and proofs on the same host at the same time.
All numbers come from the logs in `/workspace/orblx-w18-proof/` on that host.
This document has no target numbers. Each number is a measured value.

## What changed

W21 found one limit: the node router thread did all of the send work for one TCP stream.
For each packet, it read the packet, sealed it, and sent one UDP datagram with one system call.
The relay server was the next limit: one thread did one `recv` and one `send` for each datagram.

This change:

- **Batch send and receive (`orblx-relay` `batch.rs`).** `send_batch` sends many datagrams with one `sendmmsg(2)` call.
  Each datagram has two parts (an optional prefix and the frame), so the relay header is not copied.
  `recv_batch` receives many datagrams with one `recvmmsg(2)` call (`MSG_WAITFORONE`).
  On systems other than Linux, the functions use one call for each datagram.
- **Node router batch (`orblx nat run`).** The router thread takes up to 32 TUN packets that already wait.
  It seals them under one key lock, and it queues them under one queue lock.
  Each frame still has its own nonce counter. The seal is the same ChaCha20-Poly1305 seal. There is no new crypto.
- **Node send thread (`orblx-nat-send`).** The router thread does not send. It wakes the new send thread.
  The send thread sends the direct queue with `send_batch` and the relay queue with `RelaySender::send_many`.
  The seal and the kernel UDP send now run on two cores.
  The send thread also wakes every 50 ms without a wake, so a frame cannot stay in a queue.
  A partial send puts the rest of the frames back at the front of the queue, in order.
- **Relay server receive and send threads.** The UDP loop receives with `recv_batch`.
  It finds the destination of each datagram under one lock.
  A second thread (`orblx-relay-send`) sends the batch with `send_batch` to one address for each datagram.
  The two threads pass a pool of 4 buffers through two channels. The relay sends the received bytes. It does not copy them.
  A TCP destination still uses the TCP writer thread from W21.

The change adds no new crate. `libc` was already a dependency of `orblx-relay`.
There is no GSO. GSO needs datagrams of equal size, and the overlay frames have different sizes.

## Method

- One build of each tree: `cargo build --release -p orblx-cli` before the runs.
  No build ran during the runs, except the builds of the other worker.
- "Before" is `main` at `ca59caf` (the W21 code) in a clean worktree. "After" is this change on `ca59caf`.
- 3 runs of each, in turns: before, after, before, after, before, after.
- Each run is `ORBLX_NATR_PROFILE=release scripts/proof/nat-realism.sh`. Each run printed `proof_ok`.
- The throughput tool is `scripts/proof/tcp-bulk.py`, the same file in both trees. One TCP stream for 5 s.
- The logs are `w22-5-baseline-ca59caf-r{1,2,3}-run1-release-nat-realism.log` and `w22-5-after-r{1,2,3}-run1-release-nat-realism.log`.

The PR branch later took the new `main` commits (W22-1, W22-2, W22-4). Those commits do not change the relay or the node send path.

## Results: throughput ([C], release, TCP bulk transfer, 5 s, one stream)

| Run | Plain (no orblx) | prc_prc direct | prc_prc relay | sym_sym relay |
| --- | --- | --- | --- | --- |
| before r1 | 35074.05 | 824.29 | 875.90 | 698.11 |
| before r2 | 37480.26 | 733.97 | 635.15 | 929.90 |
| before r3 | 35936.33 | 931.12 | 1036.25 | 1009.08 |
| after r1 | 34776.99 | 1133.00 | 893.52 | 1113.31 |
| after r2 | 34811.36 | 1094.14 | 1141.82 | 1141.16 |
| after r3 | 32226.28 | 1045.97 | 1127.93 | 1105.28 |

All numbers are Mbit/s.

| Path | Before range | Before median | After range | After median |
| --- | --- | --- | --- | --- |
| prc_prc direct | 733.97 to 931.12 | 824.29 | 1045.97 to 1133.00 | 1094.14 |
| prc_prc relay | 635.15 to 1036.25 | 875.90 | 893.52 to 1141.82 | 1127.93 |
| sym_sym relay | 698.11 to 1009.08 | 929.90 | 1105.28 to 1141.16 | 1113.31 |
| relay, both topologies (6 values) | 635.15 to 1036.25 | 902.90 | 893.52 to 1141.82 | 1120.62 |
| plain | 35074.05 to 37480.26 | 35936.33 | 32226.28 to 34811.36 | 34776.99 |

The after median is higher than the before median on each overlay path.
The ranges overlap: the best before run (1036.25) is above the worst after run (893.52).
The after ranges are narrower. The before runs change by up to 63 % on one path.
The plain path has no orblx code. Its median is 3 % lower in the after runs, so the host was not less busy in those runs.

The W21 document showed only its best run. The W21 release runs gave 650.97 to 921.90 Mbit/s on the overlay paths.
The before runs here (same code) gave 635.15 to 1036.25 Mbit/s. `docs/w21-relay-perf.md` now shows the full W21 range.

## Results: RTT gate and switch ([C], release, 50 pings at 200 ms)

| Run | Direct avg | prc_prc relay avg | sym_sym relay avg | Lost | Gate |
| --- | --- | --- | --- | --- | --- |
| before r1 | 1.340 ms | 1.398 ms | 1.220 ms | 0/50 | ok |
| before r2 | 1.133 ms | 1.251 ms | 1.613 ms | 0/50 | ok |
| before r3 | 1.066 ms | 1.546 ms | 1.292 ms | 0/50 | ok |
| after r1 | 1.431 ms | 1.920 ms | 1.878 ms | 0/50 | ok |
| after r2 | 1.405 ms | 1.962 ms | 1.804 ms | 0/50 | ok |
| after r3 | 1.618 ms | 1.934 ms | 2.093 ms | 0/50 | ok |

The gate is: relay avg is not more than direct avg + 2 ms, and 0/50 lost. All 6 runs passed.
The after relay RTT is 0.32 ms to 0.56 ms above direct. The before relay RTT is 0.12 ms below to 0.48 ms above direct.

The after RTT is higher, by about 0.3 ms on direct and 0.5 ms on relay.
The cause is the hand-off between threads. A ping packet now goes from the router thread to the send thread,
and on the relay from the relay receive thread to the relay send thread. Each hand-off is one wake of a sleeping thread.
This is a cost of the change. The gate still passes with 1.4 ms or more of slack.

The switch gaps (direct to relay and back) were 207 ms to 397 ms before and 207 ms to 412 ms after, with 0/50 lost in each switch.

## Where the time goes (CPU in the 3 s sample, percent of one core)

| Code | Path | Sender router | Sender send | Receiver path thread | Relay server receive | Relay server send |
| --- | --- | --- | --- | --- | --- | --- |
| before r1 | prc_prc direct | 94.33 | - | 65.00 | - | - |
| before r1 | prc_prc relay | 74.67 | - | 61.33 | 72.00 (one thread) | - |
| after r1 to r3 | prc_prc direct | 33.67 to 38.00 | 38.67 to 40.67 | 68.00 to 78.67 | - | - |
| after r1 to r3 | prc_prc relay | 33.33 to 35.33 | 52.67 to 54.67 | 69.33 to 71.00 | 27.67 to 29.00 | 73.00 to 75.33 |
| after r1 to r3 | sym_sym relay | 34.67 to 35.33 | 52.00 to 55.00 | 71.00 to 73.33 | 27.67 to 28.00 | 72.00 to 77.00 |

"-" means that the thread does not exist in that code, or that it did not do the work.
"Receiver path thread" is `orblx-nat-direc` (direct) or `orblx-nat-relay` (relay) on the receiving node.
The full lines are `bulk_cpu` in the logs.

One dev run (`w22-5-dev3-diag-run1-release-nat-realism.log`) used a changed copy of `tcp-bulk.py` that also printed user and system time.
That run is not in the tables above. It showed:

- Sender router thread: 90 % to 92 % user time. This is the seal.
- Sender send thread: 96 % to 99 % system time. This is the kernel UDP path through veth, the [C] NAT router, and conntrack.
- Relay server send thread: 92 % to 95 % system time.
- Receiver relay thread: 69 % to 74 % user time. This is the open and the frame code.

**Before.** The sender router thread was near one full core (94 % direct, 75 % relay) and it did the seal and the send.
On the relay path, the single relay server thread did both the receive and the send.

**After.** No orblx thread is at one full core. The highest threads are:

- The receiver path thread, at 68 % to 79 %. It still receives one datagram in each call, opens it, and gives it to the TUN writer.
- The relay server send thread, at 72 % to 77 %. This is mostly kernel send time.
- The sender send thread, at 39 % to 55 %. This is mostly kernel send time.

**The new limit.** The sender is no longer the limit. The new limit is the receive side and the kernel UDP path, for one TCP stream:

1. The receiver path thread does the open and the TUN hand-off for each packet in one thread. It is the busiest orblx thread.
2. The kernel UDP path (veth, the [C] NAT router, conntrack) costs system time in each send thread. Batching cuts the number of system calls. It does not cut the per-packet kernel work.
3. One TCP stream cannot go faster than its window divided by the RTT. The thread hand-offs added about 0.3 ms to 0.5 ms of RTT.

Because no single thread is at 100 %, the stream is also limited by the RTT and by the hand-offs between threads.
The next steps on this path are a batch receive in the node receive threads and fewer thread hand-offs for each packet.
This document does not measure those steps.

## PR head proof ([C], release)

One more release run at the PR head `f559d537` (this change on `main` `bd26bba`).
Log: `pr60-f559d537-release-nat-realism.log`. It printed `proof_ok`.

| Path | Mbit/s | RTT avg | Lost | Gate |
| --- | --- | --- | --- | --- |
| plain | 33455.48 | - | - | - |
| prc_prc direct | 898.53 | 1.511 ms | 0/50 | - |
| prc_prc relay | 977.01 | 1.795 ms | 0/50 | ok |
| sym_sym relay | 967.18 | 1.983 ms | 0/50 | ok |

This run is lower than the 3 after runs. It is in the before range on each path.
With this run, the after medians of 4 runs are 1070.06 (direct), 1052.47 (prc_prc relay), and 1109.30 (sym_sym relay) Mbit/s.
Each of these is still higher than the before median. The host was shared during this run too.

## Tests

- REAL `cargo test -p orblx-relay`: `batch_send_and_receive_keep_bytes_order_and_source` sends 70 frames through `send_batch` and `recv_batch`.
  It checks the bytes, the order, and the source address.
  `each_peer_needs_one_address_for_each_datagram` checks the input error.
- REAL `cargo test -p orblx-relay` and `-p orblx-edge`: the W21 relay tests, the NAT tests, and the TCP relay tests pass with the new send path.

## Caveats

- All nodes, routers, and the relay are [C] containers on one REAL host. The numbers are for this host only.
- Another worker used the same host during the runs. The before runs change by up to 63 % on one path.
- 3 runs of each code. The ranges overlap. The medians are higher after on each overlay path.
- One TCP stream for 5 s for each cell. The proof does not measure many streams.
- The proof uses the relay UDP transport. The TCP transport did not change in this work, and this proof does not measure it.
- The change adds about 0.3 ms to 0.5 ms of RTT. The RTT gate still passes.
- macOS uses one system call for each datagram. CI runs the tests on macOS. This proof does not run on macOS.
