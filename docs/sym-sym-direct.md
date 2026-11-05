# Direct path for predictable symmetric NAT

This document records the direct path between two endpoint-dependent NATs when the port allocation is predictable.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test`.
- **[C]**: a container. The routers, the nodes, the coordinator, and the relay are [C].

## Tailscale behavior

Primary text, Tailscale, "How NAT traversal works" (<https://tailscale.com/blog/how-nat-traversal-works>):

> We can try to apply the same trick, but now the search is much harder: each random destination port we probe through a hard NAT also results in a random source port. That means we’re now looking for a collision on a `{source port, destination port}` pair, rather than just the destination port.
>
> Again I’ll spare you the calculations, but after 20 seconds in the same regime as the previous setup (256 probes from one side, 2048 from the other), our chance of success is… 0.01%.
>
> To hit a 99.9% chance of success, we need each side to send 170,000 probes. At 100 packets/sec, that’s 28 minutes of trying before we can communicate. 50% of the time we’ll succeed after “only” 54,000 packets, but that’s still 9 minutes of waiting around with no connection.

The same post says connections start on the relay:

> In Tailscale, we upgrade connections on the fly as we discover better paths, and all connections start out with DERP preselected.

The 0.01% figure and the 170,000-probe figure are the blog's calculation. They are not a measured Tailscale success rate.

`net/netcheck/netcheck.go` (<https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>):

> MappingVariesByDestIP is whether STUN results depend which STUN server you're talking to (on IPv4).

`GetGlobalAddrs` in the same file:

> GetGlobalAddrs returns the v4 and v6 global addresses observed during the netcheck, which includes the best latency endpoint first, followed by any other endpoints that were observed repeatedly. It excludes singular endpoints that are likely only the result of a hard NAT.

`wgengine/magicsock/magicsock.go` `determineEndpoints` (<https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/magicsock.go>):

> If they're behind a hard NAT and are using a fixed port locally, assume they might've added a static port mapping on their router to the same explicit port that tailscaled is running with. Worst case it's an invalid candidate mapping.

`handleCallMeMaybe` in `wgengine/magicsock/endpoint.go` (<https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/endpoint.go>):

> handleCallMeMaybe handles a CallMeMaybe discovery message via DERP. The contract for use of this message is that the peer has already sent to us via UDP, so their stateful firewall should be open. Now we can Ping back and make it through.

## Allocation class

The node already learns the mapping kind from two STUN answers on one socket.

When the mapping is endpoint-dependent, the node opens four more sockets and sends one STUN request on each socket. The coordinator signs the reflexive list. The list keeps the two mapping answers first. The samples follow. The peer reads the ports in that order.

`classify_ports` in `crates/orblx-edge/src/birthday.rs`:

- Fewer than four ports: `unknown`.
- Every step is the same and the step is 1 to 64: `sequential`. The origin is the highest sample.
- Any other set whose highest port is at most 512 above the lowest port: `port-block`.
- Otherwise: `random`.

A sequential NAT sprays the next 32 ports after the origin. A port block sprays a window around the midpoint. The window is at least 127 ports wide, so a 64-port block is inside it. A random allocation sprays nothing.

## Punch plan

| Local allocation | Peer allocation | Plan |
| --- | --- | --- |
| random or unknown | random or unknown | `relay-only` |
| sequential or port-block | any hard | `predict-spray` |
| any hard | sequential or port-block | `predict-spray` |

An endpoint-independent peer still uses the existing plain punch, port spray, or birthday sockets. This work does not change those plans.

`relay-only` sends no punch probes. `predict-spray` sends only the predicted ports.

One attempt, for one peer:

- Ports: at most 32 for a sequential allocation, and at most 513 for a port block (`PREDICT_PORT_MAX`).
- Packets: at most 2048 (`SPRAY_MAX`).
- Rate: 200 probes per second, burst 20.
- Time: the attempt also stops at 15 seconds.

The pair gets 4 attempts (`PREDICT_ATTEMPTS`). The packet budget is 4 × 2048 = 8192 probes from one node. Attempt 4 is the last. A later retry does not start. The spray also stops when the direct path comes up. The test `the_predict_budget_caps_ports_packets_and_attempts` checks this cap.

A punch datagram whose session token does not match is dropped. A punch whose source IP is not the signed peer is dropped. The drop happens before the node stores a direct peer. The test is `a_foreign_punch_is_dropped_before_the_peer_changes`. The lab log line is `punch_drop <address> token` or `punch_drop <address> netmap`.

The relay path is allowed as soon as both mappings are endpoint-dependent. The spray does not hold the first packet. After a move from relay to direct, the node still sends on both paths for 600 ms. A later direct failure still returns to the relay and still resends the recent direct frames.

A failed predict attempt prints `predict_probes`, waits, and tries again. The first wait is 2 seconds. Each later wait doubles. The wait stops at 60 seconds. The node gathers new STUN samples before the next attempt. The process does not restart.

## Clock

`clock_origin unix_ms` is the node process start. `path_up relay ms`, `path_up direct ms`, and `first_packet relay ms` are milliseconds from that same start. The headline numbers are the time to the first packet on the relay and the time to the direct path.

The two mapping STUN requests run first. The relay threads then start. The four allocation samples run beside the relay, so the classifier does not hold the first packet. A hard pair may use the relay as soon as both mappings are endpoint-dependent.

## Lab routers

The routers are iptables and a small UDP program on Linux containers. They are models. They are not a carrier-grade NAT.

`scripts/proof/nat-router.sh`:

- `symmetric` and `random`: `MASQUERADE --random-fully --to-ports 1024-65535`. This is the previous symmetric router.
- `sequential`: each new UDP flow gets the next external port from 1024 upward. `scripts/proof/udp-nat.py` moves the UDP. TCP and ICMP stay on the kernel NAT.
- `portblock`: each new UDP flow gets a free port in 20000-20063. The choice inside the block is not a fixed step.
- `shift`: STUN ports 3478 and 3479 stay on the sequential series, and only the STUN server can send back to those mappings. Every other destination starts at 20000 and then adds 4000. A punch aimed at the published STUN port does not enter. The predicted window misses the jumped punch port. This is the wrong-prediction model.

The UDP NAT is endpoint-dependent. Two destination ports get two external ports. A reply to a source that arrived on an external port uses that same external port. Inbound UDP from an address the inside host has sent to is accepted on an allocated port.

`scripts/proof/compose.nat-realism.yml` reads `ORBLX_NATR_MODE_C` and `ORBLX_NATR_MODE_D`. The default is `symmetric`, so the W20 proof keeps the random routers.

## Commands

```sh
export PATH=/usr/local/cargo/bin:$PATH
export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"
sudo -n env PATH="$PATH" RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" ./scripts/proof/sym-sym-direct.sh
```

The script takes the box proof lock, builds the release binary, and runs each case five times.

## Results

The run is `scripts/proof/sym-sym-direct.sh` on this host. The build is release. N is 5 for each pair. One extra run blocks the punch, waits for the second attempt, then opens the punch. The node container does not restart.

```text
rustc rustc 1.99.1 (58cf8f9c3 2026-10-13)
build profile release
```

The three times are from node-c process start. `relay_ms` is `path_up relay`. `direct_ms` is `path_up direct`. `first_packet_ms` is `first_packet relay`. The headline numbers are `first_packet_ms` and `direct_ms`. In every direct run, `first_packet_ms` is less than or equal to `direct_ms`. `probes` is the sum of the `predict_probes` lines from both nodes. `switch_lost` is the loss in 50 pings at 0.1 s. `switch_gap_ms` is the longest gap between those replies.

A foreign punch, sent from the router LAN address to the node:

```text
punch_drop 10.28.23.2:60238 token
punch_drop 10.28.23.2:60238 netmap
```

```text
case random-random-1 expect relay relay_ms 1186 direct_ms none first_packet_ms 1186 probes 0 switch_lost 0/50 switch_gap_ms 108
case sequential-random-1 expect direct relay_ms 1369 direct_ms 1685 first_packet_ms 1369 probes 61 switch_lost 0/50 switch_gap_ms 109
case sequential-sequential-1 expect direct relay_ms 1448 direct_ms 1561 first_packet_ms 1448 probes 0 switch_lost 0/50 switch_gap_ms 108
case portblock-random-1 expect direct relay_ms 1496 direct_ms 1559 first_packet_ms 1496 probes 56 switch_lost 0/50 switch_gap_ms 108
case shift-shift-1 expect miss relay_ms 1476 direct_ms none first_packet_ms 1476 probes 16384 switch_lost 0/50 switch_gap_ms 107
case random-random-2 expect relay relay_ms 1196 direct_ms none first_packet_ms 1197 probes 0 switch_lost 0/50 switch_gap_ms 108
case sequential-random-2 expect direct relay_ms 1342 direct_ms 1529 first_packet_ms 1342 probes 20 switch_lost 0/50 switch_gap_ms 108
case sequential-sequential-2 expect direct relay_ms 1492 direct_ms 1624 first_packet_ms 1492 probes 0 switch_lost 0/50 switch_gap_ms 109
case portblock-random-2 expect direct relay_ms 1472 direct_ms 1597 first_packet_ms 1473 probes 62 switch_lost 0/50 switch_gap_ms 109
case shift-shift-2 expect miss relay_ms 1371 direct_ms none first_packet_ms 1371 probes 16384 switch_lost 0/50 switch_gap_ms 107
case random-random-3 expect relay relay_ms 1193 direct_ms none first_packet_ms 1193 probes 0 switch_lost 0/50 switch_gap_ms 109
case sequential-random-3 expect direct relay_ms 1475 direct_ms 1588 first_packet_ms 1476 probes 62 switch_lost 0/50 switch_gap_ms 108
case sequential-sequential-3 expect direct relay_ms 1359 direct_ms 1461 first_packet_ms 1359 probes 0 switch_lost 0/50 switch_gap_ms 109
case portblock-random-3 expect direct relay_ms 1502 direct_ms 1564 first_packet_ms 1502 probes 60 switch_lost 0/50 switch_gap_ms 108
case shift-shift-3 expect miss relay_ms 1532 direct_ms none first_packet_ms 1532 probes 16384 switch_lost 0/50 switch_gap_ms 109
case random-random-4 expect relay relay_ms 1189 direct_ms none first_packet_ms 1189 probes 0 switch_lost 0/50 switch_gap_ms 109
case sequential-random-4 expect direct relay_ms 1529 direct_ms 1612 first_packet_ms 1530 probes 62 switch_lost 0/50 switch_gap_ms 108
case sequential-sequential-4 expect direct relay_ms 1498 direct_ms 1622 first_packet_ms 1498 probes 0 switch_lost 0/50 switch_gap_ms 106
case portblock-random-4 expect direct relay_ms 1503 direct_ms 1515 first_packet_ms 1503 probes 40 switch_lost 0/50 switch_gap_ms 108
case shift-shift-4 expect miss relay_ms 1516 direct_ms none first_packet_ms 1516 probes 16384 switch_lost 0/50 switch_gap_ms 108
case random-random-5 expect relay relay_ms 1185 direct_ms none first_packet_ms 1185 probes 0 switch_lost 0/50 switch_gap_ms 107
case sequential-random-5 expect direct relay_ms 1360 direct_ms 1507 first_packet_ms 1360 probes 20 switch_lost 0/50 switch_gap_ms 109
case sequential-sequential-5 expect direct relay_ms 1499 direct_ms 1622 first_packet_ms 1499 probes 0 switch_lost 0/50 switch_gap_ms 107
case portblock-random-5 expect direct relay_ms 1504 direct_ms 1699 first_packet_ms 1505 probes 60 switch_lost 0/50 switch_gap_ms 108
case shift-shift-5 expect miss relay_ms 1504 direct_ms none first_packet_ms 1504 probes 16384 switch_lost 0/50 switch_gap_ms 109
```

Plan lines from the fifth run of each pair:

```text
case random-random-5
The punch plan is relay-only. The local mapping is endpoint-dependent. The peer mapping is endpoint-dependent.
The local port allocation is random.
The peer port allocation is random.

case sequential-random-5
The punch plan is predict-spray. The local mapping is endpoint-dependent. The peer mapping is endpoint-dependent.
The local port allocation is sequential step 1 origin 1030.
The peer port allocation is random.

case sequential-sequential-5
The punch plan is predict-spray. The local mapping is endpoint-dependent. The peer mapping is endpoint-dependent.
The local port allocation is sequential step 1 origin 1030.
The peer port allocation is sequential step 1 origin 1030.

case portblock-random-5
The punch plan is predict-spray. The local mapping is endpoint-dependent. The peer mapping is endpoint-dependent.
The local port allocation is port-block 20003-20058.
The peer port allocation is random.
```

| Pair | Path | Success | First packet on relay | Direct path | Probes | Switch loss |
| --- | --- | --- | --- | --- | --- | --- |
| random to random | relay | 5/5 | 1185–1197 ms | none | 0 | 0/50 |
| sequential to random | direct | 5/5 | 1342–1530 ms | 1507–1685 ms | 20–62 | 0/50 |
| sequential to sequential | direct | 5/5 | 1359–1499 ms | 1461–1624 ms | 0 | 0/50 |
| port-block to random | direct | 5/5 | 1473–1505 ms | 1515–1699 ms | 40–62 | 0/50 |
| shift (wrong prediction) | relay | 5/5 | 1371–1532 ms | none | 16384 | 0/50 |

16384 probes is 4 attempts × 2048 packets × 2 nodes. That is the packet budget. The shift runs stop there and stay on the relay. Ping loss is 0. The gap stays at the 0.1 s interval.

On the sequential model the published STUN port belongs to the direct socket. A check to that port can open the path before a spray probe is counted. Those runs show 0 probes and a direct path. The shift model does not accept that check.

The blocked-punch run:

```text
retry relay up while the punch is blocked
punch_open output udp 172.29.28.13 172.29.28.14
retry paths direct direct
retry restarted false
sym_sym_direct_ok
```

The script reaches `punch_open` only after a log line `The predict attempt 2 starts.` (or a later attempt) while the UDP block is still in place. `retry restarted false` means the node container start time did not change.

```text
proof_contention sym-sym-direct:orblx-sym-proof samples 526 contended_samples 0 unknown_samples 0 max_other_orblx_containers 0 max_load1 1.03
```

## Comparison

| Pair | Orblx, this run | Tailscale primary text |
| --- | --- | --- |
| random to random | 5/5 relay. First packet 1185–1197 ms. 0 probes. | "our chance of success is… 0.01%." "all connections start out with DERP preselected." |
| sequential to random | 5/5 direct. First packet 1342–1530 ms. Direct 1507–1685 ms. | "To hit a 99.9% chance of success, we need each side to send 170,000 probes." |
| sequential to sequential | 5/5 direct. First packet 1359–1499 ms. Direct 1461–1624 ms. | "that’s 28 minutes of trying before we can communicate." |
| port-block to random | 5/5 direct. First packet 1473–1505 ms. Direct 1515–1699 ms. | "Worst case it's an invalid candidate mapping." |
| shift (wrong prediction) | 5/5 relay. First packet 1371–1532 ms. 16384 probes, the budget. Loss 0/50. | "Now we can Ping back and make it through." |

Sources: <https://tailscale.com/blog/how-nat-traversal-works>, <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>, <https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/magicsock.go>, <https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/endpoint.go>.

## Limits

- The routers are iptables models in Linux containers. They are not a carrier-grade NAT. A carrier NAT can use another allocation and another filter.
- The port-block router uses 64 ports. A larger block can fall outside the spray window.
- The sequential prediction covers 32 ports after the last sample. A router that skips more than 32 ports between the sample and the punch stays on the relay until the next attempt.
- The random router is `MASQUERADE --random-fully` over 1024-65535. Two random NATs do not punch.
