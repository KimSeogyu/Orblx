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

The 0.01% figure and the 170,000-probe figure are the blog's calculation. They are not a measured Tailscale success rate. This document does not invent a Tailscale success rate.

The client classifies a hard NAT when two STUN servers return two ports. `net/netcheck/netcheck.go` (<https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>):

> MappingVariesByDestIP is whether STUN results depend which STUN server you're talking to (on IPv4).

`GetGlobalAddrs` in the same file says it "excludes singular endpoints that are likely only the result of a hard NAT."

`wgengine/magicsock/magicsock.go` `determineEndpoints` (<https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/magicsock.go>) adds one extra candidate for a hard NAT, the local fixed port, and calls it an invalid candidate in the worst case:

> If they're behind a hard NAT and are using a fixed port locally, assume they might've added a static port mapping on their router to the same explicit port that tailscaled is running with. Worst case it's an invalid candidate mapping.

`handleCallMeMaybe` in `wgengine/magicsock/endpoint.go` (<https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/endpoint.go>) pings the endpoints named in the message. It does not spray a predicted port range. Two hard NATs therefore stay on DERP. The blog states that a birthday search of that pair is not usable for interactive traffic.

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

`relay-only` sends no punch probes. `predict-spray` sends only the predicted ports, at the existing limit of 200 probes per second, burst 20, and at most 2048 probes in 15 seconds. A node accepts a punch only from the signed peer IP and only with the session token.

The relay path is allowed as soon as both mappings are endpoint-dependent. The spray does not hold the first packet. After a move from relay to direct, the node still sends on both paths for 600 ms. A later direct failure still returns to the relay and still resends the recent direct frames.

A failed predict attempt prints `predict_probes`, waits, and tries again. The first wait is 2 seconds. Each later wait doubles. The wait stops at 60 seconds. The node gathers new STUN samples before the next attempt. The process does not restart.

## Lab routers

`scripts/proof/nat-router.sh`:

- `symmetric` and `random`: `MASQUERADE --random-fully --to-ports 1024-65535`. This is the previous symmetric router.
- `sequential`: each new UDP flow gets the next external port from 1024 upward. `scripts/proof/udp-nat.py` moves the UDP. TCP and ICMP stay on the kernel NAT.
- `portblock`: each new UDP flow gets a free port in 20000-20063. The choice inside the block is not a fixed step.

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

`relay_ms` and `direct_ms` are `path_up` from process start. `first_packet_ms` is the first ICMP reply, measured from the host clock before the two node containers start. That clock includes container start, so it is larger than `relay_ms`. `probes` is the sum of the `predict_probes` lines from both nodes. `switch_lost` is the loss in 50 pings at 0.1 s after the first reply. `switch_gap_ms` is the longest gap between those replies.

```text
case random-random-1 expect relay relay_ms 111 direct_ms none first_packet_ms 1713 probes 0 switch_lost 0/50 switch_gap_ms 108
case sequential-random-1 expect direct relay_ms 111 direct_ms 1501 first_packet_ms 1954 probes 262 switch_lost 0/50 switch_gap_ms 108
case sequential-sequential-1 expect direct relay_ms 232 direct_ms 1514 first_packet_ms 1917 probes 231 switch_lost 0/50 switch_gap_ms 109
case portblock-random-1 expect direct relay_ms 111 direct_ms 1308 first_packet_ms 1838 probes 224 switch_lost 0/50 switch_gap_ms 109
case random-random-2 expect relay relay_ms 111 direct_ms none first_packet_ms 1695 probes 0 switch_lost 0/50 switch_gap_ms 108
case sequential-random-2 expect direct relay_ms 111 direct_ms 1560 first_packet_ms 1956 probes 261 switch_lost 0/50 switch_gap_ms 109
case sequential-sequential-2 expect direct relay_ms 273 direct_ms 1571 first_packet_ms 1990 probes 203 switch_lost 0/50 switch_gap_ms 108
case portblock-random-2 expect direct relay_ms 111 direct_ms 1570 first_packet_ms 1927 probes 268 switch_lost 0/50 switch_gap_ms 108
case random-random-3 expect relay relay_ms 111 direct_ms none first_packet_ms 1713 probes 0 switch_lost 0/50 switch_gap_ms 108
case sequential-random-3 expect direct relay_ms 111 direct_ms 1624 first_packet_ms 2021 probes 260 switch_lost 0/50 switch_gap_ms 108
case sequential-sequential-3 expect direct relay_ms 111 direct_ms 1563 first_packet_ms 1980 probes 243 switch_lost 0/50 switch_gap_ms 109
case portblock-random-3 expect direct relay_ms 111 direct_ms 1568 first_packet_ms 1972 probes 267 switch_lost 0/50 switch_gap_ms 108
case random-random-4 expect relay relay_ms 111 direct_ms none first_packet_ms 1750 probes 0 switch_lost 0/50 switch_gap_ms 109
case sequential-random-4 expect direct relay_ms 111 direct_ms 1616 first_packet_ms 1942 probes 260 switch_lost 0/50 switch_gap_ms 109
case sequential-sequential-4 expect direct relay_ms 233 direct_ms 1419 first_packet_ms 1936 probes 185 switch_lost 0/50 switch_gap_ms 109
case portblock-random-4 expect direct relay_ms 111 direct_ms 1666 first_packet_ms 1847 probes 268 switch_lost 0/50 switch_gap_ms 108
case random-random-5 expect relay relay_ms 111 direct_ms none first_packet_ms 1746 probes 0 switch_lost 0/50 switch_gap_ms 108
case sequential-random-5 expect direct relay_ms 111 direct_ms 1498 first_packet_ms 1909 probes 260 switch_lost 0/50 switch_gap_ms 108
case sequential-sequential-5 expect direct relay_ms 181 direct_ms 1563 first_packet_ms 1918 probes 251 switch_lost 0/50 switch_gap_ms 108
case portblock-random-5 expect direct relay_ms 111 direct_ms 1647 first_packet_ms 1947 probes 270 switch_lost 0/50 switch_gap_ms 109
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

| Pair | Path | Success | Relay path | First packet | Direct path | Probes | Switch loss |
| --- | --- | --- | --- | --- | --- | --- | --- |
| random to random | relay | 5/5 | 111 ms | 1695–1750 ms | none | 0 | 0/50 |
| sequential to random | direct | 5/5 | 111 ms | 1909–2021 ms | 1498–1624 ms | 260–262 | 0/50 |
| sequential to sequential | direct | 5/5 | 111–273 ms | 1917–1990 ms | 1419–1571 ms | 185–251 | 0/50 |
| port-block to random | direct | 5/5 | 111 ms | 1838–1972 ms | 1308–1666 ms | 224–270 | 0/50 |

Every direct run has `relay_ms` below `direct_ms`. The first packets use the relay. The later path is direct. The ping gap stays at the 0.1 s interval (108 ms or 109 ms). The switch drops no ping in these 50-ping samples.

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
proof_contention sym-sym-direct:orblx-sym-proof samples 327 contended_samples 0 unknown_samples 0 max_other_orblx_containers 0 max_load1 0.87
```

## Comparison

| Pair | Orblx, this run | Tailscale |
| --- | --- | --- |
| random to random | 5/5 relay. 0 predict probes. Plan `relay-only`. | DERP. The blog calculates 0.01% for a birthday search after 20 seconds. The client pings advertised endpoints only. |
| sequential to random | 5/5 direct. Direct path 1498–1624 ms from process start. 260–262 probes. Switch loss 0/50. | DERP when both mappings vary by destination. The client pings the endpoints named in the call-me message. |
| sequential to sequential | 5/5 direct. Direct path 1419–1571 ms from process start. 185–251 probes. Switch loss 0/50. | DERP. The blog says 170,000 probes per side for a 99.9% birthday collision, which is 28 minutes at 100 packets per second. |
| port-block to random | 5/5 direct. Direct path 1308–1666 ms from process start. 224–270 probes. Switch loss 0/50. | DERP. The client pings the endpoints named in the call-me message. |

Sources: <https://tailscale.com/blog/how-nat-traversal-works>, <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>, <https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/magicsock.go>, <https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/endpoint.go>.

## Limits

- The routers are Linux containers on one host. A carrier NAT can use another allocation and another filter.
- The port-block router uses 64 ports. A larger block can fall outside the spray window.
- The sequential prediction covers 32 ports after the last sample. A router that skips more than 32 ports between the sample and the punch stays on the relay until the next attempt.
- The random router is `MASQUERADE --random-fully` over 1024-65535. Two random NATs do not punch.
