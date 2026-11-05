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

The proof log is inserted below after the run.

## Comparison

| Pair | Orblx | Tailscale |
| --- | --- | --- |
| random to random | See the result table. Plan `relay-only`. No predict spray. | DERP. No direct path. Blog calculation: 0.01% after 20 seconds of a birthday search. The client does not run that search. |
| sequential to random | See the result table. Plan `predict-spray`. | DERP when both mappings vary by destination. No predicted-port spray. |
| sequential to sequential | See the result table. Plan `predict-spray`. | DERP. The blog says a full search is not usable for interactive traffic. |
| port-block to random | See the result table. Plan `predict-spray` of the block window. | DERP. No port-block spray. |

Sources: <https://tailscale.com/blog/how-nat-traversal-works>, <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>, <https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/magicsock.go>, <https://github.com/tailscale/tailscale/blob/main/wgengine/magicsock/endpoint.go>.

## Limits

- The routers are Linux containers on one host. A carrier NAT can use another allocation and another filter.
- The port-block router uses 64 ports. A larger block can fall outside the spray window.
- The sequential prediction covers 32 ports after the last sample. A router that skips more than 32 ports between the sample and the punch stays on the relay until the next attempt.
- The random router is `MASQUERADE --random-fully` over 1024-65535. Two random NATs do not punch.
