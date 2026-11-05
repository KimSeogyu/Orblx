# Peer relay

A peer that already has a working path forwards sealed frames for a hard pair.
The peer forwards a frame when direct has failed and the coordinator Relay is far or down.
The peer relay uses the same session id as the coordinator Relay.
The peer relay has no session key.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test`.
- **[C]**: a container. The routers, the nodes, the coordinator, the coordinator Relay, and the easy peer are [C].

Gap matrix row 5 is partial.
The row is `5|partial|Peer relays` in `docs/matrix-rows.txt`.
This change does not add grants, static endpoints, or a choice among many peer relays.

## Path choice

`PathMachine::pick_path` in `crates/orblx-edge/src/path.rs` chooses one path for the next packet.

- Direct wins when direct probes went both ways.
- Peer relay wins when direct has failed, the peer relay probes went both ways, and the coordinator Relay is down or its attach RTT is at least `RELAY_FAR_MS` (50 ms).
- The coordinator Relay carries the packet when it is up and the peer relay is not selected.
- A near coordinator Relay stays ahead of the peer relay.
- An unknown attach RTT is not far. The first packets stay on the coordinator Relay until a sample exists.
- The function does not return a wait.

The peer relay loop runs beside the coordinator Relay loop.
The first packet uses the best path that is already up.
The node does not hold that packet for peer relay discovery.

The lab log line is `The peer relay discovery does not delay the first packet.`

## Sealed forward

`SealedPayload::parse` in `crates/orblx-relay/src/sealed.rs` is the only way to build a payload the sealed-only server will forward.
The module has no key and no decrypt function.

A payload must be an `ORBLXNAT` frame, version 1.

- A hello frame carries the public key material. The body is longer than 96 bytes.
- A probe frame and a data frame carry ciphertext. The body is at least 24 bytes (an 8 byte counter and a 16 byte tag).
- Any other bytes are `RelayError::Plaintext`. An IPv4 packet cannot be a `SealedPayload`.

`--sealed-only` calls this check before a forward.
A reject increments `orblx_relay_plaintext_rejects` and does not increment `orblx_relay_plaintext_hits`.
The coordinator Relay in this lab does not use `--sealed-only`, so the existing QUIC proof payloads still forward.

The easy peer runs `orblx relay --sealed-only`.
Each hard node passes `--peer-relay ADDR`.
The easy peer is enrolled. It has no NAT. The working path is a UDP attach to that public address.

## Lab

The host is Linux. The script is `scripts/proof/peer-relay.sh`.
It uses `scripts/proof/compose.nat-realism.yml` and `scripts/proof/nat-router.sh`.
Router-c and router-d use mode `random` (symmetric NAT, `--random-fully`).
The coordinator is `172.29.31.10`. The coordinator Relay is `172.29.31.20`. The easy peer is `172.29.31.30`.

This kernel has no netem qdisc.
The far case sets `--attach-delay-ms 100` on the coordinator Relay.
The flag waits 100 ms before the attach reply.
It does not delay a forwarded payload.
The node records that wait as the coordinator Relay RTT.
The down case drops UDP 443 and TCP 443 on the coordinator Relay. STUN on 3478 and 3479 stays up.
The near case uses `--attach-delay-ms 0`.

The far case starts the easy peer after the log line `first_packet relay`.
The down case and the near case start the easy peer before the nodes.

Ping is 50 packets at 0.1 s. Every run lost 0 packets.
The largest gap in a run is 110 ms.

The proof ran under `scripts/proof/proof-lock.sh`.
The build is the release profile.

```text
rustc rustc 1.99.1 (58cf8f9c3 2026-10-13)
build profile release
easy_peer_nat none address 172.29.31.30
proof_contention peer-relay:orblx-peer-proof samples 303 contended_samples 0 unknown_samples 0 max_other_orblx_containers 0 max_load1 0.76
```

The lock line uses `contended_samples` and `unknown_samples`.
Both values are 0.

## Cases

N is 5 for each case.
`first_packet_ms` and `path_ms` are from node-c process start.
`rtt_ms` is the coordinator Relay attach time. `none` means the attach did not complete.

| Case | N | Path | First packet kind | First packet (node-c) | Path time (node-c) | Attach RTT | Loss |
| --- | --- | --- | --- | --- | --- | --- | --- |
| far, attach delay 100 ms, peer starts after the first packet | 5 | peer-relay | relay | 1031, 1058, 1070, 1077, 1081 ms | 1783, 1806, 1830, 1866, 1888 ms | 100 ms | 0/50 |
| down, UDP 443 and TCP 443 dropped | 5 | peer-relay | peer-relay | 1277, 1278, 1279, 1280, 1286 ms | 1277, 1277, 1279, 1280, 1286 ms | none | 0/50 |
| near, attach delay 0 ms, peer is up | 5 | relay | relay | 1041, 1056, 1062, 1071, 1081 ms | 346, 348, 356, 356, 357 ms | 1 ms | 0/50 |

```text
peer_relay_ok
proof_ok
```

## Plaintext inject

Each run sends one UDP datagram to the easy peer on port 443.
The body is version 1, kind 2, the session id, then an IPv4 header and the bytes `ORBLXPLAIN`.
Every run recorded `orblx_relay_plaintext_hits 0` and `orblx_relay_plaintext_rejects 1`.
The audit needle hit count on the peer was 0.
The test `sealed_only_forwards_a_sealed_frame_and_drops_ipv4` checks the same drop in process.

## Tailscale

This table compares behavior.
It does not invent Tailscale timings.
Tailscale does not publish a first-packet time for peer relay on these pages.

| Item | Orblx, this lab | Tailscale |
| --- | --- | --- |
| Order | Direct when it is up. Peer relay when direct has failed and the coordinator Relay is far or down, and the peer relay is already up. A near coordinator Relay stays. | Direct, then peer relays, then DERP. |
| First packet | Far: the first packet is on the coordinator Relay at 1031–1081 ms. The peer process starts after that packet. The path is peer-relay at 1783–1888 ms. Down: the first packet is peer-relay at 1277–1286 ms. | The docs describe the order above. They do not publish a wait for peer relay discovery. |
| Bytes on the relay | A sealed NAT frame. The peer relay has no key. An IPv4 packet is dropped. | Disco packets and WireGuard packets. Private keys stay on the device. |
| Listen port | UDP 443 and TCP 443. Same relay session id. | `tailscale set --relay-server-port=40000` (UDP). |
| Who may forward | An enrolled peer that runs `orblx relay --sealed-only`. | A grant with `tailscale.com/cap/relay`. |
| Dependencies | No Tailscale, DERP, WireGuard, or Headscale crate. | The Tailscale client. |

Primary sources:

- [Tailscale Peer Relays](https://tailscale.com/docs/features/peer-relay). "When a device attempts to connect to another device in the tailnet, it first checks if a direct connection is possible. If not, it looks for available peer relays in the tailnet. If a peer relay is available and accessible, the device establishes a connection through the peer relay. If no peer relays are available, the device falls back to using DERP servers to relay the traffic." The same page shows `tailscale set --relay-server-port=40000` and the grant `tailscale.com/cap/relay`.
- [DERP servers](https://tailscale.com/docs/reference/derp-servers). "When a direct connection isn't possible Tailscale first attempts to use any available peer relays in the tailnet. If there aren't any peer relays available, it then falls back to DERP servers." The same page says Tailscale encrypts DERP traffic with WireGuard and that private keys never leave the device, so a DERP server cannot decrypt the traffic.
- [Introducing Tailscale Peer Relays](https://tailscale.com/blog/peer-relays-beta). "Tailscale prefers direct connections wherever possible. Clients can then fall back to available peer relays, and finally leverage Tailscale’s managed DERP fleet, or any customer-deployed custom DERPs, to ensure you have connectivity wherever you need it." The same post says "All of this traffic, over any connection, is still end-to-end encrypted via WireGuard®."
- [`net/udprelay/server.go`](https://github.com/tailscale/tailscale/blob/main/net/udprelay/server.go). "Package udprelay contains a relay server implementation for relaying Disco and WireGuard packets between Tailscale clients over UDP. This relay functionality is also known as Tailscale Peer Relays."

The same post says: "In testing with early design partners, we’ve seen throughputs nearing that of a direct connection; often multiple orders of magnitude higher than Tailscale’s managed DERP fleet."
That sentence is Tailscale's report.
This lab did not measure throughput.

## Limits

- The routers are iptables on Linux containers. They are not a carrier-grade NAT.
- The easy peer has no NAT. The lab has one peer relay.
- The far signal is the attach reply wait. This kernel cannot load a netem qdisc.
- A near coordinator Relay is not replaced by the peer relay.
- Peer relay is not the primary path step. Direct still wins when it is up.
