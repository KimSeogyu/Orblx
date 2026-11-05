# Router port mapping

The node asks the local gateway for one stable external UDP port.
The protocols are PCP, NAT-PMP, and UPnP IGD.
The client is Orblx code in `crates/orblx-edge/src/portmap.rs`.
It does not use a Tailscale crate.

A mapped port is a signed candidate.
The node publishes that port twice.
The peer then treats the node as endpoint-independent and punches that port.
The node renews the map at half the granted lifetime.
Clean shutdown deletes the map.

`--port-map auto` tries PCP, then NAT-PMP, then UPnP IGD.
Each try waits at most 250 ms.
The whole probe waits at most 750 ms.
One silent gateway does not add more delay than that budget.
`--port-map off` does not send a probe. The probe time is 0 ms.
`--port-map pcp`, `--port-map nat-pmp`, and `--port-map upnp` try one protocol.
The default lifetime request is 7200 s.
This lab requests 40 s so a renew is visible in one run.

## Lab

The host is Linux. Every router, node, coordinator, and relay is a container.
The script is `scripts/proof/port-mapping.sh`.
It uses `scripts/proof/compose.nat-realism.yml` and `scripts/proof/nat-router.sh`.
The new router mode is `symmap`.
`symmap` is the symmetric `MASQUERADE --random-fully` rule plus miniupnpd.
miniupnpd serves NAT-PMP, PCP, and UPnP IGD.
Its nft SNAT chain runs before the MASQUERADE rule.
A socket that is not mapped still gets a new external port for each destination.

The lab WAN is `23.31.0.0/24` on the Docker network only.
miniupnpd refuses a private WAN address, so this lab does not use `172.16.0.0/12`.

The proof ran under `scripts/proof/proof-lock.sh`.
The build is the release profile.

```text
rustc rustc 1.99.1 (58cf8f9c3 2026-10-13)
build profile release
```

```text
proof_contention port-mapping:orblx-pmap-proof samples 251 contended_samples 0 unknown_samples 0 max_other_orblx_containers 0 max_load1 0.70
```

The lock line uses the field names `contended_samples` and `unknown_samples`.
Both values are 0.

An unmapped socket on the `symmap` router still has two external ports:

```text
mapping 23.31.0.10 23.31.0.13:27387
mapping 23.31.0.20 23.31.0.13:54830
same False
unmapped_socket symmetric true
```

## Cases

N is 5 for the three main cases.
NAT-PMP only and UPnP only each ran once.
The clock starts when the node process starts.
The time includes the probe.
Ping is 50 packets at 0.2 s. The loss limit is 1 packet.
Every run lost 0 packets.

| Case | Routers | Config | N | Success | Path | First packet on node-c | Loss |
| --- | --- | --- | --- | --- | --- | --- | --- |
| baseline | symmetric to symmetric, UDP 5351 and 1900 dropped | `--port-map auto` | 5 | 5/5 | relay | 1235, 1239, 1190, 1245, 1237 ms | 0/50 |
| mapped | symmap to symmetric | `--port-map auto` | 5 | 5/5 | direct | 866, 876, 865, 889, 846 ms | 0/50 |
| disabled | symmap to symmetric | `--port-map off` | 5 | 5/5 | relay | 496, 485, 480, 493, 490 ms | 0/50 |
| nat-pmp | symmap to symmetric | `--port-map nat-pmp` | 1 | 1/1 | direct | 629 ms | 0/50 |
| upnp | symmap to symmetric | `--port-map upnp` | 1 | 1/1 | direct | 1425 ms | 0/50 |

The mapped runs used PCP. The probe took 0 ms because the router answered in the same millisecond.
Each mapped run renewed the map and deleted it.
After delete, the miniupnpd nft chain was empty.

Baseline has no answer, so the probe uses the 750 ms budget.
The first relay packet is about 750 ms later than the disabled case.
That is the bound. The path stays relay.

## Log lines

Baseline, node-c, run 1:

```text
The port map probe budget is 750 ms.
The port map probe took 755 ms.
The port map probe ended. No router answered.
The STUN mapping is endpoint-dependent.
The local NAT mapping is endpoint-dependent.
The first relay packet arrived at 1235 ms.
The punch plan is relay-only. The local mapping is endpoint-dependent. The peer mapping is endpoint-dependent.
```

Mapped, node-c, run 1:

```text
The port map probe budget is 750 ms.
The port map probe took 0 ms.
The port map is pcp 23.31.0.13:443 lifetime 40.
The STUN mapping is endpoint-dependent.
The local NAT mapping is endpoint-independent.
The punch plan is port-spray. The local mapping is endpoint-independent. The peer mapping is endpoint-dependent.
The first relay packet arrived at 729 ms.
The hole punch reached 23.31.0.14:47109.
The first direct packet arrived at 866 ms.
```

The peer punched the mapped port:

```text
The hole punch reached 23.31.0.13:443.
The first direct packet arrived at 552 ms.
```

Disabled, node-c, run 1:

```text
The port map is off.
The port map probe took 0 ms.
The STUN mapping is endpoint-dependent.
The local NAT mapping is endpoint-dependent.
The punch plan is relay-only. The local mapping is endpoint-dependent. The peer mapping is endpoint-dependent.
The first relay packet arrived at 496 ms.
```

NAT-PMP, node-c:

```text
The port map probe took 1 ms.
The port map is nat-pmp 23.31.0.13:443 lifetime 40.
The first direct packet arrived at 629 ms.
```

UPnP, node-c:

```text
The port map probe took 50 ms.
The port map is upnp 23.31.0.13:443 lifetime 40.
The first direct packet arrived at 1425 ms.
```

Renew and delete, from the proof log:

```text
mapped run 1 renewed yes
mapped run 1 deleted yes
success baseline 5/5 mapped 5/5 disabled 5/5 nat-pmp 1/1 upnp 1/1
proof_ok
```

## Tailscale

Tailscale describes the same idea. It does not publish lab times for the mapper.
This table compares behavior. It does not invent Tailscale timings.

| Item | Orblx, this lab | Tailscale |
| --- | --- | --- |
| Protocols | PCP, then NAT-PMP, then UPnP IGD | NAT-PMP, PCP, and UPnP on the default gateway. PCP is preferred when NAT-PMP was not seen recently. UPnP is the fallback. |
| Wait for one protocol | 250 ms | `portMapServiceTimeout` is 250 ms |
| Probe budget when nothing answers | 750 ms | No single published budget. Each service wait is 250 ms. |
| Requested lifetime | 7200 s (this proof used 40 s) | `pmpMapLifetimeSec` and `pcpMapLifetimeSec` are 7200 |
| Renew | Half the granted lifetime | `renewAfter` is half the granted lifetime |
| Delete | Lifetime 0 on clean shutdown | `pmpMapLifetimeDelete` is 0 |
| Effect on two hard NATs | Direct when one router grants a map. 5/5 in this lab. First direct packet 846–889 ms. | A mapping makes one NAT easier for the peer. If mapping and hairpinning both fail, the path stays on a relay. No lab latency is published. |

Primary source for the constants: [net/portmapper/portmapper.go](https://github.com/tailscale/tailscale/blob/main/net/portmapper/portmapper.go) and [net/portmapper/pcp.go](https://github.com/tailscale/tailscale/blob/main/net/portmapper/pcp.go).
The behavior text is from [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works).

## Limits

- The router is miniupnpd in a container, not a home router.
- The lab has one NAT layer. A second NAT in front of the gateway is not mapped.
- The mapped external port in this lab is UDP 443, the same as the local punch port.
- The UPnP run is one sample. Its first direct packet was 1425 ms. The path was direct and the loss was 0/50.
- The status file is cleared before each start. The wait accepts a path only after this process logs the first packet. That keeps a previous `relay` status from starting the ping early.
