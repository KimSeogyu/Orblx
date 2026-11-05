# Router port mapping

The node asks the local gateway for one stable external UDP port.
The protocols are PCP, NAT-PMP, and UPnP IGD.
The client is Orblx code in `crates/orblx-edge/src/portmap.rs`.
It does not use a Tailscale crate.

The probe runs beside STUN and the relay.
A silent gateway does not delay the first relay packet.
A granted port is published twice.
The peer then treats the node as endpoint-independent and punches that port.
The node renews the map at half the granted lifetime.
Clean shutdown deletes the map.

`--port-map auto` tries PCP, then NAT-PMP, then UPnP IGD.
Each try waits at most 250 ms.
The whole probe waits at most 750 ms.
`--port-map off` does not send a probe.
`--port-map pcp`, `--port-map nat-pmp`, and `--port-map upnp` try one protocol.
The requested lifetime is from 1 s to 7200 s.
This lab requests 40 s so a renew is visible in one run.

## Why the two relay times differed

An earlier lab waited for the probe before the relay started.
The baseline drops UDP 5351 and UDP 1900, so each try uses its full wait.
That probe took about 755 ms.
The first relay packet then arrived at 1190–1245 ms.
`--port-map off` took 0 ms to probe, and the first relay packet arrived at 480–496 ms.

This lab does not wait.
The baseline probe still takes about 757 ms, and it ends after the first relay packet.
Run 1 on node-c:

```text
The port map probe started at 0 ms.
The first relay packet arrived at 489 ms.
The port map probe took 757 ms.
The port map probe ended. No router answered.
```

`--port-map off` on the same router, run 1:

```text
The port map is off.
The port map probe took 0 ms.
The port map probe did not start.
The first relay packet arrived at 494 ms.
```

The two relay cases now match.
The old gap was the blocked probe, not a different relay path.

## Time split

Mapped run 1, node-c, PCP. The clock starts when the process starts.

```text
The port map probe started at 0 ms.
The port map probe took 50 ms.
The port map was granted at 51 ms.
The port map is pcp 23.31.0.13:443 lifetime 40.
The endpoints were published at 89 ms.
The punch plan time is 103 ms.
The endpoints were published at 175 ms.
The first relay packet arrived at 489 ms.
The hole punch reached 23.31.0.14:56817.
The first direct packet arrived at 605 ms.
```

The first packet is the relay packet at 489 ms.
The direct packet is at 605 ms.
The map grant is at 51 ms.
The extra time after the grant is publish and punch, not the probe budget.

## Lab

The host is Linux. Every router, node, coordinator, and relay is a container.
The script is `scripts/proof/port-mapping.sh`.
It uses `scripts/proof/compose.nat-realism.yml` and `scripts/proof/nat-router.sh`.
The router mode `symmap` is symmetric NAT plus miniupnpd.
miniupnpd serves NAT-PMP, PCP, and UPnP IGD.
An unmapped socket still gets a new external port for each destination.

```text
mapping 23.31.0.10 23.31.0.13:7403
mapping 23.31.0.20 23.31.0.13:39346
same False
unmapped_socket symmetric true
```

The echo servers are ready before that check:

```text
echo coord udp 5001 ready
echo relay udp 5001 ready
```

The proof ran under `scripts/proof/proof-lock.sh`.
The build is the release profile.

```text
rustc rustc 1.99.1 (58cf8f9c3 2026-10-13)
build profile release
proof_contention port-mapping:orblx-pmap-proof samples 392 contended_samples 0 unknown_samples 0 max_other_orblx_containers 0 max_load1 1.02
```

The lock line uses `contended_samples` and `unknown_samples`.
Both values are 0.

## Cases

N is 5 for every protocol.
Ping is 50 packets. Every run lost 0 packets.
`direct_ms` is none when the path stays on the relay.

| Case | N | Success | Path | First packet (node-c) | Time to direct (node-c) | Loss |
| --- | --- | --- | --- | --- | --- | --- |
| baseline, symmetric to symmetric, UDP 5351 and 1900 dropped | 5 | 5/5 | relay | 421, 423, 478, 489, 550 ms | none | 0/50 |
| symmap to symmetric, `--port-map off` | 5 | 5/5 | relay | 479, 489, 494, 495, 541 ms | none | 0/50 |
| symmap to symmetric, `--port-map auto` (PCP) | 5 | 5/5 | direct | 483, 489, 490, 494, 494 ms | 575, 588, 596, 605, 630 ms | 0/50 |
| `--port-map nat-pmp` | 5 | 5/5 | direct | 476, 487, 487, 553, 555 ms | 617, 619, 628, 653, 655 ms | 0/50 |
| `--port-map upnp` | 5 | 5/5 | direct | 479, 483, 484, 486, 495 ms | 596, 601, 610, 633, 635 ms | 0/50 |

```text
success baseline 5/5 mapped 5/5 disabled 5/5 nat-pmp 5/5 upnp 5/5
proof_ok
```

## Security

The map is for one UDP port. The client requests `DIRECT_QUIC_PORT` (UDP 443).
The lab log shows that port:

```text
The port map is pcp 23.31.0.13:443 lifetime 40.
```

`pcp_request_uses_the_rfc_fields` checks that the PCP packet carries internal port 443.
The proof rejects a grant line that is not port 443.

The lifetime request is capped at 7200 s.
`bound_lifetime` maps 0 and any larger value to 7200.
The CLI rejects a value outside 1 to 7200.
`lifetime_request_is_capped_at_two_hours` checks the cap.
`a_restart_sends_a_pcp_delete_with_the_saved_nonce` asks for 9999 s and the grant is 7200 s.

A crash skips the delete on shutdown.
The nonce is stored in `port-map-nonce`.
The next start sends a delete with that nonce before the new map.
PCP matches the nonce. NAT-PMP matches the internal UDP port.
UPnP deletes the same external port the client requests.
A crash with no restart still expires at the capped lifetime.

The unit test records the packets. The first packet of a restart is lifetime 0 with the saved nonce. The next packet is the new map with the same nonce.

The lab kills the node with SIGKILL, then starts it again:

```text
crash map rules before kill 1
crash map rules after kill 1
crash map rules after restart 1
crash map rules after delete 0
crash_restart orphan_cleared yes
```

One UDP 443 rule remains after the restart. Shutdown removes it.

`--port-map off` sends no probe:

```text
The port map is off.
The port map probe took 0 ms.
The port map probe did not start.
```

## Tailscale

Tailscale describes the same idea. It does not publish lab times for the mapper.
This table compares behavior. It does not invent Tailscale timings.

| Item | Orblx, this lab | Tailscale |
| --- | --- | --- |
| Protocols | PCP, then NAT-PMP, then UPnP IGD | NAT-PMP, PCP, and UPnP on the default gateway. PCP is preferred when NAT-PMP was not seen recently. UPnP is the fallback. |
| Wait for one protocol | 250 ms | `portMapServiceTimeout` is 250 ms |
| Probe when nothing answers | 750 ms, and the relay path does not wait | No single published budget. Each service wait is 250 ms. |
| Requested lifetime | 1–7200 s (this proof used 40 s) | `pmpMapLifetimeSec` and `pcpMapLifetimeSec` are 7200 |
| Renew | Half the granted lifetime | `renewAfter` is half the granted lifetime |
| Delete | Lifetime 0 on clean shutdown. A restart deletes the saved map first. | `pmpMapLifetimeDelete` is 0 |
| Effect on two hard NATs | Direct when one router grants a map. 5/5 for PCP, NAT-PMP, and UPnP. First relay packet about 420–555 ms. Direct packet about 575–655 ms. | A mapping makes one NAT easier for the peer. If mapping and hairpinning both fail, the path stays on a relay. No lab latency is published. |

Primary source for the constants: [net/portmapper/portmapper.go](https://github.com/tailscale/tailscale/blob/main/net/portmapper/portmapper.go) and [net/portmapper/pcp.go](https://github.com/tailscale/tailscale/blob/main/net/portmapper/pcp.go).
The behavior text is from [How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works).

## Limits

- The router is miniupnpd in a container, not a home router.
- The lab has one NAT layer. A second NAT in front of the gateway is not mapped.
- The mapped external port in this lab is UDP 443.
- The punch plan can stay relay-only until the map is granted. The relay packet does not wait for that grant.
