# ADR 0003: NAT path state machine

- Status: Proposed
- Date: 2026-10-28
- Owner: N-Edge

## Context

gyeol must connect through CGNAT.
gyeol must connect through symmetric NAT.
gyeol must connect through UDP-blocked egress.
gyeol must connect through flaky home and cloud paths.
The project does not use Tailscale DERP as a foundation.
The project does not use WireGuard as a foundation.
The project does not use Headscale as a foundation.
N-Edge owns discovery.
N-Edge owns STUN.
N-Edge owns hole punching.
N-Edge owns the gyeol Relay.
N-Edge owns path selection.
D-Path consumes opaque path_id values.
C-Key owns the handshake and AEAD.
The Relay must forward ciphertext only.

## Decision

The NAT path uses a four-state machine.

### Allocate

The client registers with the Coordinator.
The client receives an overlay IP.
The client gathers a reflexive address with own STUN on the Relay node.
The peers exchange signed endpoint candidates on the Coordinator control channel.

### Direct

The peers run a coordinated UDP hole punch.
The punch uses ICE-like candidates.
The punch does not require a full WebRTC stack.
On success, the peers run QUIC on UDP port 443.
The Direct attempt fails after 3 seconds.

### Relay

The peers attach through the gyeol Relay binary.
The Relay routes by session_id only.
The payload stays end-to-end encrypted.
The preferred path is UDP port 443.
If UDP port 443 is blocked, the path uses TCP port 443.
Week 6 decides the TCP framing with D-Path.
Week 6 chooses QUIC-style fallback or TLS-wrapped frames.

### Stick and upgrade

While a session uses Relay, N-Edge retries Direct in the background.
On Direct success, the session migrates with QUIC connection migration.
N-Edge emits path metrics.
path_id semantics stay stable for D-Path.

### Path scheduling

The scheduler optimizes for agent RPC p99.
The scheduler does not optimize for mean RTT alone.
Probes detect blackholes.
A blackhole causes PathDown and failover inside the agreed budget.
Bulk TUN traffic prefers sticky Direct.
Short agent RPCs may hedge with a parallel Relay attempt when Direct is degraded.

### Relay threat model

The Relay is honest-but-curious.
The Relay may be compromised.
The Relay may observe metadata.
The Relay must not read plaintext.
The Relay must not hold session keys.
C-Key establishes and rekeys sessions.
The Relay must not mint sessions.

## Consequences

Week 5 exit requires same-NAT direct QUIC PathUp.
Week 6 exit requires Relay v0 on UDP 443 and TCP 443 across three lab NAT types.
Kill K1 applies when both UDP 443 and TCP 443 NAT traversal fail.
Week 12 N-Edge DoD requires at least 95 percent connect success on symmetric or restricted-cone NAT through Direct or Relay.
This ADR does not add feature code.
This ADR is the Week 1 N-Edge documentation deliverable.

## Excluded items

The project does not use WireGuard.
The project does not use Tailscale DERP protocol or map.
The project does not use a plaintext Relay.
The project does not build a global DERP fleet.
The project does not use peer-relay as the primary path ladder step.
The project does not add enterprise GTM copy.

## Interfaces

### D-Path

PathId is opaque bytes allocated by N-Edge.
N-Edge emits PathUp with path_id and kind direct or relay.
N-Edge emits PathDown with path_id and reason.
N-Edge emits PathMetrics with path_id, rtt_ms, loss, and kind.
D-Path owns send and recv on the active path_id.

### C-Key

On Direct, N-Edge provides the UDP path.
On Direct, C-Key runs QUIC TLS 1.3 mTLS with SVID.
On Relay, C-Key establishes and rekeys the Relay session.
On Relay, the wire carries ciphertext and a routing header with session_id only.

## Open questions

1. Who freezes the Coordinator candidate blob and the sign or verify hooks?
2. Which VPS region hosts Relay v0?
3. Is a second Relay region in Week 12 scope?
4. Must Stick and upgrade be live in the Week 12 demo?
5. What is the numeric agent RPC p99 target in milliseconds?
6. For Week 6 TCP, do N-Edge and D-Path choose QUIC-style fallback or TLS-wrapped frames?

## Week 6 decision

Question 6 is decided.
The primary TCP/443 framing is QUIC-style.
A TCP record is a 16-bit big-endian length and one Relay datagram.
The datagram header is version, kind, and a 16-byte session id.
The DATA payload is one QUIC packet.
The Relay copies that payload.
The Relay does not parse the QUIC packet.
The Relay does not terminate QUIC.
The alternate is a Noise frame or a TLS-wrapped frame in the same payload slot.
Week 6 does not implement that alternate.
Week 6 leaves stick and upgrade deferred.
The path does not retry Direct while Relay is up.
The path does not migrate the QUIC connection in that build.
Week 13 enables stick.
The method is reconnect.
See [docs/w13-stick-upgrade.md](../w13-stick-upgrade.md).
