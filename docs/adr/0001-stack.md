# ADR 0001: The primary stack is gyeol-quic

- Status: Accepted
- Date: 2026-10-28

## Context

gyeol is a low-level overlay network.
The project must record the primary stack before work starts on the data path.
The project must record the primary stack before work starts on identity.
The project must record the primary stack before work starts on the gyeol Relay.
This record stores the primary stack decision.
Later ADR files will record the handshake.
Later ADR files will record NAT traversal.
Later ADR files will record the crypto design.

## Decision

The primary stack is gyeol-quic.
gyeol-quic uses a userspace TUN device.
gyeol-quic uses QUIC on UDP port 443.
gyeol-quic uses short SPIFFE SVIDs.
gyeol-quic uses the gyeol Relay.

## Excluded foundations

The project does not use WireGuard as a foundation.
The project does not use Headscale as a foundation.
The project does not use DERP as a foundation.
The project does not link to WireGuard binaries.
The project does not link to Headscale binaries.
The project does not link to DERP binaries.
The project does not link to WireGuard libraries.
The project does not link to Headscale libraries.
The project does not link to DERP libraries.
The project does not add WireGuard as a dependency.
The project does not add Headscale as a dependency.
The project does not add DERP as a dependency.

## Consequences

Week 1 crates contain only a temporary name function.
Later ADR files will record the procedure that issues an SVID.
For the session code, the planned libraries are Quinn, rustls, and ring.
You can use aws-lc-rs as the crypto backend for rustls.
