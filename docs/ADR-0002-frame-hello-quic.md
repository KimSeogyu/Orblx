# ADR-0002: Frame layout and hello-quic path

- Status: Proposed
- Language: English ASD-STE100 (Eng Lead rule)
- Date: 2026-10-28 (Asia/Seoul)
- Deciders: Datapath (frame freeze authority at W4), Crypto (ticket/SVID), Eng Lead
- Repo: https://github.com/KimSeogyu/gyeol
- Design: https://cursor.com/canvas/store-c49a327e-0259-44d4-8d57-5cb0abf5a922/0cab346c-7130-490c-8f0a-156b863acdaa

## Context

gyeol primary stack is **gyeol-quic**: userspace TUN + QUIC (UDP/443) + SPIFFE SVID mTLS.
WireGuard / Headscale / DERP are forbidden dependencies.
QUIC/TLS provides record crypto. App-layer double AEAD is deferred (Variant A only if W6 kills QUIC).

Datapath owns: TUN loop, **app frame parser**, overlay routing.
W4 freezes on-wire bytes; until then this ADR is the working contract.

## Decision

### 1. Transport

- Quinn QUIC over UDP/443 (primary).
- Relay fallback owned by EdgeNAT; Datapath consumes a `Path` handle (opaque), not DERP semantics.
- No Noise/WG UDP framing in primary.

### 2. App frame on QUIC stream (version 1)

Big-endian. Header is logical AAD for any future optional app AEAD; spike uses QUIC crypto only.

| Field | Bits/Bytes | Notes |
|-------|------------|-------|
| ver | 4 bit | = 1 |
| type | 4 bit | DATA=1, CTRL=2, TICKET=3 |
| flags | 8 bit | bit0=rekey_req, bit1=EOS |
| session_id | 32 bit | local debug/obs handle |
| seq | 64 bit | per-direction frame seq (replay assist) |
| ticket_hash | 128 bit | capability ticket fingerprint (recv ACL) |
| payload | variable | IPv4 packet plaintext (DATA); CTRL/TICKET bodies per Crypto/Identity |

Packed header size before payload: **1 + 1 + 4 + 8 + 16 = 30 bytes**  
(ver|type share first byte; flags second byte).

```
byte0:  ver:4 | type:4
byte1:  flags
byte2..5:   session_id (u32 BE)
byte6..13:  seq (u64 BE)
byte14..29: ticket_hash (16 B)
byte30..:   payload
```

### 3. CRYPTO boundary (Datapath does NOT own)

- Confidentiality/integrity: **QUIC/rustls only** (Primary). App SessionAead withdrawn → Variant A / W6.
- After handshake: call Crypto `peer_spiffe_uri()` and bind `ticket.subject` before any DATA.
- Capability ticket mint/verify + W4 HMAC vectors (Identity + Crypto).
- Header keeps `ticket_hash` (128-bit). Frame fields are **not** a custom AEAD AAD contract (QUIC protects the stream).
- Relays: never terminate mTLS / never open app crypto.
- Crypto ADR: https://cursor.com/canvas/store-c49a327e-0259-44d4-8d57-5cb0abf5a922/d79b1e02-bfeb-4dd1-b66a-9be3f302d9ff

### 4. TUN path (hello-quic plan)

W1–W3 path:

1. **W1**: this ADR + stub `gyeol-datapath` types (`Frame`, `FrameType`, encode/decode unit tests with fixed vectors).
2. **W2** (blocked on Identity): accept SVID-backed Quinn endpoint config from Crypto/Identity crates (trait, no keys in Datapath).
3. **W3 hello-quic**:
   - Process A: open TUN, read IPv4 → wrap DATA frame → write QUIC bi-stream.
   - Process B (or loopback): read stream → parse frame → write TUN.
   - Escape: `ping` to overlay IP succeeds on Linux loopback / two namespaces.

No GSO/GRO in W1–W3. No kernel module.

### 5. Explicit non-goals (this ADR)

- MESH-v0 / MSH0 UDP AEAD headers (superseded — discard).
- App ChaCha seal/open on every packet (deferred).
- Cryptokey routing / WG allowed-IPs table.
- IPv6 overlay, L2 bridge.

## Consequences

- Frame byte freeze slips only with full-team agree after W4.
- Crypto’s earlier SessionAead-over-UDP proposal applies to **Variant A (gyeol-noise)** only, not primary.
- Replay: Datapath keeps sliding window on `(session_id, seq)` as defense-in-depth; QUIC already numbers records.

## hello-quic W1 checklist

- [ ] `docs/ADR-0002-frame-hello-quic.md` merged (this doc)
- [ ] `gyeol-datapath`: `Frame::{encode,decode}` + golden tests
- [ ] No `wireguard*` / `boringtun` / `defguard` deps in workspace
- [ ] ShipPlatform CI green on stub

## Open questions (need Eng Lead / peers before W4 freeze)

1. CTRL/TICKET payload layouts — Crypto+Identity own; Datapath needs length-prefixed blob OK?
2. Multiplex: one QUIC stream per TUN peer vs many — propose **one bidi stream per peer session** for spike.
3. `session_id` allocation — local only or Coordinator-assigned? Propose local random for W3, Coordinator later.
