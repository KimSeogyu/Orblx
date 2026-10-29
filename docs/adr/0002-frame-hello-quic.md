# ADR-0002: Frame layout and hello-quic path

- Status: Accepted
- Language: English ASD-STE100 (Eng Lead rule)
- Date: 2026-10-28 (Asia/Seoul)
- Deciders: Datapath (frame freeze authority at W4), Crypto (ticket/SVID), Eng Lead
- Repo: https://github.com/KimSeogyu/orblx
- Design: https://cursor.com/canvas/store-c49a327e-0259-44d4-8d57-5cb0abf5a922/0cab346c-7130-490c-8f0a-156b863acdaa

## Context

orblx primary stack is **orblx-quic**: userspace TUN + QUIC (UDP/443) + SPIFFE SVID mTLS.
WireGuard / Headscale / DERP are forbidden dependencies.
QUIC/TLS provides record crypto. App-layer double AEAD is deferred (Variant A only if W6 kills QUIC).

Datapath owns the TUN loop, the app frame parser, and overlay routing.
W4 freezes the on-wire header bytes. This ADR is that contract.

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

1. **W1**: this ADR + stub `orblx-datapath` types (`Frame`, `FrameType`, encode/decode unit tests with fixed vectors).
2. **W2** (blocked on Identity): accept SVID-backed Quinn endpoint config from Crypto/Identity crates (trait, no keys in Datapath).
3. **W3 hello-quic**:
   - Process A: open TUN, read IPv4 → wrap DATA frame → write QUIC bi-stream.
   - Process B (or loopback): read stream → parse frame → write TUN.
   - Escape: `ping` to overlay IP succeeds on Linux loopback / two namespaces.

W3 code kept this status at Proposed.
W4 accepts this ADR and freezes the on-wire header bytes.

No GSO/GRO in W1–W3. No kernel module.

### 5. Explicit non-goals (this ADR)

- MESH-v0 / MSH0 UDP AEAD headers (superseded — discard).
- App ChaCha seal/open on every packet (deferred).
- Cryptokey routing / WG allowed-IPs table.
- IPv6 overlay, L2 bridge.

## Consequences

- Frame byte freeze slips only with full-team agree after W4.
- Crypto’s earlier SessionAead-over-UDP proposal applies to **Variant A (orblx-noise)** only, not primary.
- Replay: Datapath keeps sliding window on `(session_id, seq)` as defense-in-depth; QUIC already numbers records.

## hello-quic W1 checklist

- [ ] `docs/adr/0002-frame-hello-quic.md` merged (this doc)
- [ ] `orblx-datapath`: `Frame::{encode,decode}` + golden tests
- [ ] No `wireguard*` / `boringtun` / `defguard` deps in workspace
- [ ] ShipPlatform CI green on stub

## Accepted note (W4)

W4 accepts this ADR.

W4 freezes the on-wire frame header. The header is 30 bytes. Decision 2 is the layout.
W4 freezes the `ticket_hash` definition in that header.
`ticket_hash` is the first 16 bytes of SHA-256 over the raw ticket bytes.
`orblx_identity::ticket_hash` returns that value.
The frozen value for `crates/orblx-identity/fixtures/ticket-valid.bin` is `44f62776f5ddb2c2a259539c36db2cc4`.

W4 does not freeze the CTRL payload layout.
W4 does not freeze the TICKET payload layout.
Crypto and Identity own those layouts. Those layouts stay open.
The CTRL golden vector and the TICKET golden vector use a one-byte opaque payload.
That byte is not a payload schema.

W4 does not add app-layer AEAD.
W4 does not change the header layout.

## Frozen vectors

The files in `crates/orblx-datapath/testdata/` are the frozen bytes.
`Frame::encode` must emit these bytes.
`Frame::decode` must accept these bytes and return the same frame.

| Vector | File | What is frozen |
|--------|------|----------------|
| DATA header plus payload `ping` | `crates/orblx-datapath/testdata/frame-data-ping.hex` | 30-byte header and payload |
| Frame type DATA | `crates/orblx-datapath/testdata/frame-type-data.hex` | type nibble 1, payload `01` |
| Frame type CTRL | `crates/orblx-datapath/testdata/frame-type-ctrl.hex` | type nibble 2, payload `02` |
| Frame type TICKET | `crates/orblx-datapath/testdata/frame-type-ticket.hex` | type nibble 3, payload `03` |
| `FLAG_REKEY_REQ` | `crates/orblx-datapath/testdata/frame-flag-rekey-req.hex` | flag byte `01` |
| `FLAG_EOS` | `crates/orblx-datapath/testdata/frame-flag-eos.hex` | flag byte `02` |
| DATA header with fixture `ticket_hash` | `crates/orblx-datapath/testdata/frame-data-ticket-hash.hex` | header bytes 14..29 |
| Fixture `ticket_hash` | `crates/orblx-datapath/testdata/ticket-valid-hash.hex` | 16-byte prefix |

### DATA header plus payload `ping`

`ver` is 1. `type` is DATA. `flags` is `FLAG_REKEY_REQ | FLAG_EOS` (`0x03`).
`session_id` is `0x0000002a`. `seq` is 7.
`ticket_hash` is `000102030405060708090a0b0c0d0e0f`.
The payload is `ping`.

```text
11030000002a0000000000000007000102030405060708090a0b0c0d0e0f70696e67
```

### Frame type nibbles

Each vector has flags `00`, `session_id` 0, `seq` 0, and `ticket_hash` of 16 zero bytes.
The last byte is the opaque payload. It is not a CTRL schema. It is not a TICKET schema.

```text
DATA:   11000000000000000000000000000000000000000000000000000000000001
CTRL:   12000000000000000000000000000000000000000000000000000000000002
TICKET: 13000000000000000000000000000000000000000000000000000000000003
```

### Flag bits

Each vector is a 30-byte DATA header. The payload is empty.
`FLAG_REKEY_REQ` is bit 0 (`0x01`). `FLAG_EOS` is bit 1 (`0x02`).

```text
FLAG_REKEY_REQ: 110100000000000000000000000000000000000000000000000000000000
FLAG_EOS:       110200000000000000000000000000000000000000000000000000000000
```

### `ticket_hash`

`crates/orblx-identity/fixtures/ticket-valid.bin` hashes to:

```text
44f62776f5ddb2c2a259539c36db2cc4
```

The DATA frame below places that value in header bytes 14..29.
`session_id` is 1. `seq` is 1. The payload is `ok`.

```text
110000000001000000000000000144f62776f5ddb2c2a259539c36db2cc46f6b
```

## Open questions

These questions stay open after the W4 accept.

1. CTRL payload layout and TICKET payload layout. Crypto and Identity own these layouts. Datapath carries each payload as an opaque byte string.
2. Multiplex: one QUIC stream per TUN peer or many streams. The proposal is one bidirectional stream per peer session for the spike.
3. `session_id` allocation. The proposal is a local random value for W3. Coordinator assignment can come later.
