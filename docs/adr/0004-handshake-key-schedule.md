# ADR 0004: Handshake and key schedule

- Status: Proposed
- Language: English ASD-STE100 (Eng Lead rule)
- Date: 2026-10-28
- Owner: C-Key
- Related: [ADR 0001](0001-stack.md), [ADR 0002](0002-frame-hello-quic.md), [ADR 0003](0003-nat-path-state-machine.md)
- Design: https://cursor.com/canvas/store-c49a327e-0259-44d4-8d57-5cb0abf5a922/d79b1e02-bfeb-4dd1-b66a-9be3f302d9ff

## Context

gyeol-quic is the primary stack.
The record protection is QUIC TLS 1.3 mTLS.
Quinn and rustls run that flight.
The leaf is an X.509-SVID from Identity.
ADR 0002 gives Datapath the app frame.
ADR 0002 gives Crypto the peer SPIFFE URI and the ticket check.
This record fixes the handshake phases, the HKDF-SHA256 schedule, and the ticket verify order.
The on-wire ticket layout stays open until the frame freeze.

## Decision

### 1. Locked primitives

Use these primitives.
Do not add a second suite registry.

| Item | Value |
| --- | --- |
| Transport | QUIC TLS 1.3 mTLS through Quinn and rustls |
| Record AEAD | `TLS_AES_128_GCM_SHA256` (0x1301) or `TLS_CHACHA20_POLY1305_SHA256` (0x1303) |
| ECDHE | X25519 (0x001d) |
| SVID signature | Ed25519 (0x0807) |
| KDF | HKDF-SHA256 |
| Ticket integrity | HMAC-SHA256 with `K_ticket` |
| Ticket authority | Ed25519 TicketKey |
| Ticket fingerprint | `SHA-256(ticket_bytes)[0..16]` |

rustls selects the record AEAD.
The crypto crate records the same two suite ids.
The crypto crate does not seal application data.
The crypto crate does not open application data.

### 2. Handshake phases

Quinn owns the UDP socket and the TLS flight.
The crypto crate records the phase for Datapath.

| Phase | Entry | Peer URI | DATA |
| --- | --- | --- | --- |
| Start | `Handshake::client` or `Handshake::server` | Hidden | Reject |
| ServerHello | `select_suite` | Hidden | Reject |
| CertificateVerify | `note_certificate_verified` | Hidden | Reject |
| Finished | `note_finished` | `peer_spiffe_uri` | Reject |
| Bound | `bind_ticket` | `peer_spiffe_uri` | Allowed after the session check |
| Closed | `close` | Hidden | Reject |

`note_certificate_verified` takes the peer leaf.
Identity `extract_spiffe_id` checks the leaf profile.
The profile requires one URI SAN, `clientAuth`, and `serverAuth`.
A bad leaf stops the handshake.
`peer_spiffe_uri` stays hidden until Finished.
`bind_ticket` requires `ticket.subject` to equal that URI.
Datapath calls `authorize_data` before a DATA frame.
The call requires phase Bound, a live `SessionLimit`, the same workload kind, and the frame `ticket_hash`.

### 3. Key schedule

The hash is SHA-256.
Both locked suites use that hash.
The schedule is the TLS 1.3 HKDF-SHA256 schedule (RFC 8446).
There is no PSK.
The early secret uses 32 zero bytes as salt and as IKM.
The handshake secret uses the X25519 shared secret as IKM.
The master secret uses 32 zero bytes as IKM.
Reject an all-zero X25519 shared secret.

| Label | Context | Use |
| --- | --- | --- |
| `derived` | `Hash("")` | Salt for the next extract |
| `c hs traffic` | Hash through ServerHello | Handshake traffic secret |
| `s hs traffic` | Hash through ServerHello | Handshake traffic secret |
| `c ap traffic` | Hash through server Finished | Application traffic secret |
| `s ap traffic` | Hash through server Finished | Application traffic secret |
| `exp master` | Hash through server Finished | Exporter master secret |
| `gyeol policy` | `Hash("")` on the exporter master | Policy secret |
| `exporter` | `Hash(policy context)` | 32-byte policy binder |

`HKDF-Expand-Label` uses the `tls13 ` prefix.
rustls owns the traffic secrets for record protection.
`TrafficSecret` keeps those bytes private.
`TrafficSecret` has no seal function and no open function.
`export_binding` is the only schedule output for Datapath policy.

### 4. Transcript and policy binding

The transcript is SHA-256 over handshake messages in record order.
Do not feed application DATA into the transcript.
`note_finished` freezes further transcript updates.
The policy context is this byte string:

```
suite_id          u16 big-endian
transcript_hash   32 bytes
ticket_hash       16 bytes
uri_len           u16 big-endian
peer_spiffe_uri   uri_len bytes
```

`export_binding` rejects a suite id that differs from the schedule suite.
The binder is not a record key.

### 5. Ticket verify

Identity signs the ticket with the Ed25519 TicketKey.
Identity `verify_ticket` checks that signature, the ticket time, and the deny list.
Crypto checks HMAC-SHA256 and the subject binding.

`K_ticket` is 32 bytes.
`K_ticket` is not the SVID CA key.
The TicketKey public key must differ from the SVID CA public key.
A ring holds one current key.
A ring may also hold one previous key.
The overlap of the two validity windows must be 24 hours or less.
`verify_ticket` tries the current key first.
The key window is inclusive.
The check order is:

1. The key is inside its validity window.
2. The Ed25519 signature, the ticket time, and the deny list pass.
3. `HMAC-SHA256(K_ticket, mac_input(ticket_bytes))` matches the tag.
4. `ticket.subject` equals the peer SPIFFE URI.

The result carries `ticket_hash`.
Compare that value with the frame field before DATA.

`mac_input` returns the identity ticket bytes.
That choice is provisional.
TODO(frame-freeze): replace `mac_input` when Datapath freezes the canonical ticket bytes.
The provisional tag is a separate value.
`ticket_hash` covers the identity ticket bytes.
The hash does not cover the provisional tag.
Do not publish those bytes as the frozen HMAC vector.

### 6. Session lifetime

The hard cap is 2 hours from the first handshake.
A rehandshake does not move that start time.
The SVID cap is 15 minutes for a user, a node, and a coord.
The SVID cap is 5 minutes for an agent.
The caps match Identity `MAX_USER_TTL` and `MAX_AGENT_TTL`.
The rehandshake deadline is the earliest of these times:

- The hard cap.
- The epoch start plus the SVID cap.
- The leaf `not_after` minus 60 seconds.

The 60 second skew matches Identity `MAX_SKEW`.
Call `must_rehandshake` before DATA.
A leaf that is already inside the skew window is due at once.
A new leaf is required for the next epoch.
The workload kind stays the same for the 2 hour connection.
Reject a leaf that is already expired.
Reject a leaf whose remaining life is longer than the SVID cap.

### 7. Ownership

| Work | Owner |
| --- | --- |
| QUIC socket, TLS flight, record AEAD | Datapath through Quinn and rustls |
| App frame and header `ticket_hash` | Datapath |
| SVID issue, leaf profile, Ed25519 ticket signature, deny list | Identity |
| Phase, `peer_spiffe_uri`, HMAC tag, schedule, session cap | Crypto |
| UDP path and Relay | Edge |
| Relay plaintext | Nobody. The Relay forwards ciphertext. The Relay does not terminate mTLS. |

## Consequences

`crates/gyeol-crypto` contains this scaffold.
The crate does not open a UDP socket.
The crate does not replace the Datapath Quinn path.
Full HMAC vectors land after the frame freeze.
A peer must present a new SVID before the rehandshake deadline.
Several handshakes fit inside one 2 hour cap.
rustls remains the only record AEAD.

## Excluded items

The crate does not link to WireGuard, Headscale, or DERP.
The crate does not implement MESH-v0.
The crate does not implement an application AEAD.
The crate does not implement ML-KEM or another post-quantum exchange.
The crate does not implement Noise.
The crate does not implement 0-RTT.
The crate does not implement a cipher agility menu.
The crate does not invent a MAC.

## Interfaces

### Datapath

Call `peer_spiffe_uri` after Finished.
Treat an error as an abort.
Call `verify_ticket` with the peer URI.
Call `bind_ticket` with the proof.
Call `authorize_data` before each DATA frame.
Pass the header `ticket_hash`.
Use `export_binding` when the log needs a policy binder.
Keep the Quinn endpoint in Datapath.

### Identity

Keep `sign_ticket` and `verify_ticket`.
Keep `ticket_hash`.
Crypto calls that verify function.
Crypto calls `extract_spiffe_id` for the leaf.
Issue the TicketKey apart from the SVID CA.

## Open questions

1. Which bytes does HMAC-SHA256 cover after the frame freeze?
2. Does the TICKET frame carry the tag beside the identity ticket, or inside the hashed bytes?
3. ADR 0002 still asks whether one bidirectional stream serves one peer session.
