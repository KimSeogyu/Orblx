# Feed version 1

The sim harness owns this feed.
The crate is `gyeol-sim`.
`StackFeed::drain` returns one JSON object per string.
The HTTP server sends the same JSON on `GET /events`.
The same handler also serves `GET /v0/events`.
The harness does not open a Unix socket.
The harness does not use `orblx-sim.sock`.

## Envelope

Each object has these fields.

| Field | Value |
| --- | --- |
| `v` | `1` |
| `ts_ms` | Unix time in milliseconds |
| `source` | `identity`, `edge_nat`, `datapath`, or `harness` |
| `level` | `city_breeze`, `agent_jit`, or `radioactive_nat` |
| `difficulty` | `easy`, `medium`, or `hard` |
| `kind` | The event name |
| `session_id` | Hex session id |
| `seq` | The feed sequence number |
| `ticket_hash` | 32 hex characters when a ticket exists |
| `path` | `connector`, `agent`, or `nat_relay` |

`ticket_hash` is absent when the event has no ticket.
`path` names the active level path.

A connector session id is 16 hex characters.
An agent session id is 16 hex characters.
Those 16 characters are one `u64` in big-endian hex.
An Allocate or Direct session id is the `PathId` hex value.
That value is 32 hex characters.
A Relay session id is `RelaySessionId`.
That value is 32 hex characters.
`path.direct` uses the `PathId`.
`path.relay` uses the `RelaySessionId`.

## Identity kinds

The identity kinds are `svid.issued`, `agent.spawned`, `ticket.verified`, `jit.allow`, `jit.deny`, `svid.expired`, `svid.revoked`, and `session.dropped`.
`session.dropped` includes `within_s`.
`within_s` is the wall-clock seconds from the start of revoke to the drop.
`within_s` is at most 60.

## EdgeNAT kinds

Radioactive NAT UDP block calls `gyeol_edge::run_nat_smash`.
The call uses `NatDifficulty::Hard`, `NatLevel::RadioactiveNat`, and `NatInjectMode::UdpBlock`.
`NatEventLog::drain` returns the JSON lines.
The harness does not build a second NAT state machine.
Stick and upgrade stay deferred.

The UDP block order is:

1. `nat.inject`
2. `path.allocate`
3. `path.direct` with `ok` false
4. `nat.probe`
5. `path.down`
6. `path.switch`
7. `relay.hop`
8. `path.relay` with `hop` `tcp`
9. `path.up` with `path` `relay`

`path.direct` with `ok` false is before `path.switch`.
`path.allocate` uses overlay address `10.8.0.1`.
`session_id` is the PathId hex before Relay attaches.
`session_id` is the RelaySessionId hex after Relay attaches.

## Datapath kinds

The datapath kinds are `quic_hello`, `frame_tx`, `frame_rx`, `connector_https`, `session_up`, `session_down`, and `path_switch`.
`quic_hello` includes `peer_uri`.
`frame_tx` and `frame_rx` include `frame_type`, `flags`, and `ipv4_len`.
`connector_https` includes `host`, `status`, and `bytes`.
The host is `app-a.orblx.test` or `app-b.orblx.test`.
`session_up` and `session_down` include `reason`.
`path_switch` includes `from_path_id` and `to_path_id`.

## Adapters

The harness calls `gyeol-identity` to issue an SVID and a ticket.
The harness calls `allow_agent_jit` for application A and application B.
The harness calls `TrustBundle::authenticate_leaf` for expiry and for revoke.
The harness calls `DenySet::apply_json` for revoke.
The harness calls `Frame::encode` and `Frame::decode` for packet events.
The harness calls `PathMachine::start_allocate` and `gather_reflexive` for Allocate.
The harness does not call `establish_direct` when UDP is blocked.
`direct_is_up` stays false.
The harness then encodes one Relay datagram and one TCP record.
The harness appends session start, session end, and session deny on the `gyeol-audit` chain.

## Run

```bash
cargo run -p gyeol-sim
```

Open `http://127.0.0.1:8787`.
Select Easy, Medium, or Hard.
Press Revoke, UDP block, or Spawn agent.
The event log shows the JSON kinds.
The terminal prints each new line.
