# orblx

Former name: gyeol

orblx is a low-level overlay network.
The primary stack name is orblx-quic.
orblx-quic uses a userspace TUN device.
orblx-quic uses QUIC on UDP port 443.
orblx-quic uses short SPIFFE SVIDs.
orblx-quic uses the orblx Relay.

This repository does not include WireGuard.
This repository does not include Headscale.
This repository does not include DERP.
The build does not link to WireGuard binaries.
The build does not link to WireGuard libraries.
The build does not link to Headscale binaries.
The build does not link to Headscale libraries.
The build does not link to DERP binaries.
The build does not link to DERP libraries.
Read the decision record in [docs/adr/0001-stack.md](docs/adr/0001-stack.md).

Week 1 contains a Rust workspace.
The workspace compiles.
Week 1 does not contain handshake code.
Week 1 does not contain NAT traversal code.
Week 1 does not read the TUN device.
Week 1 does not write to the TUN device.
Week 1 does not contain QUIC session code.
Week 1 does not issue identities.

## Crates

| Path | Week 1 contents |
| --- | --- |
| `crates/orblx-datapath` | Temporary name function |
| `crates/orblx-crypto` | Temporary name function |
| `crates/orblx-edge` | Temporary name function |
| `crates/orblx-identity` | Temporary name function |
| `crates/orblx-coord` | Temporary name function |
| `crates/orblx-cli` | `orblx` command |

The `orblx` command prints a hello line.
The `orblx` command prints the version when you use `--version`.
The `orblx` command prints the version when you use `-V`.

The data path uses Quinn, rustls, and ring.
You can use aws-lc-rs as the crypto backend for rustls.
Read the comment in the workspace `Cargo.toml`.

## hello-quic

Week 3 adds the hello-quic path.
The path reads an IPv4 packet.
The path wraps the packet in one ADR-0002 DATA frame.
The path writes the frame on one QUIC bidirectional stream.
The path checks the peer leaf with `orblx-identity`.
The record in [docs/adr/0002-frame-hello-quic.md](docs/adr/0002-frame-hello-quic.md) stays Proposed.

Run the server:

```bash
cargo run -p orblx-cli -- hello-quic server \
  --cert server.pem --key server-key.pem \
  --bundle trust-bundle.pem --ticket ticket.bin \
  --tun-address 10.8.0.1
```

Run the client:

```bash
cargo run -p orblx-cli -- hello-quic client \
  --cert client.pem --key client-key.pem \
  --bundle trust-bundle.pem --ticket ticket.bin \
  --connect 127.0.0.1:443 \
  --tun-address 10.8.0.2
```

The default UDP port is 443.
The TUN device needs CAP_NET_ADMIN on Linux.
The tests do not open a TUN device.
The tests use an in-memory packet path.

## Edge path

`orblx-edge` gathers one reflexive address with in-tree STUN.
The path machine starts in Allocate.
Allocate stores one unsigned candidate.
ADR 0003 leaves the Coordinator candidate owner open.
Direct sends hole-punch datagrams.
Direct then proves hello-quic on the same UDP socket.
`direct_is_up` is true after that proof.
The Direct budget is 3 seconds.
The QUIC policy port is UDP 443.
When Direct is down, the peers attach to the orblx Relay.
The Relay routes by session id only.
The payload stays end-to-end encrypted.
UDP port 443 is the preferred Relay socket.
When UDP is blocked, the path uses TCP port 443.
TCP uses a QUIC-style length prefix.
The prefix is a 16-bit length and one Relay datagram.
The datagram payload is one QUIC packet.
Stick and upgrade is in [Stick and upgrade](#stick-and-upgrade).

Run the in-process same-NAT lab:

```bash
cargo run -p orblx-cli -- edge-smoke
```

The lab uses a local STUN server.
The lab uses a userspace UDP NAT.
The two peers share the NAT address.
The punch uses the host candidates.
The command tries to bind the QUIC server on UDP port 443.
When that bind is not permitted, the server uses an ephemeral port.

Run the same lab on UDP port 443 when the process can bind that port:

```bash
cargo run -p orblx-cli -- edge-smoke --bind 127.0.0.1:443
```

[`scripts/edge-smoke.sh`](scripts/edge-smoke.sh) runs the userspace lab.
The script runs the UDP 443 lab when root is available.
The script runs a netns source-NAT lab when `ip` and `iptables` are present.
The netns lab puts two peers behind one MASQUERADE NAT.
The QUIC server binds UDP port 443.

Gather against a STUN server:

```bash
cargo run -p orblx-cli -- stun --server 127.0.0.1:3478
```

Answer Binding requests in the lab:

```bash
cargo run -p orblx-cli -- stun-serve --listen 127.0.0.1:3478
```

## Stick and upgrade

While the path is on the Relay, the path stays on the Relay.
The path retries Direct on a 1 second interval.
A failed retry leaves the path on the Relay.
A successful retry opens a new hello-quic session on the direct socket.
The process does not restart.
The method is reconnect.
The details and the lab results are in [docs/w13-stick-upgrade.md](docs/w13-stick-upgrade.md).

```bash
cargo run -p orblx-cli -- stick-upgrade
```

## Relay

Run the Relay on UDP port 443 and TCP port 443:

```bash
cargo run -p orblx-cli -- relay --udp 0.0.0.0:443 --tcp 0.0.0.0:443
```

The Relay does not mint a session id.
Give the same session id to both peers.
The peers prove QUIC through the Relay.

```bash
cargo run -p orblx-cli -- relay-peer \
  --role server \
  --bind 0.0.0.0:0 \
  --stun 127.0.0.1:3478 \
  --session SESSION_HEX \
  --relay 127.0.0.1:443 \
  --transport auto \
  --cert server.pem --key server.key \
  --bundle bundle.pem --ticket ticket.bin
```

`--transport auto` tries UDP and then TCP.
`--transport tcp` uses TCP only.

Run the in-process labs:

```bash
cargo run -p orblx-cli -- relay-smoke udp
cargo run -p orblx-cli -- relay-smoke tcp
```

[`scripts/edge-smoke.sh`](scripts/edge-smoke.sh) runs the Direct labs and the Relay labs.
The userspace Relay labs need no extra privileges.
The netns Relay labs need root, iproute2, and iptables.

## Connector hub

The product name is Orblx.
The command name is orblx.
Week 9 adds the connector hub-spoke path.
The path carries HTTPS for two apps.
The apps are `app-a.orblx.test` and `app-b.orblx.test`.
The overlay addresses are `10.8.0.10` and `10.8.0.11`.
The path uses one QUIC bidirectional stream.
The stream carries ADR-0002 DATA frames.
Each DATA payload is one IPv4 TCP segment.
The spoke reads the TLS server name.
The hub forwards the TCP bytes to the matching app.
The build does not link to WireGuard.
The build does not link to Headscale.
The build does not link to DERP.

Run the userspace proof.
The proof does not open a TUN device.

```bash
cargo run -p orblx-cli -- connector smoke
```

The command prints status 200 for both apps.
The command prints `mesh_to` and `mesh_from` counts above zero.
The client dials the spoke ingress.
The client does not dial the app listeners.

Read the lab commands in [docs/connector-hub.md](docs/connector-hub.md).
The document has the curl commands.
The document has the two-process commands.
The document has the TUN commands for a browser.
The TUN device needs CAP_NET_ADMIN on Linux.
When the TUN device is not available, use `connector smoke`.

## Session audit

Week 10 adds a session audit hash chain.
The crate is `crates/orblx-audit`.
The chain records session start, session end, and session deny.
Each record stores the previous SHA-256 hash.
The hash covers the previous hash and the event bytes.
The Relay session id is `RelaySessionId`.
The frame session id is the datapath frame `session_id`.
The peer is a SPIFFE ID from `orblx-identity`.
The ticket hash is `orblx_identity::ticket_hash`.

Export one deny and one successful session:

```bash
cargo run -p orblx-cli -- audit demo --out chain.jsonl
```

Check the file:

```bash
cargo run -p orblx-cli -- audit verify --file chain.jsonl
```

The check reads the chain file.
The check does not use the data path.
A valid file prints `ok` and the three counters.
Read the byte layout in [docs/session-audit.md](docs/session-audit.md).
[`scripts/audit-smoke.sh`](scripts/audit-smoke.sh) runs the same check.

## Completion criteria for the 12-week work

The 12-week work is complete when all of these statements are true:

- The build does not link to a WireGuard binary.
- The build does not link to a WireGuard library.
- The build does not link to a Headscale binary.
- The build does not link to a Headscale library.
- The build does not link to a DERP binary.
- The build does not link to a DERP library.
- A person uses OIDC to get an SVID.
- The same person then sends a ping on the overlay network.
- The same person then opens two internal HTTPS applications.
- An AI agent can open application A.
- The AI agent that can open application A cannot open application B.
- The system writes a log record when the system denies application B.
- On a symmetric NAT, a direct session is valid.
- On a symmetric NAT, a session through the orblx Relay is valid.
- When an SVID expires, new packets stop within 60 seconds.
- When a ticket expires, new packets stop within 60 seconds.
- When the system revokes an SVID, new packets stop within 60 seconds.
- When the system revokes a ticket, new packets stop within 60 seconds.
- The repository contains one demo command.
- The repository contains a README in English.
- On a laptop, the local TUN round-trip rate is at least 100 Mbps.
- The system can export a short hash chain for session events.

The TUN measurement record is [docs/w12-tun-bench.md](docs/w12-tun-bench.md).
The measured rate is 8091.299206 Mbps.
The result is pass.
The kill or go packet is [docs/w12-kill-go.md](docs/w12-kill-go.md).

## Build and test

Install a stable Rust toolchain.
Install rustfmt.
Install clippy.
The code uses Rust edition 2021.

Check the format:

```bash
cargo fmt --all -- --check
```

Run Clippy:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

Run the tests:

```bash
cargo test --workspace
```

Measure the local TUN round trip:

```bash
scripts/tun-bench.sh
```

The script prints the measured rate.
The script exits 0 when the host has no TUN device.
Read the measured result in [docs/w12-tun-bench.md](docs/w12-tun-bench.md).

Start the command:

```bash
cargo run -p orblx-cli
```

Show the version:

```bash
cargo run -p orblx-cli -- --version
```

GitHub Actions runs the format check, Clippy, and the tests.
GitHub Actions runs this workflow on each pull request.
GitHub Actions runs this workflow on each push to the main branch.

## Play

The play page is a character scene.
The scene reads StackFeed JSON.
`GET /events` sends that JSON.
A feed event moves a character, a path, or both.
The scene does not play a canned story.
The cast is the human session, the agent SVID, application A, application B, the Direct path, and the Relay path.
Sprite pose uses `up`, `degraded`, `down`, `revoked`, `allow`, and `deny` from feed events.
Mint, ticket, break, relay, allow, deny, and revoke motes use the feed kind for that event.
Click a character or Path to open the inspector.
The poke box is Revoke, UDP block, and Spawn agent.
A poke uses the same board.
One level plays for about 35 seconds.
The progress bar counts feed events in that run.
Soft win and soft loss use the character pose.
Next Level starts the next difficulty.
Read the scene in [docs/w16-char-fx.md](docs/w16-char-fx.md).

One command:

```bash
export ORBLX_GOOGLE_CLIENT_ID=949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com
export ORBLX_GOOGLE_CLIENT_SECRET=
cargo run -p orblx-sim
```

Put the client secret in `ORBLX_GOOGLE_CLIENT_SECRET`.
Open `http://127.0.0.1:8787`.
`http://localhost:8787` is the other registered origin.
Read the sign-in steps in [docs/w17-google-oidc.md](docs/w17-google-oidc.md).

City Breeze:

1. Click Play City Breeze.
2. The browser opens Google sign-in.
3. Complete the Google consent.
4. The human receives the SVID and the ticket.
5. The Direct path meets `app-a.orblx.test` and `app-b.orblx.test`.
6. Each application returns status 200.

Agent JIT:

1. Click Play Agent JIT.
2. The agent allows application A.
3. The agent denies application B.

Radioactive NAT and the UDP poke:

1. Click Play Radioactive NAT or click UDP block.
2. The Direct character shows the failed Direct path.
3. The Relay character shows the TCP Relay.
4. UDP block leaves the Relay path up.

The engineering panels stay hidden.
Click Engineering view to open them.
Read the character scene in [docs/w16-char-fx.md](docs/w16-char-fx.md).
Read the level machine in [docs/w15-demo-ui.md](docs/w15-demo-ui.md).

City Breeze, Agent JIT, and Radioactive NAT each use a different board picture.
The picture changes from the feed `level` field.

## Demo

[`scripts/demo.sh`](scripts/demo.sh) checks the live harness.
The script starts the game server.
The default path checks the Google authorize redirect.
The script posts Revoke, Medium, Spawn agent, Hard, and UDP block.
`ORBLX_OIDC_MODE=mock` signs in at the local IdP for City Breeze.
Each action runs the live level machine.
The script reads the event kinds from the harness response.
The script checks that the default page is the game.
The script checks that the game reads the feed.
The script rejects a canned keyframe animation.
A pass prints `demo pass`.
The script needs `cargo`, `curl`, and `python3`.

Run the demo:

```bash
./scripts/demo.sh
```

The default address is `http://127.0.0.1:8787`.
Google sign-in uses that address or `localhost:8787`.

```bash
ORBLX_OIDC_MODE=mock ORBLX_DEMO_ADDR=127.0.0.1:8790 ./scripts/demo.sh
```

## Browser sign-in

City Breeze uses Google authorization-code OIDC.
The play path is [Play](#play).
The issuer is `https://accounts.google.com`.
Set `ORBLX_GOOGLE_CLIENT_ID` and `ORBLX_GOOGLE_CLIENT_SECRET`.
The public client id is `949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com`.
The redirect URI is `http://127.0.0.1:8787/oidc/callback`.
`http://localhost:8787/oidc/callback` is the other registered redirect.
The harness reads `OidcMode::from_env`.
An absent mode selects Google.
The harness does not open the mock IdP on that path.

Start the game:

```bash
export ORBLX_GOOGLE_CLIENT_ID=949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com
export ORBLX_GOOGLE_CLIENT_SECRET=
cargo run -p orblx-sim
```

Open `http://127.0.0.1:8787`.

Click Play City Breeze.
The browser opens the Google authorization page.
Google returns the browser to `/oidc/callback`.
The callback posts the token request.
The callback checks the ID token with `IssueGate`.
The callback issues the human SVID.
The harness verifies the human ticket.
The harness opens `app-a.orblx.test` and `app-b.orblx.test`.
Each application returns status 200.
The browser returns to the harness page.
The SVID state is `up`.
The QUIC path state is `up`.

`ORBLX_OIDC_MODE=mock` selects the local IdP.
Read that path in [docs/w14-oidc-ui.md](docs/w14-oidc-ui.md).
Read the Google checks in [docs/w17-google-oidc.md](docs/w17-google-oidc.md).

`./scripts/demo.sh` checks the Google authorize redirect.
The script uses `curl`.
A pass prints `demo pass`.

## Sim harness

The sim harness crate is `orblx-sim`.
The harness runs three levels.
The levels are City Breeze, Agent JIT, and Radioactive NAT.
The default page is the character scene in [Play](#play).
The engineering view shows peers, packets, and session panels.
The event log shows feed JSON from those runs.
UDP block calls `orblx_edge::run_nat_smash`.
Characters and paths move from feed events.
The scene does not play a canned animation.
Read the feed fields in [docs/w11-feed-v1.md](docs/w11-feed-v1.md).
Read the character scene in [docs/w16-char-fx.md](docs/w16-char-fx.md).
Read the level machine in [docs/w15-demo-ui.md](docs/w15-demo-ui.md).
Read the run steps in [docs/demo-sim.md](docs/demo-sim.md).

Run the harness:

```bash
cargo run -p orblx-sim
```

Open `http://127.0.0.1:8787`.

The event log writes each harness line when the action starts.
The log then writes the identity lines.
The log then writes the edge NAT lines.
The log then writes the datapath lines.
The lists below use that order.

Google sign-in uses `127.0.0.1:8787` or `localhost:8787`.
`ORBLX_OIDC_MODE=mock` can use another local address:

```bash
ORBLX_OIDC_MODE=mock cargo run -p orblx-sim -- --listen 127.0.0.1:8790
```

### Easy — City Breeze

Click Play City Breeze.
City Breeze opens Google sign-in.
The callback runs City Breeze.
The event kinds are, in order:

1. `difficulty_selected`
2. `svid.issued`
3. `ticket.verified`
4. `quic_hello`
5. `frame_tx`
6. `frame_rx`
7. `frame_tx`
8. `connector_https` for `app-a.orblx.test` with status 200
9. `frame_tx`
10. `connector_https` for `app-b.orblx.test` with status 200
11. `session_up`

Each City Breeze step has status `pass`.
The SVID state is `up`.
The QUIC path state is `up`.

Press Revoke.
The event kinds are, in order:

1. `smash_revoke`
2. `svid.revoked`
3. `session.dropped`
4. `session_down`

`session.dropped` includes `within_s`.
`within_s` is at most 60.
The SVID state is `revoked`.
The QUIC path state is `down`.

### Medium — Agent JIT

Click Play Agent JIT.
Agent JIT runs on the board.
The event kinds are, in order:

1. `difficulty_selected`
2. `agent.spawned`
3. `ticket.verified`
4. `jit.allow` for `app-a.orblx.test`
5. `jit.deny` for `app-b.orblx.test`
6. `svid.expired`
7. `frame_tx`
8. `session_up`
9. `session_down`
10. `session_down`

Each Agent JIT step has status `pass`.
The SVID state is `expired`.
The audit deny count is 2.

Press Spawn agent.
Spawn agent runs the same Agent JIT machine.
The first event kind is `smash_agent_spawn`.
The later kinds match items 2 to 10 in the Medium list.

### Hard — Radioactive NAT

Click Play Radioactive NAT.
Radioactive NAT runs on the board.
The event kinds are, in order:

1. `difficulty_selected`
2. `svid.issued`
3. `svid.revoked`
4. `session.dropped`
5. `nat.inject` with mode `udp_block`
6. `path.allocate` with overlay address `10.8.0.1`
7. `path.direct` with `ok` false
8. `nat.probe`
9. `path.down`
10. `path.switch`
11. `relay.hop`
12. `path.relay` with hop `tcp`
13. `path.up` with path `relay`
14. `path.down`
15. `session_down`

`path.direct` is before `path.switch`.
Direct is down.
The path then uses the TCP Relay.
`session.dropped` includes `within_s`.
`within_s` is at most 60.
The SVID state is `revoked`.
The symmetric NAT step stays `not_run` on this UDP block path.
The other Hard steps have status `pass`.
The feed does not name stick or upgrade.

Press UDP block.
UDP block runs the same NAT machine and does not revoke the SVID.
The event kinds start with `smash_udp_block` and `svid.issued`.
The later kinds match items 5 to 13 in the Hard list.
The QUIC path state is `up`.
The revoke step stays `not_run`.

## Early-user checks

Run the demo. A pass prints `demo pass`.

```bash
./scripts/demo.sh
```

Run the session audit check. A pass prints `The session audit chain check passed.`

```bash
./scripts/audit-smoke.sh
```

Run the userspace connector check. A pass prints `The userspace connector proof passed.`

```bash
./scripts/connector-smoke.sh
```

Read the kill or go packet in [docs/w12-kill-go.md](docs/w12-kill-go.md).

## TUN bench

The bench command is `./scripts/tun-bench.sh`.
Datapath owns the script and the measured rate.
The record is [docs/w12-tun-bench.md](docs/w12-tun-bench.md).
The measured rate is 8091.299206 Mbps.
The result is pass.
A host that is not Linux, or a host with no TUN device, exits clean and prints the K3 note.
That exit is not a pass of the 100 Mbps gate.

## License

The license is the Apache License, Version 2.0.
The copyright holder is Seogyu Kim, 2026.
Read [LICENSE](LICENSE) and [NOTICE](NOTICE).
