# gyeol

gyeol is a low-level overlay network.
The primary stack name is gyeol-quic.
gyeol-quic uses a userspace TUN device.
gyeol-quic uses QUIC on UDP port 443.
gyeol-quic uses short SPIFFE SVIDs.
gyeol-quic uses the gyeol Relay.

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
| `crates/gyeol-datapath` | Temporary name function |
| `crates/gyeol-crypto` | Temporary name function |
| `crates/gyeol-edge` | Temporary name function |
| `crates/gyeol-identity` | Temporary name function |
| `crates/gyeol-coord` | Temporary name function |
| `crates/gyeol-cli` | `gyeol` command |

The `gyeol` command prints a hello line.
The `gyeol` command prints the version when you use `--version`.
The `gyeol` command prints the version when you use `-V`.

The data path uses Quinn, rustls, and ring.
You can use aws-lc-rs as the crypto backend for rustls.
Read the comment in the workspace `Cargo.toml`.

## hello-quic

Week 3 adds the hello-quic path.
The path reads an IPv4 packet.
The path wraps the packet in one ADR-0002 DATA frame.
The path writes the frame on one QUIC bidirectional stream.
The path checks the peer leaf with `gyeol-identity`.
The record in [docs/adr/0002-frame-hello-quic.md](docs/adr/0002-frame-hello-quic.md) stays Proposed.

Run the server:

```bash
cargo run -p gyeol-cli -- hello-quic server \
  --cert server.pem --key server-key.pem \
  --bundle trust-bundle.pem --ticket ticket.bin \
  --tun-address 10.8.0.1
```

Run the client:

```bash
cargo run -p gyeol-cli -- hello-quic client \
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

`gyeol-edge` gathers one reflexive address with in-tree STUN.
The path machine starts in Allocate.
Allocate stores one unsigned candidate.
ADR 0003 leaves the Coordinator candidate owner open.
Direct sends hole-punch datagrams.
Direct then proves hello-quic on the same UDP socket.
`direct_is_up` is true after that proof.
The Direct budget is 3 seconds.
The QUIC policy port is UDP 443.
When Direct is down, the peers attach to the gyeol Relay.
The Relay routes by session id only.
The payload stays end-to-end encrypted.
UDP port 443 is the preferred Relay socket.
When UDP is blocked, the path uses TCP port 443.
TCP uses a QUIC-style length prefix.
The prefix is a 16-bit length and one Relay datagram.
The datagram payload is one QUIC packet.
Stick and upgrade is deferred.

Run the in-process same-NAT lab:

```bash
cargo run -p gyeol-cli -- edge-smoke
```

The lab uses a local STUN server.
The lab uses a userspace UDP NAT.
The two peers share the NAT address.
The punch uses the host candidates.
The command tries to bind the QUIC server on UDP port 443.
When that bind is not permitted, the server uses an ephemeral port.

Run the same lab on UDP port 443 when the process can bind that port:

```bash
cargo run -p gyeol-cli -- edge-smoke --bind 127.0.0.1:443
```

[`scripts/edge-smoke.sh`](scripts/edge-smoke.sh) runs the userspace lab.
The script runs the UDP 443 lab when root is available.
The script runs a netns source-NAT lab when `ip` and `iptables` are present.
The netns lab puts two peers behind one MASQUERADE NAT.
The QUIC server binds UDP port 443.

Gather against a STUN server:

```bash
cargo run -p gyeol-cli -- stun --server 127.0.0.1:3478
```

Answer Binding requests in the lab:

```bash
cargo run -p gyeol-cli -- stun-serve --listen 127.0.0.1:3478
```

## Relay

Run the Relay on UDP port 443 and TCP port 443:

```bash
cargo run -p gyeol-cli -- relay --udp 0.0.0.0:443 --tcp 0.0.0.0:443
```

The Relay does not mint a session id.
Give the same session id to both peers.
The peers prove QUIC through the Relay.

```bash
cargo run -p gyeol-cli -- relay-peer \
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
cargo run -p gyeol-cli -- relay-smoke udp
cargo run -p gyeol-cli -- relay-smoke tcp
```

[`scripts/edge-smoke.sh`](scripts/edge-smoke.sh) runs the Direct labs and the Relay labs.
The userspace Relay labs need no extra privileges.
The netns Relay labs need root, iproute2, and iptables.

## Connector hub

The product name is Orblx.
The command name is gyeol.
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
cargo run -p gyeol-cli -- connector smoke
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
The crate is `crates/gyeol-audit`.
The chain records session start, session end, and session deny.
Each record stores the previous SHA-256 hash.
The hash covers the previous hash and the event bytes.
The Relay session id is `RelaySessionId`.
The frame session id is the datapath frame `session_id`.
The peer is a SPIFFE ID from `gyeol-identity`.
The ticket hash is `gyeol_identity::ticket_hash`.

Export one deny and one successful session:

```bash
cargo run -p gyeol-cli -- audit demo --out chain.jsonl
```

Check the file:

```bash
cargo run -p gyeol-cli -- audit verify --file chain.jsonl
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
- On a symmetric NAT, a session through the gyeol Relay is valid.
- When an SVID expires, new packets stop within 60 seconds.
- When a ticket expires, new packets stop within 60 seconds.
- When the system revokes an SVID, new packets stop within 60 seconds.
- When the system revokes a ticket, new packets stop within 60 seconds.
- The repository contains one demo command.
- The repository contains a README in English.
- On a laptop, the local TUN round-trip rate is at least 100 Mbps.
- The system can export a short hash chain for session events.

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

Start the command:

```bash
cargo run -p gyeol-cli
```

Show the version:

```bash
cargo run -p gyeol-cli -- --version
```

GitHub Actions runs the format check, Clippy, and the tests.
GitHub Actions runs this workflow on each pull request.
GitHub Actions runs this workflow on each push to the main branch.

## Demo

[`scripts/demo.sh`](scripts/demo.sh) is the demo script.
In week 1, the script writes a message.
The message says that the demo is not ready.
The script then stops with exit status 0.
The 12-week work includes the full demo.

Run the script:

```bash
./scripts/demo.sh
```

## Sim harness

The sim harness crate is `gyeol-sim`.
The harness runs three levels.
The levels are City Breeze, Agent JIT, and Radioactive NAT.
Select Easy, Medium, or Hard on the page.
The page shows peers, packets, and session panels.
The event log shows feed JSON from those runs.
UDP block calls `gyeol_edge::run_nat_smash`.
Read the feed fields in [docs/w11-feed-v1.md](docs/w11-feed-v1.md).
Read the run steps in [docs/demo-sim.md](docs/demo-sim.md).

Run the harness:

```bash
cargo run -p gyeol-sim
```

Open `http://127.0.0.1:8787`.

## License

The license is the Apache License, Version 2.0.
The copyright holder is Seogyu Kim, 2026.
Read [LICENSE](LICENSE) and [NOTICE](NOTICE).
