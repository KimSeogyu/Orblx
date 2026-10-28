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

## License

The license is the Apache License, Version 2.0.
The copyright holder is Seogyu Kim, 2026.
Read [LICENSE](LICENSE) and [NOTICE](NOTICE).
