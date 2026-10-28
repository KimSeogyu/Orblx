# Sim harness

The sim harness is a local skeleton.
The crate name is `gyeol-sim`.
The harness serves a web page.
The harness does not run the gyeol-quic stack.
The harness does not open a TUN device.
The harness does not open a QUIC socket.
The harness does not issue an SVID.
The harness does not issue a ticket.

The level bodies are empty.
A button writes a stub event.
A button does not pretend that the stack ran.

## Run

Install a stable Rust toolchain.

Run the harness:

```bash
cargo run -p gyeol-sim
```

Open `http://127.0.0.1:8787`.

Use a different local address when port 8787 is busy:

```bash
cargo run -p gyeol-sim -- --listen 127.0.0.1:8790
```

Show the command help:

```bash
cargo run -p gyeol-sim -- --help
```

## Levels

The harness has three levels.

- City Breeze. A human uses OIDC to get an SVID. The human sends an overlay ping. The human opens two HTTPS applications.
- Agent JIT. The operator spawns an agent. Application A allows the agent. Application B denies the agent. The ticket TTL expiry is visible.
- Radioactive NAT. The path can block UDP. The path can use symmetric NAT. The order is Allocate, then Direct, then Relay. An SVID revoke drops new packets within 60 seconds.

Each step has the status `not run`.

## Difficulty

The difficulty values are Easy, Medium, and Hard.
The harness stores the selected value.
The fault hook is not armed.
The harness does not inject a fault.

## Page

The page has a Peers panel.
The page has a Packets panel.
The page has a QUIC path panel.
The page has an SVID panel.
The page has a Ticket panel.
The page has an event log.

The smash buttons are Revoke, UDP block, and Spawn agent.
Revoke does not revoke an SVID.
UDP block does not block UDP.
Spawn agent does not spawn an agent.
The terminal prints each new stub event.

## Event bus

The trait name is `StackFeed`.
`IdentityFeed` is the Identity stub.
`EdgeNatFeed` is the EdgeNAT stub.
`DatapathFeed` is the Datapath stub.
Each stub returns no events.
A later week can implement `StackFeed` for a live stack feed.
`Harness::with_feeds` accepts those feeds.
A feed line does not fill the session panels.
This skeleton does not write the session panels.

## Checks

Run the format check:

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
