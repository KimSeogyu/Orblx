# Sim harness

The sim harness runs three levels.
The crate name is `gyeol-sim`.
The harness serves the game.
The default page is the game.
The engineering view shows peers, packets, the QUIC path, the SVID, and the ticket.
The event log shows feed JSON.
The feed version is 1.
Read the field list in [w11-feed-v1.md](w11-feed-v1.md).
Read the play path in [w15-demo-ui.md](w15-demo-ui.md).

The harness does not open a TUN device.
The harness does not open a Unix socket.
The game board moves when a feed event arrives.
The game does not play a canned success animation.
A button runs a state machine.
The machine writes one feed object per transition.

## One command

Run the demo:

```bash
./scripts/demo.sh
```

The script starts this harness.
The script checks the Google authorize redirect for City Breeze.
The script then posts Revoke, Medium, Spawn agent, Hard, and UDP block.
The script reads the event kinds from the harness.
The script checks that the default page is the game.
The script rejects a canned keyframe animation.
A pass prints `demo pass`.
The browser steps and the kind lists are in the README.

## Run

Install a stable Rust toolchain.

Run the harness:

```bash
cargo run -p gyeol-sim
```

Open `http://127.0.0.1:8787`.
The page is the game.

Use a different local address when port 8787 is busy:

```bash
cargo run -p gyeol-sim -- --listen 127.0.0.1:8790
```

Show the command help:

```bash
cargo run -p gyeol-sim -- --help
```

## Levels

Select a level or select a difficulty.
Easy runs City Breeze.
Medium runs Agent JIT.
Hard runs Radioactive NAT.

- City Breeze. A human signs in with Google. The callback issues an SVID. The human sends an overlay ping. The human opens two HTTPS applications. Press Revoke to drop that SVID. Read the click path in [w17-google-oidc.md](w17-google-oidc.md).
- Agent JIT. Spawn agent creates the agent SVID. Application A allows the agent. Application B denies the agent. The ticket TTL expiry is visible.
- Radioactive NAT. UDP block calls `gyeol_edge::run_nat_smash`. Direct fails. The path then uses the TCP Relay. The overlay address is `10.8.0.1`. An SVID revoke drops new packets within 60 seconds. This smash does not upgrade to Direct. Stick and upgrade is in [w13-stick-upgrade.md](w13-stick-upgrade.md).

A passed step has the status `pass`.

## Difficulty

The difficulty values are Easy, Medium, and Hard.
The fault hook is armed when the level runs.
Easy arms the revoke inject.
Medium arms the agent allow and deny path.
Hard arms UDP block.
The path uses the TCP Relay.

## Page

The default page is the game.
Play City Breeze opens Google sign-in.
Read the clicks in [w15-demo-ui.md](w15-demo-ui.md).
Easy and City Breeze in the engineering view open the same sign-in page.
Sign in on that page before the level runs.
The smash buttons are Revoke, UDP block, and Spawn agent.
Revoke writes `svid.revoked` and then `session.dropped`.
`within_s` is the wall-clock seconds for that drop.
UDP block writes `nat.inject` and the path events.
Spawn agent writes `agent.spawned`, `jit.allow`, `jit.deny`, and `svid.expired`.
The terminal prints each new event.
`GET /events` sends the same JSON.

## Event bus

The trait name is `StackFeed`.
`drain` returns JSON objects.
`IdentityFeed` carries identity kinds.
`EdgeNatFeed` carries EdgeNAT kinds.
`DatapathFeed` carries datapath kinds.
`Harness::with_feeds` accepts a replacement feed.

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
