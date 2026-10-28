# Playable demo

The default page is a game.
The game is City Breeze, Agent JIT, and Radioactive NAT.
The board reads StackFeed JSON version 1.
`GET /events` sends that JSON.
The board also reads the same JSON from `GET /api/state` when the page opens after the mock IdP callback.
The page does not invent counters.
The page does not play a canned story.
A feed event moves the board.
The wait between events lets a person see each event.
The wait does not create events.

## One command

Install a stable Rust toolchain.

```bash
cargo run -p gyeol-sim
```

Open `http://127.0.0.1:8787`.

The process prints `Open http://127.0.0.1:8787` when the port is ready.
Use another address when port 8787 is busy:

```bash
cargo run -p gyeol-sim -- --listen 127.0.0.1:8790
```

Open `http://127.0.0.1:8790`.

The first `cargo` build can take longer than a later start.
After that build, start the same command again.
The play page is that URL.
No other setup is required.

## City Breeze

1. Click Play City Breeze.
2. The mock IdP page opens.
3. The page shows the issuer `https://oidc.gyeol.local`.
4. The page shows the audience `gyeol-issue`.
5. The page shows the subject `ada`.
6. Click Sign in.
7. The browser returns to the game.
8. The board shows `svid.issued`.
9. The board shows `ticket.verified`.
10. The board shows `quic_hello`.
11. The board shows the overlay ping frames.
12. The board shows `connector_https` for `app-a.orblx.test` with status 200.
13. The board shows `connector_https` for `app-b.orblx.test` with status 200.
14. The board shows `session_up`.

The feed detail is the sentence on the board.
The SVID chip and the ticket chip change from those events.

## Agent JIT

Click Play Agent JIT.
The board shows `agent.spawned`.
The board shows `jit.allow` for `app-a.orblx.test`.
The board shows `jit.deny` for `app-b.orblx.test`.
The board shows `svid.expired`.

## Radioactive NAT

Click Play Radioactive NAT.
The board shows `path.direct` with ok false.
The path label is `Direct not ok`.
The board then shows `path.relay` with hop `tcp`.
The board then shows `path.up` with path `relay`.
The path label is `Up relay`.
This level then revokes the SVID.
The path label changes when `session_down` arrives.

## Poke

UDP block is the fault and recovery poke.

1. Click UDP block.
2. The board shows `nat.inject` with mode `udp_block`.
3. The board shows `path.direct` with ok false.
4. The board shows `path.switch`.
5. The board shows `path.relay` with hop `tcp`.
6. The board shows `path.up` with path `relay`.
7. The Relay node is lit.
8. The path stays up.

Revoke drops the current SVID on the same board.
Spawn agent runs the agent path on the same board.

## Engineering view

The engineering panels are hidden.
Click Engineering view to open them.
The panels show peers, packets, the QUIC path, the SVID, the ticket, and the event log.
Those panels read the same harness snapshot.
Close the view to return to the game.
The default URL stays the game.

## Check

```bash
./scripts/demo.sh
```

A pass prints `demo pass`.
The script checks the feed kinds.
The script checks that the default page is the game.
The script rejects a canned keyframe animation.

## Notes for accept

This page is a playable board on the gyeol-sim feed.
The player drives City Breeze through the mock IdP.
The player drives Agent JIT and Radioactive NAT from the same URL.
UDP block shows the fault and the Relay recovery on that board.
The picture uses feed fields only.
The picture does not add a throughput number.
The engine is still the level machine in `gyeol-sim`.
The game is not a second stack and it is not a WASM rewrite.
A still screenshot does not show the play.
A play session has to include the clicks and the feed steps.
