# Playable demo

The default page is the character scene in [w16-char-fx.md](w16-char-fx.md).
This page records the level machine under that scene.
The default page is a game.
The game is City Breeze, Agent JIT, and Radioactive NAT.
The board reads StackFeed JSON version 1.
`GET /events` sends that JSON.
The board also reads the same JSON from `GET /api/state` when the page opens after the Google callback.
The page does not invent counters.
The page does not play a canned story.
A feed event moves the board.
The page spaces one full level across about 35 seconds.
The gap is the wait between feed events.
The wait does not create events.
A short poke uses a shorter gap.
The gap stays between 0.8 seconds and 4 seconds.

## One command

Install a stable Rust toolchain.

```bash
cargo run -p orblx-sim
```

Open `http://127.0.0.1:8787`.

The process prints `Open http://127.0.0.1:8787` when the port is ready.
Use another address when port 8787 is busy:

```bash
cargo run -p orblx-sim -- --listen 127.0.0.1:8790
```

Open `http://127.0.0.1:8790`.

The first `cargo` build can take longer than a later start.
After that build, start the same command again.
The play page is that URL.
No other setup is required.

## Level select

The level select is three cartridges.
Each cartridge has one fault line from the level machine.

- City Breeze uses the Easy note.
- Agent JIT uses the Medium note.
- Radioactive NAT uses the Hard note.

The notes come from `Difficulty::note`.
The page copies the note from `GET /api/state`.

## Difficulty curve

The curve has three steps.
The steps are Easy, Medium, and Hard.
The order is the order in the level machine.
The selected step is the stored difficulty.
The line under the curve is `fault_detail`.
The page does not add a fault percent.
The page does not add a throughput number.

## Nodes

The board has five nodes.
The nodes are the human, the hub, application A, application B, and the Relay.
Each node has a color state.
The states are `up`, `degraded`, `down`, and `revoked`.
`idle` means the feed has not named that node in this run.
A feed event sets the state.
`svid.issued` and `agent.spawned` set the human node to `up`.
`svid.revoked` sets the human node to `revoked`.
`svid.expired` sets the human node to `down`.
`path.direct` with `ok` false sets the hub to `degraded`.
`path.relay`, `relay.hop`, and `path.up` with path `relay` set the Relay node to `up`.
`jit.allow` sets application A to `up`.
`jit.deny` sets application B to `down`.
`connector_https` with status 200 sets that application to `up`.

## Packet labels

A feed event moves the packet.
The label uses the feed kind or a feed field.
The labels are `SVID`, `ticket`, `Direct`, `Relay`, `Allow`, and `Deny` when the kind is one of those events.
Other labels use the kind, the host, the status, the mode, or the reason from that same event.

## Inspector

Click a node or click Path.
The inspector shows the last feed object for that target.
The fields are the fields on that object.
`seq` and `ts_ms` change when a new feed event arrives.
The inspector does not add a counter.

## City Breeze

1. Click Play City Breeze.
2. The browser opens Google sign-in.
3. Complete the Google consent.
4. The browser returns to the game.
5. The board shows `svid.issued`.
6. The board shows `ticket.verified`.
7. The board shows `quic_hello`.
8. The board shows the overlay ping frames.
9. The board shows `connector_https` for `app-a.orblx.test` with status 200.
10. The board shows `connector_https` for `app-b.orblx.test` with status 200.
11. The board shows `session_up`.

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

The poke box stays in the corner.
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

## Timed run

Pick a level.
The board then plays that run.
A progress bar shows the feed count for the run.
The text is `Feed N of M`.
`N` is the number of feed events the board has shown.
`M` is the number of feed events in the run.
The bar does not measure bandwidth.

The end card opens when the run has no more feed events.
`Soft win` follows `session_up`, `path.up`, or `svid.expired`.
`Soft win` also follows `session_down` with reason `expired`.
`Soft loss` follows `svid.revoked`, `session.dropped`, or reason `revoked`.
`path.direct` with `ok` false is a soft loss until a later `path.up`.
The card prints the feed detail for that event.
Next Level starts the next difficulty.
City Breeze goes to Agent JIT.
Agent JIT goes to Radioactive NAT.
Radioactive NAT opens Google sign-in for City Breeze.

Each level has its own board art.
City Breeze uses a street line.
Agent JIT uses a cool grid.
Radioactive NAT uses a hazard stripe.
The art is static.
The art changes when the feed `level` field changes.

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

This page is a playable board on the orblx-sim feed.
The player drives City Breeze through Google sign-in.
The player drives Agent JIT and Radioactive NAT from the same URL.
UDP block shows the fault and the Relay recovery on that board.
The picture uses feed fields only.
The picture does not add a throughput number.
The engine is still the level machine in `orblx-sim`.
The game is not a second stack and it is not a WASM rewrite.
A still screenshot does not show the play.
A play session has to include the clicks and the feed steps.
