# Character scene

The default page is a character scene.
The scene reads StackFeed JSON version 1.
`GET /events` sends that JSON.
The scene also reads `GET /api/state` after the mock IdP callback.
A feed event moves a character, a path, or both.
The scene does not invent a feed event.
The scene does not play a canned keyframe story.

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

## Cast

The board has six characters.
A feed event sets the sprite state.
The states are `up`, `degraded`, `down`, and `revoked`.
`idle` means this run has not named that character.
`jit.allow` sets allow on application A.
`jit.deny` sets deny on application B.

| Character | Feed |
| --- | --- |
| Human | `svid.issued`, `svid.revoked`, `svid.expired`, `session.dropped` |
| Agent | `agent.spawned`, `jit.allow`, `jit.deny`, `svid.expired` on `agent_jit` |
| Direct | `path.direct`, `path.down`, `path.up`, `quic_hello`, `nat.inject` |
| app-a.orblx.test | `jit.allow`, `connector_https` for that host |
| app-b.orblx.test | `jit.deny`, `connector_https` for that host |
| Relay | `relay.hop`, `path.relay`, `path.up` with `path` `relay` |

`path.direct` with `ok` false sets Direct to `degraded`.
`path.direct` with `ok` true sets Direct to `up`.
`svid.revoked` sets the human to `revoked`.
`svid.expired` sets the named session character to `down`.

## Effects

Each mote is the picture of one received feed event.

| Feed | Effect |
| --- | --- |
| `svid.issued` | Mint motes on the human |
| `agent.spawned` | Mint motes on the agent |
| `ticket.verified` | Ticket motes on the human |
| `path.direct` with `ok` false | Break motes on Direct |
| `nat.inject`, `path.down` | Break motes on Direct |
| `relay.hop`, `path.relay`, `path.up` with `path` `relay` | Relay motes on Relay |
| `jit.allow` | Allow motes on application A |
| `jit.deny` | Deny motes on application B |
| `svid.revoked`, `session.dropped` | Revoke motes on the human |
| `connector_https` | Allow or deny motes on that application |
| `quic_hello`, `frame_tx`, `frame_rx`, `path.switch` | Ticket motes on the event lane |

The same event draws a line between the two characters in that event.
The same event moves the packet along that line.
The page spaces one full level across about 35 seconds.
The gap is the wait between feed events.
The wait does not create events.
A short poke uses a shorter gap.
The gap stays between 0.8 seconds and 4 seconds.

## Play

City Breeze:

1. Click Play City Breeze.
2. The mock IdP page opens.
3. Click Sign in.
4. The human shows the SVID and the ticket.
5. Direct meets application A and application B.
6. Each application returns status 200.
7. The human pose shows the session up.

Agent JIT:

1. Click Play Agent JIT.
2. The agent stands up.
3. The agent meets application A on `jit.allow`.
4. The agent meets application B on `jit.deny`.
5. Application A opens.
6. Application B bars the door.

Radioactive NAT and UDP block:

1. Click Play Radioactive NAT or click UDP block.
2. Direct breaks on `path.direct` with `ok` false.
3. Relay stands up on `path.relay` with hop `tcp`.
4. `path.up` with `path` `relay` keeps Relay up.
5. UDP block leaves that Relay path up.

Revoke drops the current SVID on the same board.
Spawn agent runs the agent path on the same board.

## Soft result

`session_up`, `path.up`, and `svid.expired` set a soft win pose.
`session_down` with reason `expired` sets a soft win pose.
`svid.revoked`, `session.dropped`, and reason `revoked` set a soft loss pose.
`path.direct` with `ok` false sets a soft loss pose until a later `path.up`.
The up characters lift their arms on a soft win.
The degraded, down, and revoked characters drop on a soft loss.
Next Level starts the next difficulty.
City Breeze goes to Agent JIT.
Agent JIT goes to Radioactive NAT.
Radioactive NAT opens the mock IdP for City Breeze.
The sentence for that result stays in Engineering view.

## Inspector

Click a character or click Path.
The inspector shows the last feed object for that target.
The fields are the fields on that object.
Engineering view is closed on the default page.
Click Engineering view to open the peers, the packets, the QUIC path, the SVID, the ticket, and the event log.
Close Engineering view to return to the character scene.

## Levels

The level select is three play buttons.
The buttons are City Breeze, Agent JIT, and Radioactive NAT.
The curve has Easy, Medium, and Hard.
The order is the order in the level machine.
The line under the curve is `fault_detail` from `GET /api/state`.
That line stays in Engineering view.
The page does not add a fault percent.
The page does not add a throughput number.

## Check

```bash
./scripts/demo.sh
```

A pass prints `demo pass`.
The script checks the feed kinds.
The script checks that the default page is the game.
The script checks that Engineering view is hidden.
The script rejects a canned keyframe animation.

## Notes for accept

The player drives City Breeze through the mock IdP.
The player drives Agent JIT and Radioactive NAT from the same URL.
UDP block shows the Direct fault and the Relay recovery on that board.
The picture uses feed fields only.
The picture does not add a throughput number.
The engine is still the level machine in `gyeol-sim`.
The scene is not a second stack and it is not a WASM rewrite.
A still screenshot does not show the play.
A play session has to include City Breeze and one fault beat.
