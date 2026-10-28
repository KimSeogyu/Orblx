# Stick and upgrade

The path holds Relay.
The path retries Direct.
A successful retry moves later traffic to Direct.
The process does not restart.

## Method

The method is reconnect.

The data path uses Quinn 0.11.
`prove_hello_socket` opens one hello-quic session.
That session exchanges one IPv4 packet.
That session then closes.
The Relay path binds Quinn to a loopback socket.
A bridge copies those datagrams to the gyeol Relay.
The Quinn remote address is the local bridge.
The Quinn remote address is not the peer.

Quinn 0.11 provides `Endpoint::rebind`.
`rebind` replaces the local UDP socket for the connections on that endpoint.
`rebind` does not move a connection from the local bridge to the peer address.
This crate does not call `rebind`.

`PathMachine::retry_direct` opens a new hello-quic session on the direct UDP socket.
The call runs in the same process.
The Relay path id stays in place until the new session succeeds.
The Direct path id is a new 16-byte value.
`DirectUpgrade.from_path_id` is the previous Relay path id.

## Stick

Relay Up starts a timer.
The interval is `DIRECT_RETRY_INTERVAL`.
That interval is 1 second.
A retry before the timer returns `EdgeError::StickHold`.
The state stays Relay Up.
The Relay path id does not change.
A failed punch does the same.
A failed QUIC proof does the same.
The timer starts again after a failed retry.

A successful proof moves the machine to Direct Up.
`direct_is_up` becomes true.
`relay_is_up` becomes false.
The hello-quic exchange on the direct socket is the later traffic.
That exchange does not increase the Relay forward count.

## How to run

Run the in-process labs:

```bash
cargo test -p gyeol-edge --lib stick::tests -- --test-threads=1
```

Run the same labs from the command:

```bash
cargo run -p gyeol-cli -- stick-upgrade
```

The labs call `PathMachine`.
They call `begin_relay`, `finish_relay`, and `retry_direct`.
They do not use a second state machine.

gyeol-sim Hard still calls `run_nat_smash`.
That smash ends on Relay.
Direct stays down.
The smash feed does not record stick.

## Results

`cargo test -p gyeol-edge --lib stick::tests -- --test-threads=1` passed on this machine.
`cargo run -p gyeol-cli -- stick-upgrade` exited 0 on this machine.
The runs used the in-process labs.
The runs did not use network namespaces.
The runs did not print throughput or RTT percentiles.

The command printed these results.

- same-nat: `upgraded true`, `direct echo ok true`, `direct_on_host true`, `direct_used_relay false`, `restarted false`.
- symmetric: `upgraded false`, `transport udp`, `client relay_is_up true`, `relay_path_stable true`, `restarted false`.
- udp-block: `upgraded false`, `transport tcp`, `client relay_is_up true`, `relay_path_stable true`, `restarted false`.

| Lab | Start | Later Direct attempt | Result |
| --- | --- | --- | --- |
| same-nat | Relay UDP, after Direct failed | Host punch and hello-quic succeeded | Pass. Later traffic used Direct. The process did not restart. The Relay forward count did not change. The Relay path id changed to a new Direct path id. |
| symmetric | Relay UDP, after Direct failed | No peer answered | Fail. The path stayed on Relay UDP. The Relay path id did not change. |
| udp-block | Relay TCP, after Direct failed | No peer answered | Fail. The path stayed on Relay TCP. The Relay path id did not change. |

same-nat is the upgrade proof.
symmetric did not upgrade.
udp-block did not upgrade.
Direct did not become available in those two labs.
The path held Relay.
Do not read those two rows as a pass.

`scripts/relay-netns.sh` was not run for this change.
That script still checks the Relay proof.
It does not open Direct after Relay.
