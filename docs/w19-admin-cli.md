# Admin CLI and node health

The coordinator keeps a node out of every netmap until an owner approves it.
The policy field `nodeApproval` selects this gate.
The value `true` marks a new node pending.
An owner SVID is approved at enroll.
`orblx admin approve` marks a pending node approved.
The coordinator then puts that node into netmaps and grants.
`orblx admin revoke` adds the node SVID to the deny set.
A later ping stops.
The node daemon reloads `deny.json` and drops the node within 60 seconds.
`orblx admin expire` removes the node from netmaps until the next approve.

The node daemon and the Relay expose Prometheus text on a local port.
The default address is `127.0.0.1:9464`.
The listener accepts a loopback address only.

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` container | [C] | Coordinator. UDP 443. Policy file mount |
| `owner` container | [C] | Owner SVID. Runs `orblx admin` |
| `a` container | [C] | New node. Runs `orblx ping` |
| `b` container | [C] | Approved listener. Runs `orblx up` |
| `relay` container | [C] | UDP Relay. Metrics on `127.0.0.1:9464` |

The image is `orblx-admin:w19`.
The proof script is `scripts/proof/admin.sh`.
The Compose file is `scripts/proof/compose.admin.yml`.
The policy file in the proof is `scripts/proof/admin.hujson`.

The proof uses enroll tokens.
`ORBLX_OIDC_MODE=mock` keeps laptop login off.
The script does not print enroll tokens or private keys.

## Commands

```bash
orblx admin nodes --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin users --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin approve NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin revoke NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin expire NODE --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx admin routes --coord ADDR [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx netcheck --udp ADDR --quic ADDR --relay ADDR [--stun ADDR] [--timeout SECS]
orblx ping NODE [--state DIR] [--coord ADDR] [--coord-name NAME] [--bundle FILE] [--relay ADDR] [--timeout SECS]
orblx status --json [--state-dir DIR]
orblx up --metrics 127.0.0.1:9464
orblx relay --metrics 127.0.0.1:9464
```

`--metrics off` leaves the metrics port closed.
The admin caller certificate must be an owner in the policy.
`orblx ping` prints `path direct` or `path relay` and `rtt_ms`.
A pending peer is absent from the netmap, so the ping sends no packet.
A revoked peer fails the ping before the packet is sent.
`orblx netcheck` prints UDP 443, QUIC 443, Relay reachability, and the NAT kind.
The NAT kind comes from `orblx-edge` `NatKind`.

## Container proof

Run this command on the REAL Linux host:

```bash
scripts/proof/admin.sh
```

The script deletes the `orblx-admin-proof` volumes at the start.
The recorded run used image `orblx-admin:w19`.
The lines below start after the image build.

```text
=== [C] start coordinator ===
=== [C] token owner ===
wrote one enroll token
token_id 3e3b6e527804c2eb
expires_unix 1793315942
out /var/lib/orblx/tokens/owner
=== [C] token a ===
wrote one enroll token
token_id 859a7f0108f4651b
expires_unix 1793315942
out /var/lib/orblx/tokens/a
=== [C] token b ===
wrote one enroll token
token_id 4e8b343f52b1ef5a
expires_unix 1793315942
out /var/lib/orblx/tokens/b
=== [C] coordinator address ===
coord_ip 172.18.0.2
=== [C] enroll owner ===
enrolled
name owner
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/owner
peers 0
=== [C] enroll a ===
enrolled
name a
overlay_ip 100.64.0.2
svid spiffe://orblx.local/node/a
peers 0
=== [C] enroll b ===
enrolled
name b
overlay_ip 100.64.0.3
svid spiffe://orblx.local/node/b
peers 0
=== [C] admin nodes before approve ===
node owner 100.64.0.1 approved
node a 100.64.0.2 pending
node b 100.64.0.3 pending
nodes 3
=== [C] ping before approve ===
The node cannot send packets. The node b is not in the netmap.
=== [C] admin approve ===
approved a
approved b
=== [C] admin users ===
users 0
=== [C] admin routes ===
node owner advertised 0 approved 0
node a advertised 0 approved 0
node b advertised 0 approved 0
=== [C] netmap on a ===
netmap
name a
overlay_ip 100.64.0.2
peer owner 100.64.0.1
peer b 100.64.0.3
endpoints_ok 3
grants 0
=== [C] netmap on b ===
netmap
name b
overlay_ip 100.64.0.3
peer owner 100.64.0.1
peer a 100.64.0.2
endpoints_ok 3
grants 1
=== [C] start node b ===
=== [C] ping after approve ===
path direct
rtt_ms 24
=== [C] status json ===
{"state":"up","name":"b","overlay_ip":"100.64.0.3","svid":"spiffe://orblx.local/node/b","svid_expiry":1793313243,"peers":[{"name":"a","overlay_ip":"100.64.0.2","path":"stale","svid":"spiffe://orblx.local/node/a","svid_expiry":1793313243},{"name":"owner","overlay_ip":"100.64.0.1","path":"down","svid":"spiffe://orblx.local/node/owner","svid_expiry":null}]}
=== [C] node metrics ===
# TYPE orblx_node_packets_tx counter
orblx_node_packets_tx 0
# TYPE orblx_node_packets_rx counter
orblx_node_packets_rx 0
# TYPE orblx_node_sessions gauge
orblx_node_sessions 1
=== [C] start relay ===
relay_ip 172.18.0.4
=== [C] netcheck ===
udp443 ok
quic443 ok
relay ok
nat cone
=== [C] relay metrics ===
# TYPE orblx_relay_attaches counter
orblx_relay_attaches 1
# TYPE orblx_relay_forwards counter
orblx_relay_forwards 0
# TYPE orblx_relay_forward_bytes counter
orblx_relay_forward_bytes 0
# TYPE orblx_relay_drops counter
orblx_relay_drops 0
=== [C] admin revoke ===
revoked b
deny_version 1
=== [C] ping after revoke ===
The node cannot send packets. The node b is revoked.
revoke_stop_s 0
proof_ok
```

`jq` on the REAL host parsed the status JSON.
The node metrics and the Relay metrics returned counters.
The NAT kind is `cone` because UDP 443 answered and the proof has no STUN server.
The ping after revoke stopped in the same second.
That interval is inside the 60 second limit.
