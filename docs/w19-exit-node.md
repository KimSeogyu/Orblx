# Exit node

A node offers itself as an exit node with `orblx up --advertise-exit-node`.
The coordinator stores that offer.
The signed netmap sets `exit_node` only when the policy approves the node.
`autoApprovers.exitNode` is a list of selectors.
A tag, a group, or a SPIFFE ID can appear in that list.
`0.0.0.0/0` stays an exit route.
The coordinator still rejects that prefix in `subnet_routes` and in `autoApprovers.routes`.

A client selects the exit node with `orblx set --exit-node NAME`.
The next `orblx up` reads `{state}/exit-node.json`.
`orblx up --exit-node NAME` selects the same node for that start.
The node uses the exit node only when the signed netmap marks that peer as an exit node.
An unapproved name is not used.

The client installs `0.0.0.0/0` in routing table 5200.
That route uses the TUN device.
Routes to the coordinator, the Relay, and peer underlay addresses stay on the physical path.
`--exit-node-allow-lan-access` also keeps connected LAN prefixes on the local interfaces.
Without that flag, other LAN traffic uses the exit node.

The exit node reuses the subnet forward path.
It sets `net.ipv4.ip_forward` to 1.
It adds `iptables` MASQUERADE for packets from `100.64.0.0/10` that leave a physical interface.
The TUN device is not a masquerade target.
This build does not use a userspace NAT.

While the exit node is in use, non-overlay DNS queries go to the exit node.
The client log names the query and the exit node.
The exit node log names the query and the client overlay address.
Overlay names stay on the local DNS responder.

If direct UDP fails, the client uses the orblx Relay.
UDP is the first Relay attempt.
TCP port 443 is the fallback.

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` container | [C] | Coordinator. UDP 443. Policy file mount |
| `exit` container | [C] | Exit node. Overlay and internet network |
| `client` container | [C] | Client. Exit node from `orblx set` |
| `relay` container | [C] | Relay. UDP 443 and TCP 443 |
| `web` container | [C] | HTTP echo server. No Orblx process |

The image is `orblx-exit:local`.
The proof script is `scripts/proof/exit-node.sh`.
The Compose file is `scripts/proof/compose.exit.yml`.
The policy file in the proof is `scripts/proof/exit.hujson`.

The proof network is `172.30.19.0/24`.
The coordinator address is `172.30.19.2`.
The exit node address is `172.30.19.3`.
The client address is `172.30.19.4`.
The Relay address is `172.30.19.5`.
The internet network is `10.77.0.0/24`.
That network is internal.
The client is not attached to it.
The exit node address on that network is `10.77.0.2`.
The echo server address is `10.77.0.5`.
The echo server returns the TCP client address.

The node daemon still needs a capability ticket.
Coordinator enrollment does not mint that ticket.
The script enrolls both nodes and copies the signed netmap payload.
`orblx node-issue` then writes the certificate, the key, the trust bundle, and the ticket for those overlay addresses.
The script keeps the coordinator node certificate for coordinator calls.

The exit container is privileged.
It needs a writable `/proc/sys` to set IPv4 forwarding.
On this host, `bridge-nf-call-iptables` is 1.
The masquerade still runs in the exit node network namespace.

## Commands

```bash
orblx up --advertise-exit-node --coord ADDR --bundle FILE
orblx set --exit-node NAME [--exit-node-allow-lan-access] [--state-dir DIR]
orblx up --exit-node NAME [--exit-node-allow-lan-access] [--relay ADDR] [--coord ADDR --bundle FILE]
```

`orblx up --advertise-exit-node` with `--coord` and `--bundle` registers the offer, then starts the node.
The node prints `approved exit node` or `held exit node`.
The node forwards exit traffic only after approval.
`orblx set --exit-node` writes the selection for the next start.
`orblx up --exit-node` uses that name for the current start.

## Container proof

Run this command on the REAL Linux host:

```bash
scripts/proof/exit-node.sh
```

The script removes the `orblx-exit-proof` containers at the start.
Cleanup uses `docker compose down --profile nodes --profile tool`.
The same profile flag is now in `scripts/proof/subnet.sh`.
The recorded run used image `orblx-exit:local`.
The lines below start after the image build.

```text
=== [C] bridge-nf-call-iptables ===
bridge-nf-call-iptables 1
=== [C] policy test ===
allow spiffe://orblx.local/node/client tcp spiffe://orblx.local/node/exit 80
deny spiffe://orblx.local/node/client tcp spiffe://orblx.local/node/exit 22
policy ok
=== [C] token exit ===
wrote one enroll token
token_id ccaa71a4425b1fd8
expires_unix 1793316110
out /var/lib/orblx/tokens/exit
=== [C] token client ===
wrote one enroll token
token_id d6055b394b198fdd
expires_unix 1793316111
out /var/lib/orblx/tokens/client
=== [C] enroll exit ===
enrolled
name exit
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/exit
peers 0
=== [C] enroll client ===
enrolled
name client
overlay_ip 100.64.0.2
svid spiffe://orblx.local/node/client
peers 1
=== [C] netmap before exit approval ===
netmap
name client
overlay_ip 100.64.0.2
peer exit 100.64.0.1
endpoints_ok 2
grants 0
netmap
name exit
overlay_ip 100.64.0.1
peer client 100.64.0.2
endpoints_ok 2
grants 1
exit_node_before_offer false
=== [C] overlay addresses ===
exit 100.64.0.1
client 100.64.0.2
=== [C] node material ===
The command wrote the node exit material for overlay 100.64.0.1 in /tmp/tmp.uIMIrGyhJi/nodes/exit.
The command wrote the node client material for overlay 100.64.0.2 in /tmp/tmp.uIMIrGyhJi/nodes/client.
=== [C] orblx set --exit-node exit ===
The next start uses exit node exit.
=== [C] client before the exit node is approved ===
=== [C] route before approval ===
=== [C] ip route get 10.77.0.5 ===
10.77.0.5 via 172.30.19.1 dev eth0 src 172.30.19.4 uid 0 
    cache 
=== [C] HTTP before approval ===
curl_status 28
curl: (28) Connection timed out after 5002 milliseconds
=== [C] start exit node ===
=== [C] start client with the approved exit node ===
=== [C] ip route get 10.77.0.5 ===
10.77.0.5 dev orblx0 table 5200 src 100.64.0.2 uid 0 
    cache 
=== [C] ip route get 172.30.19.2 ===
172.30.19.2 via 172.30.19.1 dev eth0 table 5200 src 172.30.19.4 uid 0 
    cache 
=== [C] ip route get 172.30.19.5 ===
172.30.19.5 via 172.30.19.1 dev eth0 table 5200 src 172.30.19.4 uid 0 
    cache 
=== [C] ip route get 172.30.19.3 ===
172.30.19.3 via 172.30.19.1 dev eth0 table 5200 src 172.30.19.4 uid 0 
    cache 
=== [C] HTTP through the exit node ===
10.77.0.2
=== [C] DNS through the exit node ===
=== [C] client DNS log ===
client-1  | The node installs route 0.0.0.0/0 through the exit node exit.
client-1  | The node sends a DNS query for example.com through the exit node exit.
client-1  | The node sends a DNS query for example.com through the exit node exit.
=== [C] exit DNS log ===
exit-1  | The node received a DNS query for example.com from 100.64.0.2.
exit-1  | The node received a DNS query for example.com from 100.64.0.2.
=== [C] drop client UDP except loopback ===
-P OUTPUT ACCEPT
-A OUTPUT ! -o lo -p udp -j DROP
-P INPUT ACCEPT
-A INPUT ! -i lo -p udp -j DROP
=== [C] wait for the TCP Relay ===
=== [C] client Relay log ===
client-1  | The path to exit uses the TCP Relay.
=== [C] HTTP stays on the exit node for 2 minutes ===
hold 1 2026-10-29T22:22:38Z 10.77.0.2
hold 2 2026-10-29T22:22:54Z 10.77.0.2
hold 3 2026-10-29T22:23:09Z 10.77.0.2
hold 4 2026-10-29T22:23:24Z 10.77.0.2
hold 5 2026-10-29T22:23:39Z 10.77.0.2
hold 6 2026-10-29T22:23:55Z 10.77.0.2
hold 7 2026-10-29T22:24:10Z 10.77.0.2
hold 8 2026-10-29T22:24:25Z 10.77.0.2
hold 9 2026-10-29T22:24:41Z 10.77.0.2
tcp_hold_start 2026-10-29T22:22:38Z
tcp_hold_end 2026-10-29T22:24:41Z
tcp_hold_seconds 123
proof_ok
```

`token_id` is the public id of the token.
The secret stays in the token file.
Before approval, `ip route get 10.77.0.5` uses `eth0`.
The HTTP call times out.
The client is not on the internet network.
After approval, `ip route get 10.77.0.5` uses `orblx0` in table 5200.
The echo body is `10.77.0.2`.
That address is the exit node on the internet network.
`ip route get` for the coordinator, the Relay, and the exit node underlay address uses `eth0`.
The client log shows the DNS query for `example.com` through the exit node.
The exit node log shows that query from `100.64.0.2`.
The script then drops UDP in the client container.
Loopback UDP stays open for the local Relay bridge.
The client log shows `The path to exit uses the TCP Relay.`
HTTP through that path returns `10.77.0.2` for 123 seconds.
The script sets iptables-legacy FORWARD to ACCEPT when that policy is DROP and iptables-nft FORWARD is ACCEPT.
The recorded lines do not include that step.
FORWARD was already ACCEPT.
