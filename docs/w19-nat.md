# NAT traversal

Two nodes sit behind two NAT routers.
They open one overlay session.
The session uses a direct UDP path when the punch works.
The session uses the orblx Relay when the punch does not work.
A later direct path replaces the Relay path.
The overlay session stays up during the switch.

`orblx status` prints the path kind for each peer.
The path kind is `direct` or `relay`.

## Who signs a candidate

ADR 0003 left this question open.
The coordinator signs the candidate.
The edge verifies the signature before it uses the address.

`endpoint_sign_payload` is the byte string.
The string is `orblx-endpoint-v1`, the node name, and the endpoint.
The coordinator signs that string with the netmap Ed25519 key.
The NAT node checks the signature with `verify_signed_candidate`.
A bad signature is rejected.
The log line is `The candidate signature for <name> was rejected.`
The log line does not contain the signature or the key.

The node learns its reflexive address with STUN.
The node sends that address to the coordinator with the `candidates` operation.
The coordinator replaces the endpoint set for that node and returns signed endpoints.

## Paths

The peers exchange signed candidates through the coordinator.
They punch UDP with retries.
A symmetric NAT can change the source port.
The punch accepts a new source port on the signed IP.

The first direct attempt lasts 3 seconds.
The Relay stays idle as the active path during that attempt.
When direct fails, the peers use the orblx Relay.
The Relay prefers UDP port 443.
TCP port 443 uses a QUIC-style length prefix.

The same session id and the same send counter stay in place when the path changes.
A silent direct path moves the session to the Relay.
The session can return to direct after the hold time.
The hold time is 1 second.

## Proof layout

The host is REAL.
Every extra host is a [C] container.
`scripts/proof/nat.sh` builds the image with `scripts/proof/stage-image.sh`.

The [C] public network is `172.29.19.0/24`.
The coordinator is `172.29.19.10`.
The Relay and the STUN server are `172.29.19.20`.
Router-1 is endpoint-independent NAT.
Router-1 uses SNAT to `172.29.19.11` and DNAT of UDP port 443.
Router-2 is symmetric NAT.
Router-2 uses `MASQUERADE --random-fully` for UDP.
Router-3 is a second endpoint-independent NAT at `172.29.19.13`.
Router-4 is a second symmetric NAT at `172.29.19.14`.
Node X is behind router-1.
Node Y is behind router-2.
Node Z is behind router-3.
Node W is behind router-4.
Each node has its own LAN: `10.19.1.0/24`, `10.19.2.0/24`, `10.19.3.0/24`, and `10.19.4.0/24`.

The REAL host must let the [C] routers forward by MAC.
`scripts/proof/nat.sh` sets `iptables-legacy` FORWARD to ACCEPT when that policy is DROP.
The script sets `bridge-nf-call-iptables` to 0.
That stop keeps the host from routing the frame around the [C] router.

## No topology shortcut

The proof does not let two nodes meet on a LAN.
The proof checks these items before case 1:

- Each node has one address on its own LAN and a default route through its router.
  No two nodes share a subnet.
- Each router drops a forwarded packet to `10.19.0.0/16` unless the packet leaves on the LAN of that router.
  Each router drops a forwarded packet from `10.19.0.0/16` unless the packet comes in on the LAN of that router.
- Node X pings the other node LANs and the other router LAN addresses.
  All the pings fail, and the proof prints `lan_shortcut false`.
- No router has a DNAT rule on its LAN interface, so no router does a hairpin.
  The only DNAT rule is the UDP 443 rule on the WAN interface of a cone router.
- A node publishes only its STUN reflexive address.
  The coordinator replaces the endpoint set for that node, so no LAN address is a candidate.

## Router mapping probe

The proof measures the NAT kind before it starts the nodes.
A [C] UDP server runs on the coordinator and on the Relay.
Each server answers with the source address that it saw.
A node sends from one inner port, 40000, to both servers.

- Router-2 gives the inner port a different external port for each destination.
  The proof stops when the two ports are equal.
- Router-4 also gives two different external ports.
- Router-1 keeps one external port for both destinations.

## Why cone to symmetric is direct

The two "cone" routers are endpoint-independent.
Each one also has a static DNAT of UDP 443 to its node.
That DNAT is a port forward, so a cone router accepts UDP 443 from any source address and any source port.

Node Y sends a punch from behind router-2 to `172.29.19.11:443`.
Router-2 gives that flow a new external port.
That port is not the port in the signed candidate for node Y, because the candidate came from the STUN flow.
Router-1 accepts the punch on UDP 443 and sends it to node X.
Node X accepts the new source port because the IP is the signed IP of node Y.
Node X answers to that address.
Router-2 has a mapping for that flow, so the answer gets to node Y.

The case 2 log shows this result.
The signed candidate for node Y and the address that the punch reached have the same IP, `172.29.19.12`, but different ports.
Node Y reached `172.29.19.11:443`, which is the WAN address of router-1.
The direct path does not use a LAN address, a shared subnet, or a hairpin.

Two symmetric routers do not have a port forward.
Each side sends to a port that the other router did not open for that flow.
Case 5 proves that such a pair uses the Relay.

## Command

Run this command on the REAL host:

```bash
bash scripts/proof/nat.sh
```

## Output

This run was on one REAL Linux host at commit `e924524`.
Docker ran the [C] containers.
The command exited 0.
The output below leaves out build lines, ping reply lines, and repeated status fields.

```text
=== REAL cargo test tampered candidate ===
The candidate signature for node-a was rejected.
The candidate signature for node-a was rejected.
test signed::tests::tampered_candidate_signature_is_rejected ... ok
REAL bridge-nf-call-iptables 0
=== [C] start public network, routers, coordinator, and relay ===
REAL bridge-nf-call-iptables 0
=== [C] router-1 cone ===
router mode cone
router wan eth1 172.29.19.11
-A PREROUTING -i eth1 -p udp -m udp --dport 443 -j DNAT --to-destination 10.19.1.10:443
-A POSTROUTING -o eth1 -j SNAT --to-source 172.29.19.11
-A FORWARD -d 10.19.0.0/16 ! -o eth0 -j DROP
-A FORWARD -s 10.19.0.0/16 ! -i eth0 -j DROP
-A FORWARD -d 10.19.1.10/32 -i eth1 -o eth0 -p udp -m udp --dport 443 -j ACCEPT
-A FORWARD -i eth0 -o eth1 -j ACCEPT
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
=== [C] router-2 symmetric ===
router mode symmetric
router wan eth0 172.29.19.12
-A POSTROUTING -o eth0 -p udp -j MASQUERADE --random-fully
-A POSTROUTING -o eth0 -p tcp -j MASQUERADE
-A POSTROUTING -o eth0 -p icmp -j MASQUERADE
-A FORWARD -d 10.19.0.0/16 ! -o eth1 -j DROP
-A FORWARD -s 10.19.0.0/16 ! -i eth1 -j DROP
-A FORWARD -i eth1 -o eth0 -j ACCEPT
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
=== [C] router-3 cone ===
router mode cone
router wan eth1 172.29.19.13
-A PREROUTING -i eth1 -p udp -m udp --dport 443 -j DNAT --to-destination 10.19.3.10:443
-A POSTROUTING -o eth1 -j SNAT --to-source 172.29.19.13
-A FORWARD -d 10.19.0.0/16 ! -o eth0 -j DROP
-A FORWARD -s 10.19.0.0/16 ! -i eth0 -j DROP
-A FORWARD -d 10.19.3.10/32 -i eth1 -o eth0 -p udp -m udp --dport 443 -j ACCEPT
-A FORWARD -i eth0 -o eth1 -j ACCEPT
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
=== [C] router-4 symmetric ===
router mode symmetric
router wan eth1 172.29.19.14
-A POSTROUTING -o eth1 -p udp -j MASQUERADE --random-fully
-A POSTROUTING -o eth1 -p tcp -j MASQUERADE
-A POSTROUTING -o eth1 -p icmp -j MASQUERADE
-A FORWARD -d 10.19.0.0/16 ! -o eth0 -j DROP
-A FORWARD -s 10.19.0.0/16 ! -i eth0 -j DROP
-A FORWARD -i eth0 -o eth1 -j ACCEPT
-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
=== [C] no hairpin and no LAN to LAN forward ===
router-1 wan eth1 dnat_rules_off_wan 0
router-2 wan eth0 dnat_rules_off_wan 0
router-3 wan eth1 dnat_rules_off_wan 0
router-4 wan eth1 dnat_rules_off_wan 0
=== [C] symmetric NAT mapping probe ===
node-y: mapping inner:40000 to 172.29.19.10:5001 seen_as 172.29.19.12:9261
node-y: mapping inner:40000 to 172.29.19.20:5001 seen_as 172.29.19.12:8926
router-2 inner_port 40000 external_ip 172.29.19.12 port_to_coord 9261 port_to_relay 8926
router-2 symmetric true
node-x: mapping inner:40000 to 172.29.19.10:5001 seen_as 172.29.19.11:40000
node-x: mapping inner:40000 to 172.29.19.20:5001 seen_as 172.29.19.11:40000
router-1 inner_port 40000 port_to_coord 40000 port_to_relay 40000
router-1 endpoint_independent true
node-w: mapping inner:40000 to 172.29.19.10:5001 seen_as 172.29.19.14:8656
node-w: mapping inner:40000 to 172.29.19.20:5001 seen_as 172.29.19.14:57802
router-4 inner_port 40000 port_to_coord 8656 port_to_relay 57802
router-4 symmetric true
=== [C] token node-x ===
wrote one enroll token
token_id 3ae187169ae6353c
out /var/lib/orblx/tokens/node-x
=== [C] token node-y ===
wrote one enroll token
token_id 71a99549307beaaa
out /var/lib/orblx/tokens/node-y
=== [C] token node-z ===
wrote one enroll token
token_id 817a513ec995f217
out /var/lib/orblx/tokens/node-z
=== [C] token node-w ===
wrote one enroll token
token_id 19b5655e445b95ba
out /var/lib/orblx/tokens/node-w
=== [C] enroll node-x ===
enrolled
=== [C] enroll node-y ===
enrolled
=== [C] enroll node-z ===
enrolled
=== [C] enroll node-w ===
enrolled
=== [C] overlay addresses ===
overlay node-x 100.64.0.1
overlay node-y 100.64.0.2
overlay node-z 100.64.0.3
overlay node-w 100.64.0.4
=== [C] no shared subnet between nodes ===
node-x: 2: eth0    inet 10.19.1.10/24 brd 10.19.1.255 scope global eth0\       valid_lft forever preferred_lft forever
node-x: default via 10.19.1.2 dev eth0 
node-x: 10.19.1.0/24 dev eth0 proto kernel scope link src 10.19.1.10 
node-y: 2: eth0    inet 10.19.2.10/24 brd 10.19.2.255 scope global eth0\       valid_lft forever preferred_lft forever
node-y: default via 10.19.2.2 dev eth0 
node-y: 10.19.2.0/24 dev eth0 proto kernel scope link src 10.19.2.10 
node-z: 2: eth0    inet 10.19.3.10/24 brd 10.19.3.255 scope global eth0\       valid_lft forever preferred_lft forever
node-z: default via 10.19.3.2 dev eth0 
node-z: 10.19.3.0/24 dev eth0 proto kernel scope link src 10.19.3.10 
node-w: 2: eth0    inet 10.19.4.10/24 brd 10.19.4.255 scope global eth0\       valid_lft forever preferred_lft forever
node-w: default via 10.19.4.2 dev eth0 
node-w: 10.19.4.0/24 dev eth0 proto kernel scope link src 10.19.4.10 
lan_reach 10.19.2.10 no
lan_reach 10.19.3.10 no
lan_reach 10.19.4.10 no
lan_reach 10.19.2.2 no
lan_reach 10.19.3.2 no
lan_shortcut false
=== [C] case 1 cone to cone ===
peer node-z overlay_ip 100.64.0.3 path direct svid spiffe://orblx.local/node/node-z svid_expiry unknown
3 packets transmitted, 3 received, 0% packet loss, time 401ms
case1 path direct
=== [C] case 2 cone to symmetric ===
peer node-y overlay_ip 100.64.0.2 path direct svid spiffe://orblx.local/node/node-y svid_expiry unknown
3 packets transmitted, 3 received, 0% packet loss, time 401ms
case2 path direct
=== [C] case 2 direct path evidence ===
node-x: The candidate for node-y is 172.29.19.12:77.
node-x: The hole punch reached 172.29.19.12:486.
node-x: The reflexive endpoint is 172.29.19.11:443.
node-y: The candidate for node-x is 172.29.19.11:443.
node-y: The hole punch reached 172.29.19.11:443.
node-y: The reflexive endpoint is 172.29.19.12:77.
case2 node-x punch_peer 172.29.19.12:486
case2 node-y punch_peer 172.29.19.11:443
=== [C] case 3 block direct UDP ===
=== [C] drop UDP between the cone routers ===
peer node-z overlay_ip 100.64.0.3 path relay svid spiffe://orblx.local/node/node-z svid_expiry unknown
=== [C] restore UDP between the cone routers ===
peer node-z overlay_ip 100.64.0.3 path direct svid spiffe://orblx.local/node/node-z svid_expiry unknown
case3 path relay
case3 return direct
=== [C] ping gap at each path switch ===
ping_summary 50 packets transmitted, 47 received, 6% packet loss, time 9829ms
ping_replies 47
case3 switch1 from direct to relay detect_ms 1395 max_gap_ms 556
case3 switch2 from relay to direct detect_ms 423 max_gap_ms 250
case3 max_gap_ms_all 556
=== [C] case 5 symmetric to symmetric ===
peer node-w overlay_ip 100.64.0.4 path relay svid spiffe://orblx.local/node/node-w svid_expiry unknown
peer node-w overlay_ip 100.64.0.4 path relay svid spiffe://orblx.local/node/node-w svid_expiry unknown
peer node-y overlay_ip 100.64.0.2 path relay svid spiffe://orblx.local/node/node-y svid_expiry unknown
3 packets transmitted, 3 received, 0% packet loss, time 401ms
node-y: The candidate for node-w is 172.29.19.14:455.
node-y: The direct attempt ended. The node can use the relay.
node-y: The reflexive endpoint is 172.29.19.12:77.
node-y: The relay transport is udp.
node-w: The candidate for node-y is 172.29.19.12:77.
node-w: The direct attempt ended. The node can use the relay.
node-w: The reflexive endpoint is 172.29.19.14:455.
node-w: The relay transport is udp.
case5 path relay relay
=== [C] case 4 tampered candidate ===
The candidate signature for node-a was rejected.
The candidate signature was rejected.
case4 rejected true
case1 path direct
case2 path direct
case3 path relay
case3 return direct
case4 rejected true
case5 path relay
router-2 port_to_coord 9261 port_to_relay 8926
proof_ok
```

The router mapping probe shows that router-2 is symmetric.
One inner port got port 9261 toward the coordinator and port 8926 toward the Relay.
Router-4 also changed the port.
Router-1 kept port 40000 for both destinations.

Case 1 is cone to cone.
The path is direct.

Case 2 is cone to symmetric.
The path is direct.
The signed candidate for node Y is `172.29.19.12:77`, from the STUN flow.
The punch reached node Y at `172.29.19.12:486`, a new port on the same IP.
Node Y reached the WAN address of router-1, `172.29.19.11:443`.
The section "Why cone to symmetric is direct" explains this result.

Case 3 drops UDP between the two cone routers while `ping -i 0.2` runs.
The path moves to relay, then returns to direct after the drop rules are removed.
The proof records the longest gap between ping replies at each switch.
The direct to relay switch had a longest gap of 556 ms.
The relay to direct switch had a longest gap of 250 ms.
Each gap is under 1 second.
The ping lost 3 of 50 packets during the direct to relay switch.
The proof stops when a switch gap is longer than 1 second or the path does not return to direct.

Case 4 rejects a tampered candidate.
The unit test prints the same rejection line.
The [C] check runs `orblx nat verify-candidate` with a bad signature.

Case 5 is symmetric to symmetric.
The direct attempt ended on both nodes, and both nodes use the Relay over UDP.
The ping through the Relay passed.
The proof stops when case 5 reports a direct path or a hole punch.
