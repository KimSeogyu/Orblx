# Subnet routes

A node advertises one or more IPv4 CIDRs.
The coordinator stores every advertised CIDR.
The coordinator copies a CIDR into the signed netmap only after the HuJSON policy approves it.
`autoApprovers.routes` approves a prefix and a longer prefix inside it.
`routeApprovals` approves one exact CIDR for one source.
A route with no matching rule stays out of the signed netmap.
`0.0.0.0/0` is an exit route.
The coordinator rejects that prefix.

A client installs an approved subnet route when it runs `orblx up --accept-routes`.
The client always installs the overlay `/32` routes.
Internet traffic stays on the host route.
The router forwards an approved LAN prefix with Linux kernel forwarding and `iptables` MASQUERADE.
The node sets `net.ipv4.ip_forward` to 1.
The node adds a POSTROUTING MASQUERADE rule for packets from `100.64.0.0/10` that leave the connected LAN interface toward that CIDR.
Conntrack restores the return packet and the kernel sends it into the TUN device.
The node then sends the packet to the overlay peer.
This build does not use a userspace NAT.

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` container | [C] | Coordinator. UDP 443. Policy file mount |
| `router` container | [C] | Subnet router. Overlay and LAN |
| `client` container | [C] | Client. `--accept-routes` |
| `lan` container | [C] | LAN device. No Orblx process |
| Mac | REAL | Operator leg. Steps are at the end of this file |

The image is `orblx-subnet:local`.
The proof script is `scripts/proof/subnet.sh`.
The Compose file is `scripts/proof/compose.subnet.yml`.
The policy file in the proof is `scripts/proof/subnet.hujson`.

The proof network is `172.30.18.0/24`.
The LAN network is `10.88.0.0/24`.
The LAN device address is `10.88.0.5`.
The router LAN address is `10.88.0.2`.
The router advertises `10.88.0.0/24` and `10.99.0.0/24`.
The policy approves only `10.88.0.0/24` for `tag:router`.

The node daemon still needs a capability ticket.
Coordinator enrollment does not mint that ticket.
The script enrolls both nodes, advertises the routes, and copies the signed netmap payload.
`orblx node-issue` then writes the certificate, the key, the trust bundle, and the ticket for those overlay addresses.
`orblx up` reads that state and the coordinator netmap.

The router container is privileged.
It needs a writable `/proc/sys` to set IPv4 forwarding.
On this host, `bridge-nf-call-iptables` is 0.
The masquerade runs in the router network namespace.
The host bridge does not call iptables for those frames.

## Commands

```bash
orblx coord advertise --coord ADDR --bundle FILE --state DIR --route CIDR [--route CIDR]
orblx up --advertise-routes CIDR [--advertise-routes CIDR] [--coord ADDR --bundle FILE]
orblx up --accept-routes [--coord ADDR --bundle FILE]
```

`orblx coord advertise` replaces the advertised set for an enrolled node.
`orblx up --advertise-routes` with `--coord` and `--bundle` does the same call, then starts the node.
The node forwards each approved CIDR that is a connected LAN route.
`orblx up --accept-routes` installs peer subnet routes from the netmap.
A prefix of length 0 is not installed.

## Container proof

Run this command on the REAL Linux host:

```bash
scripts/proof/subnet.sh
```

The script removes the `orblx-subnet-proof` containers at the start.
Run the Mac leg on hosts that you start by hand.
The recorded run used image `orblx-subnet:local`.
The lines below start after the image build.

```text
=== [C] bridge-nf-call-iptables ===
bridge-nf-call-iptables 0
=== [C] policy test ===
allow spiffe://orblx.local/node/client tcp spiffe://orblx.local/node/router 80
deny spiffe://orblx.local/node/client tcp spiffe://orblx.local/node/router 22
policy ok
=== [C] token router ===
wrote one enroll token
token_id 9f7ae328e0b5d31b
expires_unix 1793284805
out /var/lib/orblx/tokens/router
=== [C] token client ===
wrote one enroll token
token_id e247ca2344850a50
expires_unix 1793284805
out /var/lib/orblx/tokens/client
=== [C] enroll router ===
enrolled
name router
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/router
peers 0
=== [C] enroll client ===
enrolled
name client
overlay_ip 100.64.0.2
svid spiffe://orblx.local/node/client
peers 1
=== [C] advertise routes ===
approved route 10.88.0.0/24
held route 10.99.0.0/24
advertised 2
=== [C] netmap on client ===
netmap
name client
overlay_ip 100.64.0.2
peer router 100.64.0.1
endpoints_ok 2
grants 0
=== [C] client netmap routes ===
{"version":1,"self":{"name":"client","overlay_ip":"100.64.0.2"},"peers":[{"name":"router","overlay_ip":"100.64.0.1","svid":"spiffe://orblx.local/node/router","endpoints":["172.30.18.3:443"],"routes":["10.88.0.0/24"]}]}
=== [C] client route table ===
default via 172.30.18.1 dev eth0
10.88.0.0/24 dev orblx0 scope link
100.64.0.1 dev orblx0 scope link
172.30.18.0/24 dev eth0 proto kernel scope link src 172.30.18.4
=== [C] routes on orblx0 ===
10.88.0.0/24 scope link
100.64.0.1 scope link
=== [C] path for 1.1.1.1 ===
1.1.1.1 via 172.30.18.1 dev eth0 src 172.30.18.4 uid 0
    cache
=== [C] ping the LAN device ===
PING 10.88.0.5 (10.88.0.5) 56(84) bytes of data.
64 bytes from 10.88.0.5: icmp_seq=1 ttl=126 time=101 ms
64 bytes from 10.88.0.5: icmp_seq=2 ttl=126 time=100 ms
64 bytes from 10.88.0.5: icmp_seq=3 ttl=126 time=101 ms

--- 10.88.0.5 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 100.461/100.537/100.589/0.055 ms
=== [C] HTTP to the LAN device ===
HTTP/1.1 200 OK
Content-Length: 7

lan-ok
proof_ok
```

`token_id` is the public id of the token.
The secret stays in the token file.
The client netmap contains `10.88.0.0/24`.
The held route `10.99.0.0/24` is absent from that file.
The route table on `orblx0` matches that set.
`ip route get 1.1.1.1` uses `eth0`.
The LAN device has no Orblx process.
Ping and HTTP from the client reach `10.88.0.5` through the router.
The script sets iptables-legacy FORWARD to ACCEPT when that policy is DROP and iptables-nft FORWARD is ACCEPT.
This host already had FORWARD ACCEPT, so that step printed no line.

## Real Mac leg

Eng Lead runs this section.
The container proof above already used a container named `client`.
This section uses the real Mac as the client.
Leave the `client` Compose service stopped.
Do not run these steps from the container proof script.

### REAL Linux host

Start the coordinator with `scripts/proof/subnet.hujson`, or with your own policy that approves one LAN CIDR.

```bash
sudo orblx coord serve --state /var/lib/orblx --listen 0.0.0.0:443 --name coord --policy /var/lib/orblx/policy.hujson
```

Enroll the Linux router with an enroll token.
Advertise the real LAN CIDR and one extra CIDR that the policy does not approve.

```bash
sudo orblx coord advertise \
  --coord COORD:443 \
  --bundle /var/lib/orblx/trust-bundle.pem \
  --state /var/lib/orblx/router \
  --route 192.168.1.0/24 \
  --route 10.99.0.0/24
```

Expect one `approved route` line and one `held route` line.
On the Linux machine that owns the LAN, start the node and forward the approved CIDR.

```bash
sudo orblx up \
  --state-dir /var/lib/orblx/router \
  --advertise-routes 192.168.1.0/24 \
  --listen 0.0.0.0:443
```

The node prints `The node forwards 192.168.1.0/24` when that prefix is a connected route.
Replace `192.168.1.0/24` with the real LAN prefix.

### REAL Mac

Enroll the Mac, or use the node state from the W18-3 setup.
The state directory needs the certificate, the private key, the trust bundle, and the capability ticket.
Fetch the netmap and start the node with `--accept-routes`.

```bash
sudo orblx coord netmap --coord COORD:443 --bundle /var/lib/orblx/bundle.pem --state /var/lib/orblx
sudo orblx up --accept-routes --state-dir /var/lib/orblx
```

Open a page on a LAN device that does not run Orblx.

```bash
curl -fsS "http://192.168.1.10/"
```

Check the route table.

```bash
netstat -rn -f inet | grep utun
route -n get 1.1.1.1
```

The approved LAN prefix uses the utun device.
The held prefix does not appear.
`route -n get 1.1.1.1` does not use the utun device.
