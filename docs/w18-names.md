# W18 overlay names

The product name is Orblx.
Each node answers DNS for the current netmap.
The full name is `<node>.<owner>.orblx`.
The short name is `<node>`.
The A record is the overlay IPv4 address.
A name outside the netmap goes to the system resolver.
A name under `.orblx` that is not in the netmap is NXDOMAIN.
The node does not forward that name.

The optional netmap field is `owner`.
An empty owner omits `<node>.<owner>.orblx`.
The short name remains.
The coordinator leaves `owner` empty.
The signed netmap JSON stays the same when `owner` is empty.

The responder listens on the node overlay address at UDP port 53.
The node reads the netmap file again when the file changes.
The answers follow the new netmap.
The running node name and the running overlay address must stay the same.

`PeerVisibility::is_visible` is the visibility hook.
The node reads `grants.signed.json` from the state directory.
That file is the signed grant document that arrives with the signed netmap.
The node checks the signature with `netmap.pub`.
The node does not read the HuJSON policy file.
`reach` on that document lists the peers this node may reach.
`GrantPeers` uses that list.
A peer absent from `reach` is NXDOMAIN for the short name and for `<node>.<owner>.orblx`.
The response does not contain the overlay address.
A missing `grants.signed.json` uses `AllowPeers`.
`AllowPeers` allows every peer.

On Linux the node runs `resolvectl` on the TUN device `orblx0`.
The DNS server is the overlay address.
The per-link domain list starts with `~orblx`.
Each visible owner adds the search domain `<owner>.orblx`.
The link is not a default route.
Other names stay on the system resolver.
When `resolvectl` is not available, the node logs a warning and continues.
`orblx down` reverts the link.

On macOS the node writes `/etc/resolver/orblx`.
The file names the overlay address.
`orblx down` removes that file.

L3 stays on the existing QUIC path.
This path does not use WireGuard.
This path does not use Headscale.
This path does not use DERP.

## Docker proof

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs the script |
| `node-a` container | [C] | Node `a`. Overlay `100.64.0.1` |
| `node-b` container | [C] | Node `b`. Overlay `100.64.0.2` |
| `node-c` container | [C] | Node `c`. Overlay `100.64.0.3` |
| Mac | REAL | Operator leg. The steps are at the end of this file |

The proof extends the W18-1 harness.
The image file is `scripts/proof/Dockerfile`.
The image name is `orblx-w18:local`.
The compose file is `scripts/proof/compose.w18.yml`.
The script is `scripts/proof/w18-names.sh`.
The policy file is `scripts/proof/w18-names.hujson`.
The owner in this proof is `lab`.
The policy allows `a` to reach `b` on TCP port 8080.
The policy denies `a` to `c`.
`node-issue --policy` writes `grants.signed.json` for each node.
Each node serves `ok` from `http://<overlay>:8080/orblx-name.txt`.

The command is:

```bash
sudo ./scripts/proof/w18-names.sh
```

The script exits 0 when the user is not root.
The script exits 0 when Docker is absent.
The script sets `iptables-legacy` FORWARD to ACCEPT when that policy is DROP and the nft policy is ACCEPT.
That DROP discards UDP on a user-defined bridge.
This run already had ACCEPT, so the script did not print that line.
The script built the image.
`node-issue` wrote signed grants.
Node a can reach 1 peer.
Node b can reach 2 peers.
Node c can reach 1 peer.
The script then printed these lines:

```text
=== REAL W18 overlay name proof ===
image orblx-w18:local
owner lab
policy deny a to c
node a overlay 100.64.0.1 name a.lab.orblx
node b overlay 100.64.0.2 name b.lab.orblx
node c overlay 100.64.0.3 name c.lab.orblx
---- [C] resolvectl domain node-a ----
Link 3 (orblx0): ~orblx lab.orblx
---- [C] resolvectl dns node-a ----
Link 3 (orblx0): 100.64.0.1
---- [C] ping ----
PING b.lab.orblx (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.5 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.4 ms

--- b.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 50.192/50.355/50.474/0.119 ms
[C] node-a to b ok
PING b.lab.orblx (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.4 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.4 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.3 ms

--- b.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.348/50.363/50.388/0.017 ms
[C] node-a to b.lab.orblx ok
---- [C] dns node-a c ----
c rcode 3 answers 0
[C] node-a c nxdomain
---- [C] dns node-a c.lab.orblx ----
c.lab.orblx rcode 3 answers 0
[C] node-a c.lab.orblx nxdomain
---- [C] resolvectl query node-a c.lab.orblx ----
c.lab.orblx: Name 'c.lab.orblx' not found
PING a.lab.orblx (100.64.0.1) 56(84) bytes of data.
64 bytes from 100.64.0.1: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.1: icmp_seq=2 ttl=127 time=50.4 ms
64 bytes from 100.64.0.1: icmp_seq=3 ttl=127 time=50.4 ms

--- a.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.213/50.329/50.396/0.082 ms
[C] node-b to a ok
PING a.lab.orblx (100.64.0.1) 56(84) bytes of data.
64 bytes from 100.64.0.1: icmp_seq=1 ttl=127 time=100 ms
64 bytes from 100.64.0.1: icmp_seq=2 ttl=127 time=100 ms
64 bytes from 100.64.0.1: icmp_seq=3 ttl=127 time=100 ms

--- a.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2001ms
rtt min/avg/max/mdev = 100.286/100.401/100.464/0.081 ms
[C] node-b to a.lab.orblx ok
PING b.lab.orblx (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.3 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.4 ms

--- b.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.184/50.308/50.414/0.094 ms
[C] node-c to b ok
PING b.lab.orblx (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.3 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.5 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.5 ms

--- b.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.264/50.413/50.494/0.105 ms
[C] node-c to b.lab.orblx ok
---- [C] http ----
---- [C] curl node-a http://b.lab.orblx:8080/orblx-name.txt ----
ok
[C] node-a to http://b.lab.orblx:8080/orblx-name.txt ok
---- [C] curl node-b http://a.lab.orblx:8080/orblx-name.txt ----
ok
[C] node-b to http://a.lab.orblx:8080/orblx-name.txt ok
proof_ok
```

`rcode 3` is NXDOMAIN.
The query goes to the overlay DNS responder on node a.
`c` and `c.lab.orblx` have no A record.
`ping b` from node-a uses the search domain `lab.orblx`.
The printed name is `b.lab.orblx`.
The address is `100.64.0.2`.
`curl http://b.lab.orblx:8080/orblx-name.txt` returns `ok`.
The shared TUN poll is 50 ms.
A ping RTT near 50 ms or near 100 ms is the expected result.

## macOS check

Run these commands on a REAL Mac after `orblx up`.
This host is Linux.
This file does not contain Mac output.
Use a netmap whose owner is `lab` and whose peer name is `b`.
Replace the names when the netmap uses other values.
A peer absent from the signed `reach` list is NXDOMAIN on the Mac as well.

```bash
sudo orblx up
cat /etc/resolver/orblx
ping -c 3 b
ping -c 3 b.lab.orblx
curl -fsS http://b.lab.orblx:8080/orblx-name.txt
sudo orblx down
test ! -e /etc/resolver/orblx && echo resolver_removed
```

`orblx up` writes `/etc/resolver/orblx`.
The file contains `nameserver` and the overlay address.
`orblx down` removes `/etc/resolver/orblx`.
