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
`is_visible` allows every peer.
`AllowPeers` uses that function.
W18-5 can replace `AllowPeers`.
A peer that the hook denies gets NXDOMAIN for the short name and the full name.
The response does not contain the overlay address.

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

The proof extends the W18-1 harness.
The image file is `scripts/proof/Dockerfile`.
The image name is `orblx-w18:local`.
The compose file is `scripts/proof/compose.w18.yml`.
The script is `scripts/proof/w18-names.sh`.
The owner in this proof is `lab`.
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
The script built the image, then printed these lines:

```text
W18 overlay name proof
image orblx-w18:local
owner lab
node a overlay 100.64.0.1 name a.lab.orblx
node b overlay 100.64.0.2 name b.lab.orblx
node c overlay 100.64.0.3 name c.lab.orblx
---- resolvectl domain node-a ----
Link 3 (orblx0): ~orblx lab.orblx
---- resolvectl dns node-a ----
Link 3 (orblx0): 100.64.0.1
---- ping ----
PING b.lab.orblx (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.3 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.4 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.4 ms

--- b.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.306/50.359/50.416/0.044 ms
node-a to b ok
PING b.lab.orblx (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.3 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.2 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.4 ms

--- b.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.230/50.299/50.371/0.057 ms
node-a to b.lab.orblx ok
PING c.lab.orblx (100.64.0.3) 56(84) bytes of data.
64 bytes from 100.64.0.3: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.3: icmp_seq=2 ttl=127 time=50.3 ms
64 bytes from 100.64.0.3: icmp_seq=3 ttl=127 time=50.3 ms

--- c.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.153/50.268/50.345/0.083 ms
node-a to c ok
PING c.lab.orblx (100.64.0.3) 56(84) bytes of data.
64 bytes from 100.64.0.3: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.3: icmp_seq=2 ttl=127 time=50.2 ms
64 bytes from 100.64.0.3: icmp_seq=3 ttl=127 time=50.4 ms

--- c.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.161/50.242/50.403/0.113 ms
node-a to c.lab.orblx ok
PING a.lab.orblx (100.64.0.1) 56(84) bytes of data.
64 bytes from 100.64.0.1: icmp_seq=1 ttl=127 time=101 ms
64 bytes from 100.64.0.1: icmp_seq=2 ttl=127 time=100 ms
64 bytes from 100.64.0.1: icmp_seq=3 ttl=127 time=101 ms

--- a.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 100.446/100.512/100.580/0.054 ms
node-b to a ok
PING a.lab.orblx (100.64.0.1) 56(84) bytes of data.
64 bytes from 100.64.0.1: icmp_seq=1 ttl=127 time=50.1 ms
64 bytes from 100.64.0.1: icmp_seq=2 ttl=127 time=50.4 ms
64 bytes from 100.64.0.1: icmp_seq=3 ttl=127 time=50.5 ms

--- a.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.148/50.345/50.515/0.151 ms
node-b to a.lab.orblx ok
PING b.lab.orblx (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=100 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=100 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=101 ms

--- b.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 100.273/100.423/100.508/0.106 ms
node-c to b ok
PING b.lab.orblx (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.5 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.4 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.5 ms

--- b.lab.orblx ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2001ms
rtt min/avg/max/mdev = 50.439/50.478/50.523/0.034 ms
node-c to b.lab.orblx ok
---- http ----
---- curl node-a http://b.lab.orblx:8080/orblx-name.txt ----
ok
node-a to http://b.lab.orblx:8080/orblx-name.txt ok
---- curl node-b http://a.lab.orblx:8080/orblx-name.txt ----
ok
node-b to http://a.lab.orblx:8080/orblx-name.txt ok
---- curl node-a http://c.lab.orblx:8080/orblx-name.txt ----
ok
node-a to http://c.lab.orblx:8080/orblx-name.txt ok
proof_ok
```

`ping b` from node-a uses the search domain `lab.orblx`.
The printed name is `b.lab.orblx`.
The address is `100.64.0.2`.
`curl http://b.lab.orblx:8080/orblx-name.txt` returns `ok`.
The shared TUN poll is 50 ms.
A ping RTT near 50 ms or near 100 ms is the expected result.

## macOS check

Run these commands on a Mac after `orblx up`.
This host is Linux.
This file does not contain Mac output.
Use a netmap whose owner is `lab` and whose peer name is `b`.
Replace the names when the netmap uses other values.

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
