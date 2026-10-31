# W18 Linux node daemon

The product name is Orblx.
One Linux process holds one orblx-quic session for each peer.
L3 is the primary path.
The CLI commands are `orblx up`, `orblx down`, and `orblx status`.
The default state directory is `/var/lib/orblx`.
The flag `--state-dir` selects another directory.
The file `node.json` in that directory stores the node name and the overlay IP.
A later start reads that file.
A netmap overlay IP that differs from the stored IP is an error.
The process keeps the stored IP.
`orblx status` prints each peer, the path kind, and the SVID expiry.
The path kind is `direct` when the session received a frame in the last 2 seconds.
The path kind is `stale` when the session is up and that frame is older.
The path kind is `down` when the session is down.
A coordinator address in `--coord` or in `coord-addr` makes the node renew the SVID at two thirds of the certificate life.
The router sends each outbound TUN packet to the peer that owns the destination overlay IP.
The TUN device name is `orblx0`.
The systemd unit is `scripts/orblxd.service`.

## Docker proof

The proof uses three Linux containers on one bridge.
The image file is `scripts/proof/Dockerfile`.
The image name is `orblx-w18:local`.
The base image is `ubuntu:24.04`.
The compose file is `scripts/proof/compose.w18.yml`.
The compose project name is `orblx-w18`.
Each service has `cap_add: NET_ADMIN`.
Each service has the device `/dev/net/tun`.
Each service runs `orblx up` from its netmap.
The bridge subnet is `172.28.18.0/24`.
The gateway is `172.28.18.1`.

| Node | Overlay IP | Bridge address | Published UDP port |
| --- | --- | --- | --- |
| a | 100.64.0.1 | 172.28.18.11 | 4431 |
| b | 100.64.0.2 | 172.28.18.12 | 4432 |
| c | 100.64.0.3 | 172.28.18.13 | 4433 |

The command is:

```
sudo ./scripts/proof/w18-linux-daemon.sh
```

The script exits 0 when the user is not root.
The script exits 0 when Docker is absent.
The CI workflow runs fmt, clippy, and the workspace tests.
The proof script is a root command on a Docker host.
The script builds `target/debug/orblx` when that file is absent.
The script uses `cargo` and `rustc` from `PATH`.
The script stops when `rustc` is older than the crate MSRV in `Cargo.toml`.
The script issues node material for a, b, and c.
The script writes one netmap for each node.
The script starts the compose project.
Each node pings the other two overlay addresses.
The script then restarts `node-b`.
The script checks the overlay IP in `orblx status`, in `node.json`, and on `orblx0`.

### systemd unit and `orblx down` (W25-54, row 54)

The compose service `node-s` has the profile `systemd`.
The default `up` does not start it.
`node-s` runs `/lib/systemd/systemd` as PID 1 (`privileged`, `cgroup: private`, `/run` and `/run/lock` on tmpfs).
The proof mounts `scripts/orblxd.service` at `/etc/systemd/system/orblxd.service`.
Node s has overlay IP `100.64.0.4` and bridge address `172.28.18.14`.
Node s has the peers a and b. Node a also has the peer s.
After the restart check of `node-b`, the script does these steps in node s:

1. Wait until `systemctl is-system-running` is `running` or `degraded`. Check that PID 1 is `systemd`.
2. `systemctl start orblxd`. Check that the unit is `active`, that a has a direct path to s, and that s and a ping each other.
3. `systemctl stop orblxd`. Check the stop gates.
4. `systemctl start orblxd`, then `systemctl restart orblxd`. Check that `MainPID` changed and do the start checks again.
5. `orblx down --state-dir /var/lib/orblx` while the unit runs. Wait 6 s (3 times `RestartSec`).
   Read `NRestarts`. A change prints `down_triggers_restart_on_failure yes` and the proof fails.
   Then check the stop gates.
6. `systemctl start orblxd` and the start checks, then `systemctl stop orblxd` and the stop gates.

The stop gates are: `ActiveState` is `inactive` (not `failed`), `Result` is `success`,
no `orblx0` link, and no socket on UDP 443.
The script prints `systemd_unit_proof passed`.

The script writes an env file and prints `env_file`.
A new shell passes that file to Compose.

```
docker compose --env-file ENV_FILE -f scripts/proof/compose.w18.yml exec node-a orblx status
docker compose --env-file ENV_FILE -f scripts/proof/compose.w18.yml down
```

`ENV_FILE` is the printed path.
Without the env file, Compose has no `W18_*` values.
`exec` and `down` then fail.

The shared TUN poll is 50 ms.
A ping RTT near 50 ms or near 100 ms is the expected result.

## Result

This host ran `sudo ./scripts/proof/w18-linux-daemon.sh`.
The script built the image `orblx-w18:local` and then printed these lines:

```
W18 Linux daemon proof
image orblx-w18:local
node a overlay 100.64.0.1 underlay 172.28.18.11
node b overlay 100.64.0.2 underlay 172.28.18.12
node c overlay 100.64.0.3 underlay 172.28.18.13
---- status a ----
state up
name a
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/a
svid_expiry 1793276982
peer b overlay_ip 100.64.0.2 path direct svid spiffe://orblx.local/node/b svid_expiry 1793276982
peer c overlay_ip 100.64.0.3 path direct svid spiffe://orblx.local/node/c svid_expiry 1793276982
---- status b ----
state up
name b
overlay_ip 100.64.0.2
svid spiffe://orblx.local/node/b
svid_expiry 1793276982
peer a overlay_ip 100.64.0.1 path direct svid spiffe://orblx.local/node/a svid_expiry 1793276982
peer c overlay_ip 100.64.0.3 path direct svid spiffe://orblx.local/node/c svid_expiry 1793276982
---- status c ----
state up
name c
overlay_ip 100.64.0.3
svid spiffe://orblx.local/node/c
svid_expiry 1793276982
peer a overlay_ip 100.64.0.1 path direct svid spiffe://orblx.local/node/a svid_expiry 1793276982
peer b overlay_ip 100.64.0.2 path direct svid spiffe://orblx.local/node/b svid_expiry 1793276982
---- ping ----
PING 100.64.0.2 (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=100 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=100 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=100 ms

--- 100.64.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 100.277/100.378/100.472/0.079 ms
node-a to 100.64.0.2 ok
PING 100.64.0.3 (100.64.0.3) 56(84) bytes of data.
64 bytes from 100.64.0.3: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.3: icmp_seq=2 ttl=127 time=50.3 ms
64 bytes from 100.64.0.3: icmp_seq=3 ttl=127 time=50.3 ms

--- 100.64.0.3 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.173/50.249/50.310/0.057 ms
node-a to 100.64.0.3 ok
PING 100.64.0.1 (100.64.0.1) 56(84) bytes of data.
64 bytes from 100.64.0.1: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.1: icmp_seq=2 ttl=127 time=50.4 ms
64 bytes from 100.64.0.1: icmp_seq=3 ttl=127 time=50.5 ms

--- 100.64.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 50.199/50.354/50.509/0.126 ms
node-b to 100.64.0.1 ok
PING 100.64.0.3 (100.64.0.3) 56(84) bytes of data.
64 bytes from 100.64.0.3: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.3: icmp_seq=2 ttl=127 time=50.4 ms
64 bytes from 100.64.0.3: icmp_seq=3 ttl=127 time=50.4 ms

--- 100.64.0.3 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.185/50.322/50.412/0.098 ms
node-b to 100.64.0.3 ok
PING 100.64.0.1 (100.64.0.1) 56(84) bytes of data.
64 bytes from 100.64.0.1: icmp_seq=1 ttl=127 time=50.1 ms
64 bytes from 100.64.0.1: icmp_seq=2 ttl=127 time=50.3 ms
64 bytes from 100.64.0.1: icmp_seq=3 ttl=127 time=50.3 ms

--- 100.64.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.135/50.246/50.323/0.080 ms
node-c to 100.64.0.1 ok
PING 100.64.0.2 (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.3 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.4 ms

--- 100.64.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.240/50.298/50.366/0.051 ms
node-c to 100.64.0.2 ok
---- restart b ----
overlay_ip_before 100.64.0.2
node_json_before 100.64.0.2
 Container orblx-w18-node-b-1  Restarting
 Container orblx-w18-node-b-1  Started
---- status b after restart ----
state up
name b
overlay_ip 100.64.0.2
svid spiffe://orblx.local/node/b
svid_expiry 1793276982
peer a overlay_ip 100.64.0.1 path direct svid spiffe://orblx.local/node/a svid_expiry 1793276982
peer c overlay_ip 100.64.0.3 path direct svid spiffe://orblx.local/node/c svid_expiry 1793276982
overlay_ip_after 100.64.0.2
node_json_after 100.64.0.2
tun_address_after 100.64.0.2/32
restart_same_ip true
---- ping after restart ----
PING 100.64.0.2 (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.3 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.3 ms

--- 100.64.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.212/50.258/50.310/0.040 ms
node-a to 100.64.0.2 ok
PING 100.64.0.1 (100.64.0.1) 56(84) bytes of data.
64 bytes from 100.64.0.1: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.1: icmp_seq=2 ttl=127 time=50.4 ms
64 bytes from 100.64.0.1: icmp_seq=3 ttl=127 time=50.3 ms

--- 100.64.0.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 50.179/50.292/50.431/0.104 ms
node-b to 100.64.0.1 ok
PING 100.64.0.3 (100.64.0.3) 56(84) bytes of data.
64 bytes from 100.64.0.3: icmp_seq=1 ttl=127 time=100 ms
64 bytes from 100.64.0.3: icmp_seq=2 ttl=127 time=100 ms
64 bytes from 100.64.0.3: icmp_seq=3 ttl=127 time=100 ms

--- 100.64.0.3 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2002ms
rtt min/avg/max/mdev = 100.226/100.376/100.481/0.109 ms
node-b to 100.64.0.3 ok
PING 100.64.0.2 (100.64.0.2) 56(84) bytes of data.
64 bytes from 100.64.0.2: icmp_seq=1 ttl=127 time=50.2 ms
64 bytes from 100.64.0.2: icmp_seq=2 ttl=127 time=50.3 ms
64 bytes from 100.64.0.2: icmp_seq=3 ttl=127 time=50.3 ms

--- 100.64.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 50.153/50.258/50.322/0.074 ms
node-c to 100.64.0.2 ok
W18 proof passed
```

Every ping pair sent 3 packets and received 3 packets.
The loss is 0%.
After the restart, node b kept overlay IP `100.64.0.2`.
`node.json` kept `100.64.0.2`.
The TUN address stayed `100.64.0.2/32`.
The script printed `restart_same_ip true`.
The script printed `W18 proof passed`.

### Result: systemd unit and `orblx down` (W25-54)

Run on 2026-10-31 KST, branch `w25-54-systemd-down` at `adc15970`, log
`/workspace/orblx-w18-proof/w25t-w18-systemd-adc15970.log`. The proof held the lock 70 s.

| Step | ActiveState | Result | NRestarts | MainPID | orblx0 links | UDP 443 sockets | ping s and a |
| --- | --- | --- | --- | --- | --- | --- | --- |
| boot | inactive | success | 0 | 0 | 0 | 0 | not run |
| start | active | success | 0 | 163 | not read | not read | ok |
| stop | inactive | success | 0 | 0 | 0 | 0 | not run |
| start again | active | success | 0 | 271 | not read | not read | ok |
| restart | active | success | 0 | 337 | not read | not read | ok |
| `orblx down` | inactive | success | 0 | 0 | 0 | 0 | not run |
| start after down | active | success | 0 | 460 | not read | not read | ok |
| final stop | inactive | success | 0 | 0 | 0 | 0 | not run |

`systemd_state` was `running`. PID 1 was `systemd`.
`orblx down` took 412 ms. After it, `orblx status` printed `state down`.
`orblx down` does not trigger `Restart=on-failure`: `NRestarts` stayed 0 and the unit stayed `inactive`.
The reason: `orblx down` sends SIGTERM, and the node exits 0 (`ExecMainStatus=0`).
systemd counts that exit as clean.

## Host note

The compose file sets `net.ipv4.conf.all.rp_filter=0` and `net.ipv4.conf.default.rp_filter=0`.
The new TUN device inherits that value.
Inside the container, `/proc/sys` is read-only, so the node log can report a failed write of `orblx0` rp_filter.
The node continues when those defaults are already 0.

On this VM, container-to-container ICMP needed these host settings before the proof:

```
sysctl -w net.bridge.bridge-nf-call-iptables=0
sysctl -w net.bridge.bridge-nf-call-ip6tables=0
```

A normal Docker host forwards that ICMP with the default bridge settings.
The proof script leaves those sysctls unchanged.

## Real-host proof

Use one real Mac, one real Linux host, and the three containers on that Linux host.
The containers are extra Linux nodes.
The Linux host also runs one native node.
Linux opens the TUN device `orblx0`.
macOS opens a utun device.
The kernel chooses the utun name.
`orblx up` prints that name.
The Mac command is the same `orblx up`.
The utun details are in `docs/w18-macos.md`.

Set `LINUX_LAN` to the Linux host address on the LAN.
Set `MAC_LAN` to the Mac address on the LAN.
Allow UDP 443, 4431, 4432, and 4433 on the Linux host from the Mac.
Allow UDP 443 on the Mac from the Linux host.

Issue one shared lab on the Linux host.
The SVID life and the ticket life are 15 minutes.
This lab has no coordinator address.
Run `orblx node-issue` again after that life ends.
A node with a coordinator address renews the SVID without `node-issue`.
Copy the `mac` directory to the Mac.
Leave `key.pem` and `ticket-mac.key` unread on the terminal.

```
cargo build -p orblx-cli --bin orblx
sudo install -m 755 target/debug/orblx /usr/local/bin/orblx
sudo mkdir -p /var/lib/orblx-lab
sudo /usr/local/bin/orblx node-issue \
  --out /var/lib/orblx-lab \
  --node a=100.64.0.1 \
  --node b=100.64.0.2 \
  --node c=100.64.0.3 \
  --node host=100.64.0.4 \
  --node mac=100.64.0.5
```

Each node has its own netmap.
The endpoints in that file are the addresses that node can reach.
The node with the smaller name dials.
The node with the larger name accepts.
The name order here is `a`, `b`, `c`, `host`, `mac`.

Write `/var/lib/orblx-lab/netmap-a.json`:

```json
{
  "version": 1,
  "self": {"name": "a", "overlay_ip": "100.64.0.1"},
  "peers": [
    {"name": "b", "overlay_ip": "100.64.0.2", "svid": "spiffe://orblx.local/node/b", "endpoints": ["172.28.18.12:443"], "routes": ["100.64.0.2/32"]},
    {"name": "c", "overlay_ip": "100.64.0.3", "svid": "spiffe://orblx.local/node/c", "endpoints": ["172.28.18.13:443"], "routes": ["100.64.0.3/32"]},
    {"name": "host", "overlay_ip": "100.64.0.4", "svid": "spiffe://orblx.local/node/host", "endpoints": ["172.28.18.1:443"], "routes": ["100.64.0.4/32"]},
    {"name": "mac", "overlay_ip": "100.64.0.5", "svid": "spiffe://orblx.local/node/mac", "endpoints": ["MAC_LAN:443"], "routes": ["100.64.0.5/32"]}
  ]
}
```

Replace `MAC_LAN` with the Mac LAN address.
Write `netmap-b.json` and `netmap-c.json` the same way.
Node b uses bridge addresses `172.28.18.11` for a and `172.28.18.13` for c.
Node c uses bridge addresses `172.28.18.11` for a and `172.28.18.12` for b.
Both use `172.28.18.1:443` for host and `MAC_LAN:443` for mac.

Write `/var/lib/orblx-lab/netmap-host.json` with self `host` / `100.64.0.4`.
The host reaches the containers on the bridge:

| Peer | Endpoint |
| --- | --- |
| a | 172.28.18.11:443 |
| b | 172.28.18.12:443 |
| c | 172.28.18.13:443 |
| mac | MAC_LAN:443 |

Write `netmap-mac.json` on the Mac with self `mac` / `100.64.0.5`.
The Mac uses the published ports:

| Peer | Endpoint |
| --- | --- |
| a | LINUX_LAN:4431 |
| b | LINUX_LAN:4432 |
| c | LINUX_LAN:4433 |
| host | LINUX_LAN:443 |

Start the containers from the Linux host with the commands below.
The proof script writes netmaps for a, b, and c only.

```
sudo install -d -m 755 /var/lib/orblx /etc/orblx
sudo cp -a /var/lib/orblx-lab/host/. /var/lib/orblx/
sudo cp /var/lib/orblx-lab/netmap-host.json /etc/orblx/netmap.json
sudo tee /etc/orblx/w18.env >/dev/null <<'EOF'
W18_STATE_A=/var/lib/orblx-lab/a
W18_STATE_B=/var/lib/orblx-lab/b
W18_STATE_C=/var/lib/orblx-lab/c
W18_NETMAP_A=/var/lib/orblx-lab/netmap-a.json
W18_NETMAP_B=/var/lib/orblx-lab/netmap-b.json
W18_NETMAP_C=/var/lib/orblx-lab/netmap-c.json
EOF
set -a
source /etc/orblx/w18.env
set +a
image_dir=$(mktemp -d)
cp target/debug/orblx "$image_dir/orblx"
cp scripts/proof/Dockerfile "$image_dir/Dockerfile"
docker build -t orblx-w18:local "$image_dir"
sudo docker compose --env-file /etc/orblx/w18.env -f scripts/proof/compose.w18.yml up -d
sudo install -m 644 scripts/orblxd.service /etc/systemd/system/orblxd.service
sudo systemctl daemon-reload
sudo systemctl enable --now orblxd
```

The unit runs `/usr/local/bin/orblx up --netmap /etc/orblx/netmap.json --state-dir /var/lib/orblx`.
The unit stops the node with `orblx down`.
The manual command is the same `orblx up` line.

On the Mac, run the same command as root.
The state directory default is `/var/lib/orblx`.
When `--netmap` is absent, the file is `/var/lib/orblx/netmap.json`.
`scripts/dev.orblx.plist` runs `orblx up` with that default.

```
sudo orblx up --netmap netmap-mac.json --state-dir /var/lib/orblx --listen 0.0.0.0:443
ifconfig | grep 100.64.0.5
```

The `ifconfig` line shows `100.64.0.5` on a `utun` interface.

Check the Linux host:

```
sudo orblx status --state-dir /var/lib/orblx
ping -c 3 100.64.0.1
ping -c 3 100.64.0.2
ping -c 3 100.64.0.3
```

Check one container:

```
sudo docker compose --env-file /etc/orblx/w18.env -f scripts/proof/compose.w18.yml exec node-a ping -c 3 100.64.0.2
sudo docker compose --env-file /etc/orblx/w18.env -f scripts/proof/compose.w18.yml exec node-a ping -c 3 100.64.0.4
```

Restart one container and read the same overlay IP:

```
sudo docker compose --env-file /etc/orblx/w18.env -f scripts/proof/compose.w18.yml restart node-b
sudo docker compose --env-file /etc/orblx/w18.env -f scripts/proof/compose.w18.yml exec node-b orblx status
sudo docker compose --env-file /etc/orblx/w18.env -f scripts/proof/compose.w18.yml exec node-b ip -4 -o addr show dev orblx0
```

`orblx status` prints `overlay_ip 100.64.0.2`.
The TUN line prints `100.64.0.2/32`.
`/var/lib/orblx-lab/b/node.json` still contains `100.64.0.2`.

Stop the containers from a new shell:

```
sudo docker compose --env-file /etc/orblx/w18.env -f scripts/proof/compose.w18.yml down
```
