# W18 macOS client

The product name is Orblx.
This document records the macOS utun path.
This pull request does not add the node daemon.
W18-1 adds `gyeol up`.
This path does not use WireGuard.
This path does not use Headscale.
This path does not use DERP.

## What works now

`open_tun` opens a utun device on macOS.
The packet bytes on the bridge are one IPv4 packet.
The 4-byte utun family header stays in `crates/gyeol-datapath/src/tun_macos.rs`.
The process needs root.
A requested interface name must be `utun` plus a number, for example `utun4`.
An empty name lets the kernel choose the utun device.
The control unit for `utunN` is `N + 1`.

The code assigns the overlay IPv4 address.
The utun destination is the same address.
The MTU is 1500.
The code adds one route for the overlay prefix.
The route network is the address masked by the netmask.
The installer runs `/sbin/ifconfig` and `/sbin/route`.
A route that is already present is success.
`RouteInstaller` is the trait for those two calls.
Tests use a recording installer.
The tests do not open a utun device.

`scripts/dev.gyeol.plist` is the launchd unit.
The label is `dev.gyeol`.
The unit runs `/usr/local/bin/gyeol up` as root.
The working directory is `/var/lib/gyeol`.
The unit starts at load.
A non-zero exit starts the process again after 10 seconds.
A zero exit stays down.
Load this unit after W18-1 installs the `gyeol up` command.

CI runs one `macos-latest` job.
That job checks the format, builds the workspace, runs Clippy with warnings denied, and runs the tests.
The Linux job is unchanged.

### Address check on one Mac

This check shows the utun address and the route.
This check does not prove traffic to a second host.
Use the PEM files from the hello-quic example.

```bash
sudo cargo run -p gyeol-cli -- hello-quic server \
  --cert server.pem --key server-key.pem \
  --bundle trust-bundle.pem --ticket ticket.bin \
  --tun-address 100.64.0.2 --tun-netmask 255.255.255.0
```

In a second terminal, run:

```bash
ifconfig | grep 100.64.0.2
netstat -rn -f inet | grep 100.64.0.0
```

The first command shows `100.64.0.2`.
The second command shows `100.64.0.0` and a `utun` interface.

## Real-host proof

Eng Lead runs this proof after W18-1 merges.
This pull request does not contain the command output.
The `gyeol-sim` demo is not this proof.

Use one real Mac and one real Linux host.
The hosts are on different networks.
Do not use `100.64.0.0/24` for another network on either host.

| Host | Overlay address | Netmask |
| --- | --- | --- |
| Linux | 100.64.0.1 | 255.255.255.0 |
| Mac | 100.64.0.2 | 255.255.255.0 |

W18-1 reads peers from a netmap file.
W18-1 stores node state in `/var/lib/gyeol`.
Use the netmap file format from `docs/w18-linux-daemon.md`.
Put both nodes in that file.
The Linux node address is 100.64.0.1.
The Mac node address is 100.64.0.2.

### Linux host

```bash
cargo build --release -p gyeol-cli
sudo install -m 755 target/release/gyeol /usr/local/bin/gyeol
sudo mkdir -p /var/lib/gyeol
```

Copy the W18-1 netmap file into `/var/lib/gyeol` before you start the node.
Start the node with the W18-1 service or with:

```bash
sudo gyeol up
sudo gyeol status
```

`gyeol status` shows the Mac peer.
Find the interface that owns 100.64.0.1:

```bash
ip -4 addr show
```

Allow overlay HTTP and ICMP on that interface. Replace `IFACE` with the interface name:

```bash
sudo iptables -I INPUT -i IFACE -p tcp --dport 8080 -j ACCEPT
sudo iptables -I INPUT -i IFACE -p icmp -j ACCEPT
python3 -m http.server 8080 --bind 100.64.0.1
```

Leave the HTTP server running.

### Mac

Build the same main branch. W18-1 is merged. This pull request is merged.

```bash
cargo build --release -p gyeol-cli
sudo install -m 755 target/release/gyeol /usr/local/bin/gyeol
sudo mkdir -p /var/lib/gyeol /var/log
```

Copy the W18-1 netmap file into `/var/lib/gyeol`.
Install the launchd unit:

```bash
sudo cp scripts/dev.gyeol.plist /Library/LaunchDaemons/dev.gyeol.plist
sudo chown root:wheel /Library/LaunchDaemons/dev.gyeol.plist
sudo chmod 644 /Library/LaunchDaemons/dev.gyeol.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.gyeol.plist
sudo launchctl print system/dev.gyeol
```

Confirm the address and the route:

```bash
ifconfig | grep 100.64.0.2
netstat -rn -f inet | grep 100.64.0.0
```

Open the Linux overlay HTTP service:

```bash
curl -fsS --max-time 10 http://100.64.0.1:8080/
open http://100.64.0.1:8080/
```

`curl` exits 0.
The browser shows the directory listing from the Linux host.

### Linux ping

On the Linux host, ping the Mac:

```bash
ping -c 3 -W 2 100.64.0.2
```

The command reports 3 packets received.
The Mac must answer ICMP echo on 100.64.0.2.

### Record

Paste the command output under this heading after the run.

| Field | Value |
| --- | --- |
| Mac command | `curl -fsS --max-time 10 http://100.64.0.1:8080/` and `open http://100.64.0.1:8080/` |
| Linux command | `ping -c 3 -W 2 100.64.0.2` |
| Result | pending Eng Lead |
| Output | pending Eng Lead |
