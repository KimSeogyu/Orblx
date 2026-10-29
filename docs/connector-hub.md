# Orblx connector hub

The product name is Orblx.
The command name is orblx.
The connector is the hub-spoke path for two HTTPS apps.
The apps are `app-a.orblx.test` and `app-b.orblx.test`.
The overlay addresses are `10.8.0.10` and `10.8.0.11`.
The overlay port is TCP 443.
The path uses one QUIC bidirectional stream.
The stream carries ADR-0002 DATA frames.
Each DATA payload is one IPv4 TCP segment.
The spoke reads the TLS server name and selects the overlay address.
The hub opens a TCP connection to the app listener.
QUIC protects the stream.
The path does not use WireGuard.
The path does not use Headscale.
The path does not use DERP.

The hub and the spoke use human SVIDs.
An agent SVID still allows one destination.
That rule is the W8 JIT allow.
This path does not change that rule.

## Userspace proof

This proof does not open a TUN device.
The test `two_https_apps_answer_through_the_mesh` runs the same proof.
Run the proof:

```bash
cargo run -p orblx-cli -- connector smoke
```

You must see both of these results:

- `app-a.orblx.test` returns status 200 and body `app-a`.
- `app-b.orblx.test` returns status 200 and body `app-b`.

`mesh_to` is greater than zero for each app.
`mesh_from` is greater than zero for each app.
`dialed` is the spoke ingress.
`backend_a` and `backend_b` are other local ports.
The client does not dial those ports.

[`scripts/connector-smoke.sh`](../scripts/connector-smoke.sh) runs the same command and checks the text.

## Curl on the userspace path

This path does not need CAP_NET_ADMIN.
One process runs the hub, the spoke, and the two apps.
The HTTPS bytes still cross the QUIC mesh.

```bash
cargo run -p orblx-cli -- connector serve --ingress 127.0.0.1:8443 --ca-out orblx-app-ca.pem
```

In a second terminal:

```bash
curl --fail --silent --show-error \
  --resolve app-a.orblx.test:8443:127.0.0.1 \
  --cacert orblx-app-ca.pem \
  https://app-a.orblx.test:8443/
curl --fail --silent --show-error \
  --resolve app-b.orblx.test:8443:127.0.0.1 \
  --cacert orblx-app-ca.pem \
  https://app-b.orblx.test:8443/
```

The first command prints `app-a`.
The second command prints `app-b`.
Stop the serve process with Ctrl+C.

## Two processes

`issue` writes the SVID PEM files and the ticket files.
The sidecar names match `hello-quic`.
The command still loads those files from disk.

```bash
cargo run -p orblx-cli -- connector issue --out /tmp/orblx-w9
cargo run -p orblx-cli -- connector hub --dir /tmp/orblx-w9 --listen 127.0.0.1:7443
```

In a second terminal:

```bash
cargo run -p orblx-cli -- connector spoke \
  --dir /tmp/orblx-w9 \
  --connect 127.0.0.1:7443 \
  --ingress 127.0.0.1:8443
```

In a third terminal:

```bash
curl --fail --silent --show-error \
  --resolve app-a.orblx.test:8443:127.0.0.1 \
  --cacert /tmp/orblx-w9/app-ca.pem \
  https://app-a.orblx.test:8443/
curl --fail --silent --show-error \
  --resolve app-b.orblx.test:8443:127.0.0.1 \
  --cacert /tmp/orblx-w9/app-ca.pem \
  https://app-b.orblx.test:8443/
```

The default hub port is UDP 7443.
Use `--listen 0.0.0.0:443` when the process can bind UDP port 443.
UDP port 443 is the policy port.

## Browser or curl with a TUN device

This lab needs Linux, root, CAP_NET_ADMIN, and iproute2.
macOS cannot open this TUN device.
The command returns an error on macOS.
When `/dev/net/tun` is missing, or when CAP_NET_ADMIN is missing, use the userspace proof.
[`scripts/connector-tun.sh`](../scripts/connector-tun.sh) prints `K3 tun_ready false` in that case and exits 0.

The script does the following steps when root can open a TUN device:

1. `connector issue` writes the identity files.
2. The script creates two network namespaces and one veth pair.
3. The hub namespace runs `hello-quic server` with TUN address `10.8.0.1`.
4. The script adds `10.8.0.10/32` and `10.8.0.11/32` on that TUN device.
5. The hub namespace runs `connector apps` on those addresses and port 443.
6. The spoke namespace runs `hello-quic client` with TUN address `10.8.0.2`.
7. curl in the spoke namespace resolves each name to the overlay address.

The packets from curl enter the spoke TUN device.
`hello-quic` carries the IPv4 packets on one QUIC stream.
The hub writes the packets to its TUN device.
The kernel delivers each packet to the app on that overlay address.
There is no other route from the spoke namespace to `10.8.0.10` or `10.8.0.11`.

Build the binary, then run the lab.
Root may not have cargo on `PATH`.

```bash
cargo build -p orblx-cli
sudo ./scripts/connector-tun.sh
```

A manual run uses the same commands.
Build the binary first:

```bash
cargo build -p orblx-cli
```

Create the lab files:

```bash
cargo run -p orblx-cli -- connector issue --out /tmp/orblx-w9
```

Hub namespace, after the TUN device `orblxh` is up:

```bash
sudo ip addr add 10.8.0.10/32 dev orblxh
sudo ip addr add 10.8.0.11/32 dev orblxh
sudo ./target/debug/orblx connector apps \
  --dir /tmp/orblx-w9 \
  --bind-a 10.8.0.10:443 \
  --bind-b 10.8.0.11:443
```

Spoke namespace, after `hello-quic client` is up:

```bash
curl --fail --silent --show-error \
  --resolve app-a.orblx.test:443:10.8.0.10 \
  --cacert /tmp/orblx-w9/app-ca.pem \
  https://app-a.orblx.test/
curl --fail --silent --show-error \
  --resolve app-b.orblx.test:443:10.8.0.11 \
  --cacert /tmp/orblx-w9/app-ca.pem \
  https://app-b.orblx.test/
```

## K3

K3 is the TUN device.
The userspace connector is the CI proof.
The TUN lab is optional.
The TUN lab is dead when any of these statements is true:

- The host is macOS.
- `/dev/net/tun` is absent.
- The process does not have CAP_NET_ADMIN.

The script reports that state with the line `K3 tun_ready false`.
The script then exits 0.
The userspace proof still runs in `cargo test --workspace`.

## K4

K4 is the SVID PEM load from disk.
This week does not replace that load.
`connector issue` writes PEM files and ticket files.
`connector hub` and `connector spoke` read those files.
`hello-quic` can read the same ticket sidecar files.
The sidecar names are `ticket-verifier.pem`, `ticket-mac.key`, `ticket-not-before`, `ticket-not-after`, and `svid-ca.pub`.
The MAC file is the ticket path plus `.mac`.
