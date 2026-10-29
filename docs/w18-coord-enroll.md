# Coordinator enrollment

The coordinator runs in a Docker container on the real Linux host.
That container is the VPS stand-in.
Two node containers enroll with one-use tokens.
The real Mac enrolls with Google.
The Mac steps are at the end of this file.
Eng Lead runs those steps.

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` container | [C] | Coordinator. UDP 443. Named volume `orblx-coord-store` |
| `node-a` container | [C] | Token enrollment for `server-a` |
| `node-b` container | [C] | Token enrollment for `server-b` |
| Mac | REAL | Google enrollment against the coordinator container |

The image is `orblx-coord:w18`.
The proof script builds it from `scripts/proof/Dockerfile`.
That Dockerfile is the same file the node daemon proof uses.
The coordinator Compose file is `scripts/proof/compose.coord.yml`.
It is separate from `scripts/proof/compose.w18.yml`.

The coordinator process listens on `0.0.0.0:443/udp`.
The node store is the named volume at `/var/lib/orblx`.
Enrollment uses server authentication.
The node SVID does not exist at enroll time.
A later `orblx coord netmap` uses the node SVID as the client certificate.
The coordinator SVID life is 15 minutes from process start.
W19-3 rotates that SVID.
The container process is root so the volume is writable.
Do not copy `ca.key.pem`, `netmap.seed`, or the `tokens/` directory.
`trust-bundle.pem` is public.

`ORBLX_OIDC_MODE=mock` is for unit tests.
The container proof uses enroll tokens.
`orblx login` uses Google.

## Container proof

Run this command on the REAL Linux host:

```bash
scripts/proof/coord-enroll.sh
```

The script deletes the `orblx-coord-proof` volumes at the start.
Run it before the Mac enrollment when the volume must stay.
The script does not print enroll tokens or private keys.

On this host, `iptables-legacy` FORWARD policy was DROP while `iptables-nft` FORWARD policy was ACCEPT.
That DROP discards UDP on a user-defined bridge.
The script sets the legacy policy to ACCEPT in that case.

The recorded run used image `orblx-coord:w18`.
The lines below start after the image build.

```text
=== [C] start coordinator ===
=== [C] token server-a ===
wrote one enroll token
token_id 5a82b71b1450bd4a
expires_unix 1793281122
out /var/lib/orblx/tokens/server-a
=== [C] token server-b ===
wrote one enroll token
token_id 66c1b4b7dde39a00
expires_unix 1793281122
out /var/lib/orblx/tokens/server-b
=== [C] coordinator address ===
coord_ip 172.18.0.2
=== [C] enroll server-a ===
enrolled
name server-a
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/server-a
peers 0
=== [C] enroll server-b ===
enrolled
name server-b
overlay_ip 100.64.0.2
svid spiffe://orblx.local/node/server-b
peers 1
=== [C] netmap before restart ===
netmap
name server-a
overlay_ip 100.64.0.1
peer server-b 100.64.0.2
endpoints_ok 2
=== [C] restart coordinator ===
=== [C] netmap after restart ===
netmap
name server-a
overlay_ip 100.64.0.1
peer server-b 100.64.0.2
endpoints_ok 2
same_ip server-a 100.64.0.1
same_peer server-b 100.64.0.2
=== [C] reuse token server-a ===
The enroll token is already used.
reused_token rejected
=== [C] netmap json ===
{"version":1,"self":{"name":"server-a","overlay_ip":"100.64.0.1"},"peers":[{"name":"server-b","overlay_ip":"100.64.0.2","svid":"spiffe://orblx.local/node/server-b","endpoints":["server-b:443"],"routes":[]}]}
=== [C] orblx up reads netmap.json ===
The file /var/lib/orblx/ticket.bin did not open. No such file or directory (os error 2)
orblx_up_read_netmap true

proof_ok
```

`token_id` is the public id of the token.
The secret stays in the token file.
`/var/lib/orblx/netmap.json` inside the node container is the shared netmap document.
`orblx up` reads that file by default.
The command then asks for `ticket.bin`.
That file is the capability ticket from `orblx node-issue`.
The coordinator does not write the ticket.

The overlay address of `server-a` is `100.64.0.1` before the coordinator restart and after it.
The reused token for `server-c` is rejected.

## Real Mac Google enrollment

Eng Lead runs this section.
The coordinator container is already up from the proof script.
Do not run `scripts/proof/coord-enroll.sh` again.
That script deletes the volume.

### REAL Linux host

Set the public Google client id and recreate the coordinator container.
The named volume stays.
The enrolled nodes stay.

```bash
export ORBLX_OIDC_MODE=google
export ORBLX_GOOGLE_CLIENT_ID=949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com
docker compose -f scripts/proof/compose.coord.yml up -d coord
docker compose -f scripts/proof/compose.coord.yml logs coord
```

The log line `Google JWKS is loaded.` means laptop login can proceed.
The container must reach `https://www.googleapis.com/oauth2/v3/certs`.
Do not put `ORBLX_GOOGLE_CLIENT_SECRET` on the coordinator.
The secret stays on the Mac.

Copy only the trust bundle:

```bash
docker compose -f scripts/proof/compose.coord.yml exec -T coord cat /var/lib/orblx/trust-bundle.pem > trust-bundle.pem
```

Copy `trust-bundle.pem` to the Mac.
Leave `ca.key.pem`, `netmap.seed`, and `tokens/` on the Linux host.

The Compose file publishes `443:443/udp` on the Linux host.
The Mac uses that host address.
The Mac does not use `172.18.0.2`.

### REAL Mac

Build the client:

```bash
cargo build --release -p orblx-cli --bin orblx
```

Set the Google client on the Mac.
The operator supplies the secret.
Do not write the secret in a shell history note, a log, or this file.

```bash
export ORBLX_OIDC_MODE=google
export ORBLX_GOOGLE_CLIENT_ID=949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com
export ORBLX_GOOGLE_CLIENT_SECRET='the operator sets this value'
```

Port `8787` on the Mac must be free.
The callback is `http://127.0.0.1:8787/oidc/callback`.

Replace `LINUX_HOST` with the real Linux host address.
Replace `MAC_HOST` with the Mac address that the Linux host can reach.

```bash
./target/release/orblx login \
  --name macbook \
  --coord LINUX_HOST:443 \
  --bundle trust-bundle.pem \
  --state "$HOME/Library/Application Support/orblx" \
  --endpoint MAC_HOST:443
```

The command prints an authorize URL.
Open that URL in a browser on the Mac.
Do not paste the URL.
The URL contains the OIDC nonce.

A successful login prints `enrolled`, the node name, `overlay_ip`, and the SVID `spiffe://orblx.local/node/macbook`.
The state directory then holds `netmap.json`.
`orblx up --state-dir "$HOME/Library/Application Support/orblx"` reads that file.

Fetch the netmap again:

```bash
./target/release/orblx coord netmap \
  --coord LINUX_HOST:443 \
  --bundle trust-bundle.pem \
  --state "$HOME/Library/Application Support/orblx"
```

Record `overlay_ip`.

On the REAL Linux host, restart only the coordinator container:

```bash
docker compose -f scripts/proof/compose.coord.yml restart coord
```

On the REAL Mac, run `orblx coord netmap` again.
`overlay_ip` is the same value.
Do this before the node SVID expires.
The life is 15 minutes.
