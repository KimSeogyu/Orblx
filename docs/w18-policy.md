# ACL policy

The policy file is HuJSON.
HuJSON is JSON with `//` comments, `/* */` comments, and trailing commas.
The coordinator reads the file.
The coordinator compiles groups, tags, and accept rules into receiver grants.
The coordinator signs the grants with the same Ed25519 netmap key that signs the netmap.
The node stores `grants.signed.json` next to `netmap.json`.
The receiver checks each TCP packet against those grants.
An allow writes no audit record.
A deny appends one record to the `orblx-audit` hash chain.

An agent source needs one host, one protocol, and one port.
A human source may use a group, a tag, and one port.
The default is deny.
A failed inline test rejects the file.
The coordinator keeps the last good policy and logs one error line.

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` container | [C] | Coordinator. UDP 443. Policy file mount |
| `box` container | [C] | Receiver. Node name `box` |
| `mac` container | [C] | Source stand-in. Node name `mac` |
| Mac | REAL | Operator leg. Steps are at the end of this file |

The image is `orblx-coord:w18`.
The proof script is `scripts/proof/policy.sh`.
The Compose file is `scripts/proof/compose.policy.yml`.
The policy file in the proof is `scripts/proof/policy.hujson`.

The proof uses enroll tokens.
`ORBLX_OIDC_MODE=mock` keeps laptop login off.
The Mac leg uses Google.
The script does not print enroll tokens or private keys.

## Commands

```bash
orblx policy check --file FILE
orblx policy test --file FILE
orblx policy enforce --state DIR --src NAME --dst-ip ADDR --port PORT --audit FILE
orblx coord serve --state DIR --policy FILE
```

`policy check` and `policy test` run the inline tests.
`policy enforce` verifies the grant signature.
Then it admits a capability ticket and applies the grants on the receiver.
TCP port 22 follows an allow grant.
TCP port 5432 has no grant, so the receiver denies it.

## Container proof

Run this command on the REAL Linux host:

```bash
scripts/proof/policy.sh
```

The script deletes the `orblx-policy-proof` volumes at the start.
Run the Mac leg on a coordinator that you start by hand.
The recorded run used image `orblx-coord:w18`.
The lines below start after the image build.

```text
=== [C] start coordinator ===
=== [C] policy test ===
allow spiffe://orblx.local/node/mac tcp spiffe://orblx.local/node/box 22
deny spiffe://orblx.local/node/mac tcp spiffe://orblx.local/node/box 5432
policy ok
=== [C] token box ===
wrote one enroll token
token_id acf2615327edbcf8
expires_unix 1793283426
out /var/lib/orblx/tokens/box
=== [C] token mac ===
wrote one enroll token
token_id 8e31bcbd9a2c385a
expires_unix 1793283426
out /var/lib/orblx/tokens/mac
=== [C] coordinator address ===
coord_ip 172.18.0.2
=== [C] enroll box ===
enrolled
name box
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/box
peers 0
=== [C] enroll mac ===
enrolled
name mac
overlay_ip 100.64.0.2
svid spiffe://orblx.local/node/mac
peers 1
=== [C] netmap on box ===
netmap
name box
overlay_ip 100.64.0.1
peer mac 100.64.0.2
endpoints_ok 2
grants 1
=== [C] grants on box ===
{"version":1,"receiver":"spiffe://orblx.local/node/box","grants":[{"src":"spiffe://orblx.local/node/mac","proto":6,"port_start":22,"port_end":22}]}
=== [C] enforce on box ===
src spiffe://orblx.local/node/mac
dst spiffe://orblx.local/node/box
allow tcp 22
deny tcp 5432
audit /var/lib/orblx/audit.jsonl
=== [C] audit verify ===
ok
tip 1bd1ab540f9d79b33b946999e2b79cae5a873625a4d5e5f14e40c20eb8d73d3d
start 0
end 0
deny 1
records 1
=== [C] failing policy ===
The policy test failed. The source spiffe://orblx.local/node/mac to spiffe://orblx.local/node/box on tcp port 5432 is denied. The test expects an allow.
failing_policy kept_grants
policy_errors 1
proof_ok
```

`token_id` is the public id of the token.
The secret stays in the token file.
`proto` 6 is TCP.
The grant allows `spiffe://orblx.local/node/mac` to TCP port 22 on the box.
Port 5432 is absent.
The audit chain has one deny record.
`orblx audit verify` prints `ok` and `deny 1`.

The failing file expects an allow on TCP 5432.
`orblx policy check` rejects that file.
The coordinator log contains one line that starts with `policy load failed:`.
The grant document stays the last good document.
That document still allows TCP 22.

On this host, `iptables-legacy` FORWARD policy was DROP.
The script sets that policy to ACCEPT when `iptables-nft` FORWARD policy is ACCEPT.
That DROP discards UDP on a user-defined bridge.

## Real Mac leg

Eng Lead runs this section.
The container proof above already used a container named `mac`.
This section uses the real Mac as node `mac`.
Start a new coordinator.
Leave the `mac` Compose service stopped.

### REAL Linux host

```bash
WORK="$(mktemp -d)"
cp scripts/proof/policy.hujson "$WORK/policy.hujson"
export POLICY_FILE="$WORK/policy.hujson"
docker compose -f scripts/proof/compose.policy.yml up -d coord
```

Wait until the trust bundle exists.
Create one enroll token for the box.
Enroll only the box container.
Use the same `coord enroll` arguments as `scripts/proof/policy.sh`.
Copy only the trust bundle to the Mac:

```bash
docker compose -f scripts/proof/compose.policy.yml exec -T coord cat /var/lib/orblx/trust-bundle.pem > trust-bundle.pem
```

Leave `ca.key.pem`, `netmap.seed`, and `tokens/` on the Linux host.
The Compose file publishes `443:443/udp`.
The Mac uses the Linux host address.
The Mac does not use the Docker bridge address.

Set the public Google client id and recreate the coordinator container.
The named volume stays.

```bash
export ORBLX_OIDC_MODE=google
export ORBLX_GOOGLE_CLIENT_ID=949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com
docker compose -f scripts/proof/compose.policy.yml up -d coord
```

The log line `Google JWKS is loaded.` means laptop login can proceed.
The container must reach `https://www.googleapis.com/oauth2/v3/certs`.
Keep `ORBLX_GOOGLE_CLIENT_SECRET` on the Mac.

### REAL Mac

Build the client:

```bash
cargo build --release -p orblx-cli --bin orblx
```

Set the Google client on the Mac.
The operator supplies the secret.
Keep the secret out of shell history, logs, and this file.

```bash
export ORBLX_OIDC_MODE=google
export ORBLX_GOOGLE_CLIENT_ID=949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com
export ORBLX_GOOGLE_CLIENT_SECRET='the operator sets this value'
```

Port `8787` on the Mac must be free.
The callback is `http://127.0.0.1:8787/oidc/callback`.
Replace `LINUX_HOST` with the real Linux host address.
Replace `MAC_HOST` with the Mac address that the Linux host can reach.
The node name is `mac`.
That name matches the policy source `spiffe://orblx.local/node/mac`.

```bash
./target/release/orblx login \
  --name mac \
  --coord LINUX_HOST:443 \
  --bundle trust-bundle.pem \
  --state "$HOME/Library/Application Support/orblx" \
  --endpoint MAC_HOST:443
```

The command prints an authorize URL.
Open that URL in a browser on the Mac.
Leave the URL out of notes.
The URL contains the OIDC nonce.

A successful login prints `enrolled`, overlay address `100.64.0.2` when the box took `100.64.0.1`, and the SVID `spiffe://orblx.local/node/mac`.

Fetch the netmap:

```bash
./target/release/orblx coord netmap \
  --coord LINUX_HOST:443 \
  --bundle trust-bundle.pem \
  --state "$HOME/Library/Application Support/orblx"
```

### REAL Linux host, box receiver

Fetch the netmap inside the box container.
Replace `COORD_IP` with the coordinator address on the Docker bridge.

```bash
docker compose -f scripts/proof/compose.policy.yml --profile nodes run --rm box \
  coord netmap \
  --coord COORD_IP:443 \
  --bundle /coord-state/trust-bundle.pem \
  --state /var/lib/orblx
```

Run the receiver check.
Replace `BOX_IP` with the box overlay address.

```bash
docker compose -f scripts/proof/compose.policy.yml --profile nodes run --rm box \
  policy enforce \
  --state /var/lib/orblx \
  --src mac \
  --dst-ip BOX_IP \
  --port 22 \
  --port 5432 \
  --audit /var/lib/orblx/audit.jsonl
```

The command prints `allow tcp 22` and `deny tcp 5432`.

```bash
docker compose -f scripts/proof/compose.policy.yml --profile nodes run --rm box \
  audit verify --file /var/lib/orblx/audit.jsonl
```

The verify command prints `ok` and `deny 1`.
