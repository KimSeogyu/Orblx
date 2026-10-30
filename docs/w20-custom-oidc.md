# Custom OIDC issuer

The coordinator accepts ID tokens from one OIDC issuer that you configure.
You set the issuer URL and the client ID.
The coordinator finds the JWKS with OIDC discovery.
Google is a preset of the same verifier.
The crate `orblx-identity` owns the token check (`OidcIssuer`, `OidcJwks`, and `OidcReject`).
The crate `orblx-coord` owns the config file and the JWKS cache.

## Config

Start the coordinator with `--config FILE`:

```bash
orblx coord serve --state DIR --listen 0.0.0.0:443 --name coord --policy FILE --config /etc/orblx/coord.toml
```

The file has one section, `[oidc]`:

```toml
[oidc]
issuer = "https://idp.example.com"
client_id = "orblx"
allowed_domains = ["example.com"]
allowed_emails = ["ops@partner.example"]
# Optional. A PEM CA file for an issuer with a private CA.
ca_file = "/etc/orblx/idp-ca.pem"
```

| Key | Content |
| --- | --- |
| `preset` | `google` or absent. `google` sets the issuer to `https://accounts.google.com` and needs a Google client ID |
| `issuer` | The `iss` value. It must be `https://`. It must not contain `?`, `#`, `@`, or `\`. At most 256 characters |
| `client_id` | The `aud` value. 1 to 200 printable characters |
| `allowed_domains` | Email domains. At most 64 entries. Lowercase compare |
| `allowed_emails` | Full email addresses. At most 64 entries. Lowercase compare |
| `ca_file` | Extra TLS roots for discovery and the JWKS. At most 64 KiB. The coordinator reads it at start |

The parser accepts quoted strings, one-line arrays, and `#` comments.
An unknown key, a repeated key, or another section stops the start.
The config file overrides the W17 environment path.
Without `--config`, the W17 Google environment path does not change.
The start prints `oidc issuer ISSUER client_id ID allowed_domains N allowed_emails N`.
The client ID is not a secret. The flow has no client secret.

When both lists are empty, any subject of the issuer can enroll.
When a list is set, the token must have `email`, `email_verified` must be `true`, and the email must match one entry in a list.

## Discovery and the JWKS cache

1. The coordinator gets `ISSUER/.well-known/openid-configuration`.
2. The `issuer` field must be equal to the configured issuer.
3. `jwks_uri` must be `https://`.
4. `id_token_signing_alg_values_supported` must contain `RS256` or `ES256`.
5. The coordinator gets `jwks_uri`.
6. The coordinator keeps RSA keys as RS256 keys and EC P-256 keys as ES256 keys. It skips `use: enc` keys. A repeated `kid` or an empty key set is an error.

All requests use HTTPS with TLS 1.3. Plain HTTP is not possible.
A reply must be `200` and at most 64 KiB.

The coordinator gets the JWKS again in these cases:

| Reason | Trigger |
| --- | --- |
| `first` | No key set is in the cache |
| `stale` | The key set is older than 300 seconds |
| `unknown-kid` | The token `kid` is not in the cached key set |

The coordinator gets the JWKS at most one time in 10 seconds.
Thus a flood of tokens with a random `kid` does not flood the issuer.
A fetch failure keeps the old key set.
The log line is `oidc jwks loaded REASON kids KID...` or `oidc jwks fetch failed REASON STAGE STEP`.
`STAGE` is `discovery` or `jwks`. `STEP` is the failed step, for example `connect`, `tls`, `http`, or `document`.

## Token check

The check order is:

1. The header `alg` is `RS256` or `ES256`. The header has no `jwk`, `jku`, `x5u`, `x5c`, or `crit`.
2. The header has a `kid`. The `kid` is in the key set. The key type agrees with `alg`.
3. The signature is correct.
4. `iss` is equal to the issuer. `aud` contains the client ID. If `azp` is present, it is the client ID.
5. When the request or the token has a nonce, both have the same nonce.
6. `sub` makes a valid SVID `spiffe://orblx.local/user/SUB`.
7. `iat`, `nbf`, and `exp` are in the time window. The skew is 60 seconds.
8. The email lists pass.

A failed check prints `oidc reject REASON` in the coordinator log.
The node gets only `The OIDC check failed.`.
An accepted token prints `oidc accept sub SUB`.
The config audit actor is `oidc:SUB`.
The logs do not contain the token.

| Reason | Cause |
| --- | --- |
| `malformed` | The token is not a JWT, or a claim is missing |
| `algorithm` | The `alg` is not allowed, a key header is present, or the key type does not agree |
| `unknown-kid` | The `kid` is not in the key set |
| `bad-signature` | The signature is not correct |
| `wrong-issuer` | `iss` is not the issuer |
| `wrong-audience` | `aud` or `azp` is not the client ID |
| `expired` | `exp` is in the past |
| `not-yet-valid` | `iat` or `nbf` is in the future |
| `nonce` | The nonces are not the same |
| `email-not-allowed` | The email is missing, not verified, or not in a list |
| `jwks-missing` | The coordinator has no key set. The fetch failed |

## Enroll a node

```bash
orblx coord enroll --name NAME --coord ADDR --bundle FILE --id-token-file FILE [--nonce HEX] --state DIR [--endpoint HOST:PORT]
```

The node reads the ID token from a file. The command does not print the token.
`--token-file` and `--id-token-file` are exclusive. `--nonce` needs `--id-token-file`.

## Test issuer

The crate `orblx-test-idp` is a small HTTPS OIDC issuer for tests and proofs only.
It is not a production issuer.

```bash
orblx-test-idp init --dir DIR --host HOST
orblx-test-idp serve --dir DIR --issuer URL [--listen ADDR]
orblx-test-idp rotate --dir DIR --kid KID --alg RS256|ES256 [--drop KID]
orblx-test-idp mint --dir DIR --kid KID --issuer URL --aud ID --sub SUB --out FILE [--email E] [--nonce N] [--ttl S] [--age S] [--header-kid KID] [--tamper]
```

`init` makes a test TLS CA, a server certificate, and two signing keys: `rs1` (RS256) and `es1` (ES256).
The key files have mode 0600.
`serve` reads the key file on each request, so `rotate` takes effect at once.
`mint` writes the token to a 0600 file and prints only the `kid`, the `alg`, the expiry, and the file path.
`--tamper` changes one signature character. `--header-kid` sets a `kid` that is not the signing key.
All keys are made at run time. The repository has no keys.

## Container proof

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `idp` container | [C] | `orblx-test-idp serve` on `https://idp:8443` with a test CA |
| `coord` container | [C] | Coordinator with `--config`. Trusts the test CA through `ca_file` |
| `laptop` container | [C] | Enrolls with ID tokens and pings `srv` |
| `srv` container | [C] | Node `srv`. Enrolls with an enroll token and runs `orblx up` |

The image is `orblx-oidc:w20`.
The proof script is `scripts/proof/custom-oidc.sh`.
The Compose file is `scripts/proof/compose.oidc.yml`.
The policy file is `scripts/proof/oidc.hujson`.
The proof uses no external account and no real secret.

Run this command on the REAL Linux host:

```bash
scripts/proof/custom-oidc.sh
```

The script does these steps:

1. It makes the test issuer, copies the test CA out, and writes `coord.toml` with `allowed_domains = ["example.test"]`.
2. It starts the issuer and the coordinator.
3. It enrolls `srv` with an enroll token.
4. It enrolls `laptop` with an RS256 token for `alice@example.test` and a nonce.
5. It starts `srv`, and `laptop` pings `srv`. The path must be `direct`.
6. It enrolls `desk` with an ES256 token for `bob@example.test`.
7. It sends a wrong issuer, a wrong audience, an expired token, a bad signature, an unknown `kid`, and an email in `other.test`. Each must fail with the correct reason.
8. It mints one more `rs1` token. Then it adds `es2` and removes `rs1` at the issuer.
9. It enrolls `rotated` with an `es2` token. The coordinator must load `es1 es2` for the reason `unknown-kid`.
10. It sends the old `rs1` token. It must fail with `unknown-kid`.
11. It checks that no token signature is in the logs or in `nodes.json`, and that no private key is in the logs.
12. It prints the node owners, then prints `proof_ok`.

The coordinator container runs `orblx` without the proof entrypoint.
The entrypoint starts systemd-resolved, and systemd-resolved does not send the one-label name `idp` to the Docker DNS.

The recorded run output starts after the image build.
Times are Unix seconds (UTC).

```text
=== [C] init test issuer ===
idp init host idp kids rs1 es1
idp_ca 60:CB:00:07:DA:76:BC:C2:C0:32:4E:4D:1E:89:FC:FF:36:4A:85:2E:A0:54:23:69:87:DE:62:0C:67:E1:05:61
=== [C] start test issuer and coordinator ===
oidc issuer https://idp:8443 client_id orblx-proof allowed_domains 1 allowed_emails 0
coord_ip 172.18.0.3
=== [C] enroll srv with a token ===
wrote one enroll token
token_id 99e9968676e9b86b
expires_unix 1793323111
out /var/lib/orblx/tokens/srv
enrolled
name srv
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/srv
peers 0
=== [C] enroll laptop with an RS256 ID token ===
minted kid rs1 alg RS256 exp 1793320112 file /tokens/laptop
enrolled
name laptop
overlay_ip 100.64.0.2
svid spiffe://orblx.local/node/laptop
peers 1
oidc jwks loaded first kids rs1 es1
oidc accept sub alice
=== [C] netmap on srv ===
netmap
name srv
overlay_ip 100.64.0.1
peer laptop 100.64.0.2
endpoints_ok 2
grants 1
=== [C] start node srv ===
=== [C] laptop pings srv ===
path direct
rtt_ms 21
=== [C] enroll desk with an ES256 ID token ===
minted kid es1 alg ES256 exp 1793320114 file /tokens/desk
enrolled
name desk
overlay_ip 100.64.0.3
svid spiffe://orblx.local/node/desk
peers 2
minted kid es1 alg ES256 exp 1793320115 file /tokens/wrong-issuer
minted kid rs1 alg RS256 exp 1793320116 file /tokens/wrong-audience
minted kid es1 alg ES256 exp 1793315976 file /tokens/expired
minted kid rs1 alg RS256 exp 1793320116 file /tokens/bad-signature
minted kid ghost alg ES256 exp 1793320117 file /tokens/unknown-kid
minted kid es1 alg ES256 exp 1793320117 file /tokens/wrong-domain
=== [C] reject wrong issuer ===
The OIDC check failed.
oidc reject wrong-issuer
=== [C] reject wrong audience ===
The OIDC check failed.
oidc reject wrong-audience
=== [C] reject expired ===
The OIDC check failed.
oidc reject expired
=== [C] reject bad signature ===
The OIDC check failed.
oidc reject bad-signature
=== [C] reject unknown kid ===
The OIDC check failed.
oidc reject unknown-kid
=== [C] reject email domain ===
The OIDC check failed.
oidc reject email-not-allowed
=== [C] rotate issuer keys: add es2, drop rs1 ===
minted kid rs1 alg RS256 exp 1793320128 file /tokens/old-key
idp rotate kids es1 es2
minted kid es2 alg ES256 exp 1793320140 file /tokens/rotated
enrolled
name rotated
overlay_ip 100.64.0.4
svid spiffe://orblx.local/node/rotated
peers 3
oidc jwks loaded unknown-kid kids es1 es2
=== [C] reject dropped key rs1 ===
The OIDC check failed.
oidc reject unknown-kid
=== [C] coordinator OIDC log lines ===
oidc issuer https://idp:8443 client_id orblx-proof allowed_domains 1 allowed_emails 0
enrolled srv
oidc jwks loaded first kids rs1 es1
oidc accept sub alice
enrolled laptop
oidc accept sub bob
enrolled desk
oidc reject wrong-issuer
oidc reject wrong-audience
oidc reject expired
oidc reject bad-signature
oidc jwks loaded unknown-kid kids rs1 es1
oidc reject unknown-kid
oidc reject email-not-allowed
oidc jwks loaded unknown-kid kids es1 es2
oidc accept sub dave
enrolled rotated
oidc reject unknown-kid
=== [C] no token text in logs or the node store ===
token_text_in_logs none
srv token:99e9968676e9b86b
laptop oidc:alice
desk oidc:bob
rotated oidc:dave
proof_ok
```

## Limits

- Enroll reads an ID token file. The generic issuer has no browser login flow in `orblx login`. Get the token with the issuer tools.
- The coordinator accepts one issuer.
- The verifier accepts RS256 and ES256 only.
- The test issuer is for tests. Do not use it in production.
