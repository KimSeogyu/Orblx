# Mock IdP sign-in

The default City Breeze path is Google OIDC.
Read that path in [w17-google-oidc.md](w17-google-oidc.md).
This page describes `ORBLX_OIDC_MODE=mock`.
The harness serves a local OIDC sign-in page on that mode.
City Breeze uses that page when the mode is mock.
The page is the browser path for a human SVID.
The signer is the built-in `MockOidc` in `gyeol-identity`.
`IssueGate` turns the ID token into the human SVID.

## Issuer

| Field | Value |
| --- | --- |
| Issuer | `https://oidc.gyeol.local` |
| Audience | `gyeol-issue` |
| Subject | `ada` |
| Client | `gyeol-sim` |
| Response type | `code` |
| Scope | `openid` |
| Key | Ed25519 |

The issuer string is `MOCK_OIDC_ISSUER`.
The audience string is `OIDC_AUDIENCE`.
The subject is the City Breeze human `ada`.
The SVID is `spiffe://gyeol.local/user/ada`.

## Click path

1. Start the harness with `cargo run -p gyeol-sim`.
2. Open `http://127.0.0.1:8787`.
3. Click Play City Breeze. Easy in the engineering view opens the same page.
4. The browser requests `GET /oidc/authorize`.
5. The sign-in page shows the issuer, the audience, and the subject.
6. Click Sign in.
7. The browser sends `POST /oidc/authorize`.
8. The harness redirects to `GET /oidc/callback?code=...&state=...`.
9. The callback checks the one-time code and the state value.
10. The callback issues the human SVID.
11. The harness verifies the ticket.
12. The harness opens `app-a.orblx.test` and `app-b.orblx.test`.
13. Each application returns status 200.
14. The browser returns to `/`.
15. The SVID panel shows `up`.
16. The QUIC path panel shows `up`.

Use another local address when port 8787 is busy:

```bash
cargo run -p gyeol-sim -- --listen 127.0.0.1:8790
```

Open `http://127.0.0.1:8790` and follow the same clicks.

## Routes

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/oidc/authorize` | The sign-in page |
| `POST` | `/oidc/authorize` | Redirect to the callback |
| `GET` | `/oidc/callback` | Issue the SVID, run City Breeze, redirect to `/` |

`GET /oidc/authorize` requires these query fields:

- `client_id=gyeol-sim`
- `response_type=code`
- `redirect_uri` is `/oidc/callback` or the same path on this host
- `state` is 16 to 128 lowercase hex characters
- `scope=openid`

The sign-in form posts the same fields plus `subject=ada`.

## Redirect

The harness accepts a callback on this host.
A relative redirect is `/oidc/callback`.
An absolute redirect uses `http` or `https`, the request host, and the path `/oidc/callback`.
The sign-in response uses the path `/oidc/callback` on this harness.
The code and the state travel on that path.

## Code

The code is one-time.
The code life is 120 seconds.
The callback returns the same state value.
A second use of the code fails.
A different state value fails.
A subject other than `ada` fails.

## Feed

The callback keeps the version 1 envelope.
The City Breeze kinds stay in this order:

1. `difficulty_selected`
2. `svid.issued`
3. `ticket.verified`
4. `quic_hello`
5. `frame_tx`
6. `frame_rx`
7. `frame_tx`
8. `connector_https` for `app-a.orblx.test` with status 200
9. `frame_tx`
10. `connector_https` for `app-b.orblx.test` with status 200
11. `session_up`

`svid.issued` remains the identity kind for the human SVID.
The callback detail names the mock IdP and the audience `gyeol-issue`.

## Demo script

`./scripts/demo.sh` performs the sign-in with `curl`.
The script opens the login page.
The script posts the sign-in form.
The script follows the callback.
The script then reads `GET /api/state`.
The script checks the City Breeze event kinds.
The script then runs Revoke, Medium, Spawn agent, Hard, and UDP block.
A pass prints `demo pass`.

```bash
./scripts/demo.sh
```

Set `GYEOL_DEMO_ADDR` when port 8787 is busy.

```bash
GYEOL_DEMO_ADDR=127.0.0.1:8790 ./scripts/demo.sh
```

## Other levels

The Easy button and the City Breeze button open the sign-in page.
Medium and Hard keep the in-process path.
Agent JIT still uses the parent human token inside the process.
Radioactive NAT still issues the human SVID inside the process.
Press Revoke after City Breeze to drop the human SVID.
The crate tests can still run the City Breeze machine in process.

## Scope

This page is the local demo sign-in.
The subject is the fixed demo user `ada`.
