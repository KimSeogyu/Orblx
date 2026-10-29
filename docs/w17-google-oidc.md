# Google OIDC human SVID

City Breeze uses Google authorization-code OIDC.
The issuer is `https://accounts.google.com`.
`IssueGate` checks a real Google `id_token`.
`IssueGate` writes a short human SVID.
The SVID is `spiffe://gyeol.local/user/{sub}`.
`{sub}` is the Google `sub` claim.
The library does not use a fixed subject.

`MockOidc` is not the default.
`MockOidc` stays for CI and the harness.
Set `ORBLX_OIDC_MODE` to `mock` for that path.
An absent variable selects Google.
The value `google` selects Google.
The harness must read `OidcMode::from_env`.
The harness must not start the mock IdP when the mode is Google.

## Client

The Google OAuth Web client name is `Orblx gyeol-sim`.
The client is in Testing mode.
The operator sets both environment variables.
Do not commit the client secret.
Do not write the client secret in a log, a doc, or a pull request.

| Variable | Value |
| --- | --- |
| `ORBLX_GOOGLE_CLIENT_ID` | The public Web client id |
| `ORBLX_GOOGLE_CLIENT_SECRET` | The operator sets this value |
| `ORBLX_OIDC_MODE` | Absent or `google` for Google. `mock` for CI |

The registered public client id is:

`949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com`

Set `ORBLX_GOOGLE_CLIENT_ID` to that id.
`GoogleClient::from_env` reads the id and the secret.
A missing secret is a configuration error.
The library does not fall back to `MockOidc`.

## Redirect

Register these redirect URIs on the Google client:

- `http://127.0.0.1:8787/oidc/callback`
- `http://localhost:8787/oidc/callback`

Register these JavaScript origins on the Google client:

- `http://127.0.0.1:8787`
- `http://localhost:8787`

`GoogleClient::authorize_url` accepts only the two redirect URIs.
Another port is not a registered redirect.
City Breeze always shows the Google account chooser.

## Checks

The harness gets the JWKS document with `GET`.
The URL is `https://www.googleapis.com/oauth2/v3/certs`.
`GoogleJwks::from_json` reads that document.
The harness posts the token request to `https://oauth2.googleapis.com/token`.
`GoogleClient::token_request` builds the form body.
The body contains the client secret.
The harness must not log the body.
`GoogleTokenRequest::id_token_from_response` reads `id_token`.
This crate does not open a network connection.

`GoogleJwks::verify` checks the ID token.

| Check | Rule |
| --- | --- |
| `alg` | `RS256` |
| `kid` | One RSA signature key in the JWKS document |
| Signature | The selected Google key |
| `iss` | `https://accounts.google.com` |
| `aud` | The OAuth client id |
| `azp` | The client id when the claim is present. Required when `aud` has more than one value |
| `nonce` | The nonce from the authorize request |
| `exp` and `iat` | The caller clock, with 60 seconds of skew |
| `sub` | A SPIFFE user name |

The function rejects `alg` `none`.
The function rejects an embedded `jwk` header.
The function does not use a key from the token header.

## SVID

`IssueGate::from_google` stores the client id and the JWKS document.
`IssueGate::issue_google_human_svid` verifies the ID token.
The method issues `spiffe://gyeol.local/user/{sub}`.
The SVID life is the remaining ID token life.
The life is at most 15 minutes.
15 minutes is `MAX_USER_TTL`.
The shorter value wins.

`IssueGate::issue_human_svid` accepts only a mock token.
`IssueGate::issue_agent_svid` accepts only a mock parent token.
A Google gate returns a token error for those two methods.

## Mock path

`ORBLX_OIDC_MODE=mock` selects `OidcMode::Mock`.
`IssueGate::new` trusts `MockOidc`.
The mock issuer is `https://oidc.gyeol.local`.
The mock audience is `gyeol-issue`.
Use this path for CI and the harness.
Do not use this path as the City Breeze default.

## Harness call

The harness calls this API on the Google path:

1. Read `OidcMode::from_env`.
2. Read `GoogleClient::from_env`.
3. Send the browser to `authorize_url`.
4. Receive the authorization code on `/oidc/callback`.
5. Post `token_request` to the token endpoint.
6. Read `id_token` from the response.
7. Fetch the JWKS document and call `GoogleJwks::from_json`.
8. Call `IssueGate::from_google`.
9. Call `issue_google_human_svid` with the same nonce.

The browser pages and `scripts/demo.sh` stay on the harness change.
That change must keep the mock path behind `ORBLX_OIDC_MODE=mock`.

## Harness surface

The default page is the character scene.
Play City Breeze sends the browser to `GET /oidc/authorize`.
The page does not show a mock IdP panel.
The page does not show a fixed subject.
The page does not show a fake banner.
`ORBLX_OIDC_MODE=mock` still serves the local sign-in page.
That page stays off the default path.

A missing client id or a missing client secret returns HTTP 400.
The response names `ORBLX_GOOGLE_CLIENT_ID` and `ORBLX_GOOGLE_CLIENT_SECRET`.
The response is not the mock sign-in page.

The callback posts the token request.
The harness does not log that body.
The harness reads `id_token`.
The harness fetches the JWKS document.
The harness calls `GoogleJwks::from_json`.
The harness calls `IssueGate::from_google`.
The harness calls `issue_google_human_svid` with the authorize nonce.
The feed line says that Google issued the human ID token.
The SVID state is `up`.
The QUIC path state is `up`.

## Play

Set the two environment variables.
Leave `ORBLX_OIDC_MODE` unset.

```bash
export ORBLX_GOOGLE_CLIENT_ID=949089074205-hpspmac5i7uld6q5p3f019tvmojhoipi.apps.googleusercontent.com
export ORBLX_GOOGLE_CLIENT_SECRET=
cargo run -p gyeol-sim
```

Put the client secret in `ORBLX_GOOGLE_CLIENT_SECRET`.
Do not commit that value.
`.env.example` shows the public client id and an empty secret.

Open `http://127.0.0.1:8787`.
`http://localhost:8787` is the other registered origin.
Another port is not a registered redirect.

1. Click Play City Breeze.
2. The browser opens the Google authorization page.
3. Complete the Google consent.
4. Google returns the browser to `/oidc/callback`.
5. The character scene shows the human SVID up.
6. The Direct path meets `app-a.orblx.test` and `app-b.orblx.test`.

The play recording waits for the client secret.
The engineering lead injects `ORBLX_GOOGLE_CLIENT_SECRET` into the agent.
The recording then follows the click path above.
Save that recording under `artifacts/orblx-w17-play/`.

## Demo and CI

`./scripts/demo.sh` checks the default page.
The page and `app.js` must not contain a mock IdP panel or the fixed subject.
With both Google variables set, `GET /oidc/authorize` returns 303.
The location is the Google authorization URL.
The location contains the client id, the loopback redirect, `state`, and `nonce`.
The location does not contain the client secret.
The response body is not the mock sign-in page.
The script then presses Revoke without a City Breeze session.
That cold revoke issues a session and then drops it.
The later actions are Medium, Spawn agent, Hard, and UDP block.

Without the two variables, the same request returns 400.
The body names both variables.

`ORBLX_OIDC_MODE=mock` keeps the local sign-in path.
CI sets the public client id and a stand-in secret.
The stand-in secret is not a Google secret.
CI uses it only to prove the authorize redirect.
CI does not exchange a token.
