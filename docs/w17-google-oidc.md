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
