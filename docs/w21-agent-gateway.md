# Agent gateway

`orblx gateway` is an HTTP gateway on the overlay.
It forwards an HTTP request to a local service only with a valid W21-2 agent grant.
It uses the same checks as the TCP guard in `docs/w21-agent-grant.md`.
It adds a path scope, a request nonce, and a replay check.

No new crypto or handshake design is in this change.
The request proof is the W21-2 use proof (`seal_use`).
The proof already has an `extra` field that the agent signs with its SVID key (Ed25519).
The gateway puts the request data in that field.

## Request

The agent runs `orblx agent http --grant DIR --path /api/items`.
The request carries two headers:

| Header | Content |
| --- | --- |
| `Orblx-Agent-Proof` | The W21-2 use proof in base64 |
| `Orblx-Agent-Nonce` | 16 random bytes in hex. A new value for each request |

The signed `extra` field is:

```text
orblx-gateway-v1\n METHOD \n TARGET \n NONCE_HEX \n SHA256_HEX(BODY)
```

`TARGET` is the request target with the query.
Thus a change to the method, the path, the query, the nonce, or the body breaks the signature.

## Checks

The gateway reads one HTTP/1.0 or HTTP/1.1 request on each connection.
It refuses `Transfer-Encoding`, a body above 1 MiB, and a head above 48 KiB.
The checks, in order:

1. The last good deny read is not older than 2 s. Else `503 stale`.
2. The proof is valid for this node, service, and port, with the signed request data.
   The grant signature, the ticket, the end time (strict ms), and the deny set pass.
3. The pair (ticket hash, nonce) is new. Else `403 replay`.
   The gateway keeps each pair for 120 s. The proof stamp window is 60 s, so an older proof fails step 2.
4. The path is inside the grant path prefix, on a `/` boundary.
   A `.` or `..` part, a `%`, or a `\` fails. Else `403 path`.

| Case | Status and reason |
| --- | --- |
| No proof header | `403 missing` |
| Proof but no valid nonce | `403 nonce` |
| Proof for another service on the same gateway | `403 ticket` |
| Changed method, path, nonce, or body | `403 ticket` |
| Proof for another port | `403 destination` |
| Path outside the prefix | `403 path` |
| Same request again | `403 replay` |
| At or after the end time | `403 expired` |
| After a revoke | `403 revoked` (shared core. The W21-2 proof shows it) |
| Request that does not parse | `400 request` |

The gateway removes the proof header, the nonce header, hop headers, and each `x-orblx-` header from the client.
It adds `x-orblx-agent` (the agent URI) and `x-orblx-grant` (the grant id) for the upstream.

## Audit

Each request goes to the gateway audit chain (`--audit FILE`), allowed or denied.
An allowed request is `agent-use`. A denied request is `agent-deny` with the reason.
The detail holds the method and the path without the query.
The gateway also writes `agent-grant`, `agent-expire`, and `agent-revoke` as the TCP guard does.
Use `orblx audit verify-config --file FILE` to check the chain.

## Proof

| Part | Kind | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `coord` container | [C] | Coordinator, mock OIDC, policy `scripts/proof/agent.hujson` |
| `owner` container | [C] | Owner SVID. Approves the grant |
| `a` container | [C] | Agent node. Runs `orblx agent http` |
| `b` container | [C] | `orblx gateway` api on 8080 and db on 5432. Python upstream on 127.0.0.1:8081 |

Run this command on the REAL Linux host:

```sh
./scripts/proof/agent-gateway.sh
```

The script prints `proof_ok` at the end.

### Result (2026-10-30 11:44 KST, log `w21-3-try2.log`)

Grant: service `api`, port 8080, path `/api`, TTL 20 s.

| Check | Result |
| --- | --- |
| [C] GET `/api/items?q=1`, GET `/api/items`, POST with an 11-byte body | 200. The upstream sees no proof header, and sees the agent URI and the grant id |
| [C] No grant | `403 missing` |
| [C] `/admin`, `/apix`, `/api/../admin` | `403 path` |
| [C] Proof for service db on the api gateway | `403 ticket` |
| [C] Proof for port 8080 on the db gateway (5432) | `403 destination` |
| [C] Same request bytes two times | First 200, second `403 replay` |
| [C] Loop to the end time 11:45:10.000 KST | Last 200 at -63 ms. Gateway deny at +113 ms. Client deny reply at +149 ms |
| [C] Request after the end | `403 expired` |
| [C] Api chain | `ok`, grant 1, use 132, deny 8, expire 1. 140 requests sent, 140 recorded |
| [C] Db chain | `ok`, deny 1. 1 request sent, 1 recorded |
| [C] Coordinator chain | `verify ok`, 9 records |
| [C] Logs | 0 matches for the ticket hex, the key PEM, `PRIVATE KEY`, `T0JMWEFHVDE`, `ge1.`, `orblx-agent-proof`, `q=1` |

The log grep covers the Compose logs, the gateway logs, the upstream log, the chains, and the client output.

## Caveats

- The gateway keeps the nonce set in memory. A gateway restart clears it, so a proof younger than 60 s can be sent again one time after a restart.
- Each gateway process has its own nonce set and its own chain file.
- The proof does not cover the request headers other than the proof and the nonce.
- The gateway reads one request on each connection. It sends `Connection: close`.
- The gateway does not support `Transfer-Encoding: chunked`.
- The gateway does not log the query. It logs the path. Do not put a secret in a path part.
- The upstream gets plain HTTP on the node loopback. The overlay carries the request between nodes.
