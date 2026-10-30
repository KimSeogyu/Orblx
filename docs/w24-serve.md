# W24-C serve hardening

This change makes `orblx serve` and `orblx funnel` (W21-4, `docs/w21-serve-funnel.md`) safer:

1. A forged peer source address gets no access.
2. serve reads each HTTP/1.1 request. Chunked request bodies work. A body above the limit gets `413`.
3. Funnel stays off by default. Unit tests and the proof show it.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The nodes, the outside host, and both Docker networks are [C].

The change adds no new crypto design and no new dependency for crypto.
New crates in `orblx-serve`: `hyper` (HTTP/1.1), `hyper-util`, `http-body-util`, `bytes`, and `libc`.

## 1. Forged peer address

### Problem

The overlay ACL maps the source address of a connection to a netmap peer.
In W21-4, the daemon did not check where the connection came in.
A host on the underlay can send a packet with the overlay address of a peer as its source.
When the replies also go to that host (for example, after a wrong or injected route), the TCP handshake finishes.
Then serve used the policy of the peer, not of the real sender.

The proof shows this on `main` (3464fdf) [C].
The outside host used the source `100.64.0.1` (node a). It got `HTTP/1.0 200 OK`.
node b printed `serve_allow spiffe://orblx.local/node/a from 100.64.0.1`.
Log: `/workspace/orblx-w18-proof/w24-c-baseline-main-3464fdf-serve-hardening.log`.

### Fix

- A peer source address counts only when the connection came in on the overlay TUN interface.
  The datapath writes a packet to TUN only after the QUIC session authenticated the peer SVID.
- On Linux, the overlay listener sets `IP_PKTINFO`. For each accepted socket, `getsockopt(IP_PKTOPTIONS)` gives the
  interface index of the first SYN. The daemon compares it with the index of the interface that has the overlay address.
- A peer address from a different interface gets `serve_deny forged-source from IP`. The connection closes before TLS.
- When the daemon cannot read the index, it gets `serve_deny ingress-unknown from IP`. The check fails closed.
- A source that is not a netmap peer still gets `serve_deny unknown-source from IP`.
- On macOS, the kernel API is not available. The listener prints `serve_ingress_check unavailable` one time,
  and the W21-4 source address check applies. See Caveats.

Code: `crates/orblx-serve/src/ingress.rs`, `admit` in `crates/orblx-serve/src/server.rs`.

### Tests

| Test | Label | What it shows |
| --- | --- | --- |
| `server::tests::a_forged_peer_address_is_rejected` | REAL | Source `100.64.0.1` (peer a) from a non-TUN interface gives `forged-source`. An unknown interface gives `ingress-unknown`. A non-peer gives `unknown-source`. |
| `ingress::tests::the_kernel_reports_the_loopback_ingress_for_a_loopback_connection` | REAL | On Linux, the kernel gives the loopback index for a loopback connection. The index of a different interface gives `Other`. |
| `ingress::tests::only_the_tunnel_index_is_tunnel` | REAL | Only the TUN index gives `Tunnel`. |

## 2. HTTP/1.1 requests and the body limit

### Behavior

- After TLS, hyper reads each request. hyper decodes `Content-Length` bodies and chunked bodies.
  hyper refuses a request with two different `Content-Length` values.
- The proxy reads the whole body before it opens `127.0.0.1:PORT`.
  It sends the body with one `Content-Length` header and no `Transfer-Encoding` header.
  The local web app reads one clear body length.
- The default body limit is 10485760 bytes (10 MiB). `orblx serve PORT --max-body BYTES` sets a different limit.
  The limit is in `serve.json` as `max_body_bytes`. Without the field, the default applies.
  A W21-4 `serve.json` keeps the same bytes and the same audit digest.
- A declared `Content-Length` above the limit gets `413 Payload Too Large` before the proxy reads the body.
  With `Expect: 100-continue`, the proxy sends no `100 Continue`, so the client does not send the body.
- A chunked body that goes above the limit gets `413`. The proxy then reads and drops at most 1 MiB more
  for at most 5 s, so that the client can read the response. The response has `Connection: close`.
- The daemon prints `serve_too_large from IP limit N` (or `funnel_too_large`).
- Time limits: 10 s for the request head, 60 s for the body (`408` after that).
- The proxy removes hop-by-hop headers in both directions. It sets `X-Forwarded-For` (the client IP)
  and `X-Forwarded-Proto: https`. It removes the client values of `Forwarded`, `X-Forwarded-For`, and `X-Forwarded-Proto`.
- In W24-C, a request with `Upgrade` got `501`.
  Since W25-4 (#81, 130fe357), a WebSocket upgrade (HTTP/1.1 `Upgrade: websocket`) goes to the app.
  Other upgrades, for example `h2c`, still get `501`. See [`docs/w25-serve-websocket.md`](w25-serve-websocket.md).
- An HTTP/1.0 client gets an HTTP/1.0 response. The W21-4 proof client uses HTTP/1.0.

Code: `crates/orblx-serve/src/http.rs`.

### Tests

| Test | Label | What it shows |
| --- | --- | --- |
| `http::tests::a_chunked_body_reaches_the_app_with_one_content_length` | REAL | A 1000-byte chunked body reaches the app with `Content-Length: 1000`, no `Transfer-Encoding`, the same byte sum, and `X-Forwarded-For: 127.0.0.1` (the client value is gone). |
| `http::tests::a_body_at_the_limit_works_and_one_byte_more_gets_413` | REAL | Limit 1024: a 1024-byte chunked body gets `200`. A 1025-byte chunked body gets `413` and does not reach the app. |
| `http::tests::a_declared_length_above_the_limit_gets_413_before_the_body` | REAL | `Content-Length` above the limit gets `413`, with and without `Expect: 100-continue`. No `100 Continue`. |
| `http::tests::a_content_length_body_and_a_get_work` | REAL | A `PUT` with a body and an HTTP/1.0 `GET` work. |
| `http::tests::a_request_with_two_framing_headers_does_not_reach_the_app` | REAL | Two different `Content-Length` values do not reach the app. |
| `config::tests::a_body_limit_change_is_audited_and_kept` | REAL | `--max-body` writes one audit record. A limit of 0 is refused. |
| `config::tests::a_w21_serve_file_loads_with_funnel_off_and_the_default_body_limit` | REAL | A W21-4 file loads with funnel off and the default limit. |

## 3. Funnel off by default

- `plan` in `server.rs` gives the listeners for one serve state.
  It gives a funnel listener only for `funnel: true` with a listen address.
- `server::tests::funnel_stays_off_by_default` [REAL]: no state gives no listener. A W21-4 file without the
  `funnel` field gives no funnel listener. A listen address with `funnel: false` gives no funnel listener.
  `funnel: true` without a listen address does not load.
- `config::tests::funnel_is_off_by_default_and_each_change_is_audited` (W21-4) [REAL] still passes.

## Proof

```bash
SERVE_PROJECT=orblx-w24c-serve SERVE_IMAGE=orblx-w24c-serve:local \
SERVE_OVL=172.30.141 SERVE_OUT=172.30.142 \
ORBLX_NET_HOOK=/workspace/orblx-w18-proof/fix-container-egress.sh \
bash scripts/proof/serve-hardening.sh
```

The script uses the same Compose file and hosts as W21-4 (`scripts/proof/compose.serve.yml`).
The shared setup is in `scripts/proof/serve-lib.sh`. `serve-funnel.sh` (W21-4) uses it too.
The `SERVE_*` values are optional. They set the Compose project, the image tag, and the two networks, so that
parallel runs do not use the same names. The defaults are the W21-4 values.
`SERVE_BIN` runs the proof with a different `orblx` binary (the baseline run used the `main` binary).
The local web app on node b is `scripts/proof/serve-app.py`. It returns the body length, the framing headers, and the byte sum.
The HTTPS POST client is `scripts/proof/serve-post.py`.
The script does not print private keys, tickets, or SVID proofs.

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `node-a` | [C] | Overlay `100.64.0.1`. The ACL allows it. |
| `node-b` | [C] | Overlay `100.64.0.2`. Runs `orblx serve 8080` and the web app. Also on the outside network at `.12`. |
| `node-c` | [C] | Overlay `100.64.0.3`. The ACL denies it. |
| `outside` | [C] | `.20` on the outside network only. It has no orblx node. |

### Result

The run below is [C]. Log: `/workspace/orblx-w18-proof/w24-c-serve-hardening-branch.log` on the REAL host. It printed `proof_ok`.

| Step | Client | Result |
| --- | --- | --- |
| `orblx serve 8080` | - | `serve_listen 100.64.0.2:443 target 127.0.0.1:8080 max_body 10485760` |
| Funnel default | outside to `.12:8443` | TCP refused. `funnel status` prints `funnel off`. No `funnel_listen` line. |
| Over TUN | node-a | `HTTP/1.0 200 OK`, `serve_allow spiffe://orblx.local/node/a from 100.64.0.1` |
| Forged peer address | outside with source `100.64.0.1`, and node b routes `100.64.0.1/32` back to outside | Closed before TLS. `serve_deny forged-source from 100.64.0.1`. The count of `serve_allow` lines for node a did not change. |
| Over TUN after the forged step | node-a | `HTTP/1.0 200 OK` |
| Chunked, 1048576 bytes | node-a | `HTTP/1.1 200 OK`. The app got 1048576 bytes with `Content-Length` and no `Transfer-Encoding`. The byte sum matched. |
| Chunked, 10485760 bytes (the limit) | node-a | `HTTP/1.1 200 OK`. The app got 10485760 bytes. The byte sum matched. |
| Chunked, 10485761 bytes | node-a | `HTTP/1.1 413 Payload Too Large`. `serve_too_large from 100.64.0.1 limit 10485760` |
| `Content-Length: 10485761`, `Expect: 100-continue` | node-a | `413` and no `100 Continue` |
| `Content-Length: 4096`, `Expect: 100-continue` | node-a | `100 Continue`, then `HTTP/1.1 200 OK`. The byte sum matched. |
| App log | - | No body above 10485760 bytes reached the app. |
| ACL | node-c | Reset before TLS. `serve_deny spiffe://orblx.local/node/c from 100.64.0.3` |

The node logs had no `PRIVATE KEY` and no `BEGIN CERTIFICATE` line.

The same script with the `main` binary (3464fdf) stopped at the forged step. The forged GET got `200`. See section 1.

### W21-4 proof

`scripts/proof/serve-funnel.sh` (W21-4) ran with this change and printed `proof_ok` [C].
Log: `/workspace/orblx-w18-proof/w24-c-w21-serve-funnel-branch.log`.
The steps and the checks did not change. The script now gets its setup from `serve-lib.sh`.
`orblx audit verify-config` printed `ok`, `serve 1`, `funnel-on 1`, `funnel-off 1`, and `records 3`.

After the merge, both scripts run again on `main`. Logs: `w24-c-serve-hardening-main.log` and
`w24-c-w21-serve-funnel-main.log` in `/workspace/orblx-w18-proof/`.

## Caveats

- All hosts are [C] containers on one REAL host. No REAL multi-host run is in this change.
- The forged step adds a host route on node b, so that the replies go to the forger. Without this route, the replies go
  through TUN to the real peer, and a blind forger cannot finish the TCP handshake. The route shows the worst case.
- The TUN ingress check is Linux only. On macOS, serve keeps the W21-4 source address check. A macOS run is not in this change.
  The macOS CI job builds and tests the code, but it does not run a TUN.
- The ingress check does not check the inner source address of packets that come through a QUIC session.
  A peer that sends a packet with the source address of a different peer is a datapath ACL topic. It is not in this change.
  The reply to such a packet goes through TUN to the real peer, so the sender cannot finish the TCP handshake.
- The proxy keeps each request body in memory up to the limit. The limit applies to each request.
- In W24-C, WebSocket and other `Upgrade` requests got `501`. In W21-4, serve was a TCP stream proxy, so they passed.
  Since W25-4 (#81, 130fe357), WebSocket upgrades go to the app again. Other upgrades, for example `h2c`, still get `501`.
  See [`docs/w25-serve-websocket.md`](w25-serve-websocket.md).
- HTTP/2 is not in this change. The TLS ALPN value stays `http/1.1`.
