# W25-4 serve WebSocket pass-through

This change lets `orblx serve` and `orblx funnel` send WebSocket connections to the local app.
In W24-C (`docs/w24-serve.md`), serve answered each `Upgrade` request with `501`.
Now a WebSocket upgrade (HTTP/1.1 `Upgrade: websocket`) goes to the app. All other upgrades still get `501`.
This change replaces the `Upgrade` lines in `docs/w24-serve.md`.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The nodes, the outside host, and both Docker networks are [C].

The change adds no new crypto design, no new dependency, no new listener, and no new port.
Funnel stays off by default.

## 1. Behavior

- serve uses the same listener and the same connection as before. The W24-C checks run first, before TLS:
  - The ingress check (`serve_deny forged-source from IP`).
  - The overlay ACL (`serve_deny SVID from IP`, `serve_deny unknown-source from IP`).
- After TLS, hyper reads the request. A request with an `Upgrade` header gets one of these results:

| Request | Result | Log line |
| --- | --- | --- |
| `GET`, HTTP/1.1, `Upgrade` is exactly `websocket`, `Connection` has `upgrade`, `Sec-WebSocket-Key` and `Sec-WebSocket-Version` are present, no body | The request goes to the app | `serve_ws_open from IP` |
| Any other upgrade (for example `h2c`, or `websocket, h2c`), or a WebSocket request with a body | `501`. The request does not go to the app | `serve_upgrade_refused from IP` |

- The proxy sends the request to `127.0.0.1:PORT` with `Upgrade: websocket`, `Connection: Upgrade`,
  `X-Forwarded-For`, and `X-Forwarded-Proto: https`.
- When the app answers `101` with `Upgrade: websocket`, the proxy sends `101` to the client.
  Then it copies bytes in the two directions until one side closes.
  At the end, it prints `serve_ws_closed from IP up N down N` (N is a byte count).
- When the app answers with a different status, the proxy sends that answer to the client. No tunnel opens.
- When the app answers `101` with a different `Upgrade` value, the client gets `502`.
- The body limit applies to HTTP request bodies. It does not apply to the WebSocket bytes after `101`.
- The tunnel belongs to its connection task. When serve stops the listener (for example, `orblx serve off`),
  the tunnel stops too.
- The log has no request path, no `Sec-WebSocket-Key`, and no message data.
- With funnel on, a funnel connection uses the same code. Its lines start with `funnel_`.

Code: `crates/orblx-serve/src/http.rs` (`proxy`, `is_websocket`, `websocket`, `serve_connection`).

## 2. Tests

| Test | Label | What it shows |
| --- | --- | --- |
| `http::tests::a_websocket_upgrade_passes_100_messages_both_ways` | REAL | `101` with the app `Sec-WebSocket-Accept`. 100 messages go out and come back the same. The total is above the 1024-byte body limit. The app saw `Upgrade`, `Connection`, and `X-Forwarded-For`. |
| `http::tests::an_upgrade_that_is_not_websocket_gets_501_and_does_not_reach_the_app` | REAL | `h2c`, `websocket, h2c`, `POST`, no key, no `Connection: Upgrade`, and a body: each gets `501`. The app got 0 requests. |
| `http::tests::an_app_that_refuses_the_upgrade_sends_its_answer_and_no_tunnel` | REAL | The app answer `403` goes to the client. No tunnel opens. |
| `http::tests::dropping_the_connection_stops_the_tunnel` | REAL | An abort of the connection task closes the open tunnel. |
| All W24-C serve tests (`server`, `config`, `ingress`, `http`) | REAL | They still pass. |

`cargo test --workspace --locked`: 499 passed, 0 failed (REAL, Linux).
`cargo clippy --workspace --all-targets --locked -- -D warnings`: no warnings.

## 3. Proof

Script: `scripts/proof/serve-websocket.sh`. It uses `scripts/proof/serve-lib.sh` (the W21-4 and W24-C setup).
New tools: `scripts/proof/serve-ws.py` (client) and `scripts/proof/serve-ws-app.py` (echo app).
The two tools use only the Python standard library. They do the RFC 6455 framing.
The client masks each frame. It checks `Sec-WebSocket-Accept` and the URI SAN of node b.

Topology [C]: nodes a, b, and c on one bridge. node b and the outside host are on a second bridge.
The app on node b listens on `127.0.0.1:8090`. node b runs `orblx serve 8090`.

| Gate | Label | Result |
| --- | --- | --- |
| 1. Echo, 100 messages, no loss | [C] | `sent 100 received 100 lost 0 bytes 279264 largest 70000 close yes`. The app printed `messages 100 bytes 279264 unmasked 0 xff 100.64.0.1`. node b printed `serve_ws_closed from 100.64.0.1 up 279904 down 279500`. |
| 2. Forged source upgrade | [C] | The outside host used the source `100.64.0.1` with a route back. The client got `tls_failed`. node b printed `serve_deny forged-source from 100.64.0.1`. `serve_allow` lines 3 -> 3, `serve_ws_open` 1 -> 1, `serve_tls_failed` 0 -> 0: the deny came before TLS. |
| 3. ACL-denied node | [C] | node c got `tls_failed`. node b printed `serve_deny spiffe://orblx.local/node/c from 100.64.0.3`. `serve_ws_open` 1 -> 1. |
| 4. Not WebSocket | [C] | `Upgrade: h2c` and `Upgrade: websocket, h2c` each got `HTTP/1.1 501 Not Implemented`. Two `serve_upgrade_refused` lines. The app log kept 1 connection line. |
| Funnel off, one listener | [C] | `funnel off`. The outside host on port 8443: `ConnectionRefusedError`. node b had 1 TCP listener on port 443 and 0 on port 8443. 0 `funnel_listen` lines. |
| 6. No keys in the logs | [C] | 0 PEM lines. The client wrote its 2 `Sec-WebSocket-Key` values to a file on node a. 0 of them are in the node logs or the app log. The path `/chat` is not in a log. |

After gates 2 and 3, node a opened a new WebSocket. It sent and got 10 messages.

The script printed `proof_ok` in 5 runs with the debug binary and 1 run with the release binary.
Logs: `/workspace/orblx-w18-proof/w25-d-serve-websocket-run3.log` to `-run6.log`, and
`/workspace/orblx-w18-proof/w25-d-serve-websocket-release-run1.log`.
Runs 1 and 2 stopped on proof script errors (a listener count that included the `orblx ssh` port 22,
and a log pattern with `^` on prefixed lines). The script has the fixes.

### Echo round-trip time [C]

These are measurements, not gates. Each message goes node a -> overlay -> node b serve -> app and back.

| Binary | Median ms | Max ms | Largest message (bytes) |
| --- | --- | --- | --- |
| debug, branch (runs 3 to 6) | 15.729, 16.413, 18.401, 16.792 | 1091.565, 996.407, 1260.032, 1033.499 | 70000 |
| debug, main 130fe357 | 15.974 | 1149.397 | 70000 |
| release, branch (before the merge) | 0.202 | 56.961 | 70000 |
| release, main 130fe357 | 0.256 | 77.254 | 70000 |

Logs on main: `/workspace/orblx-w18-proof/w25-d-serve-websocket-main-130fe357.log` (debug) and
`/workspace/orblx-w18-proof/w25-d-serve-websocket-release-main-130fe357.log` (release, `SERVE_BIN` set to
`target/release/orblx`). The release run on main also printed `proof_ok`, with 100 sent, 100 received, and 0 lost.

The max is for a message of 65536 or 70000 bytes.
The debug build is slow for the datapath crypto. The release build shows this. Set `SERVE_BIN` to a release
binary to measure the release numbers.
`TCP_NODELAY` on the serve sockets did not change the debug numbers (median 16.413, max 996.407 in one run).
The change does not set it.

## 4. Other proofs on this branch

| Proof | Label | Result | Log |
| --- | --- | --- | --- |
| W24-C `scripts/proof/serve-hardening.sh` | [C] | `proof_ok` | `/workspace/orblx-w18-proof/w25-d-serve-hardening.log` |
| W21-4 `scripts/proof/serve-funnel.sh` | [C] | `proof_ok` | `/workspace/orblx-w18-proof/w25-d-serve-funnel.log` |
| W23-4 `scripts/proof/nat-realism.sh` (release) | [C] | `proof_ok`. `rtt limit_ms 5 ok`. Relay gate ok: prc_prc relay 0.796 ms, sym_sym relay 0.772 ms, direct 0.477 ms, slack 1 ms, 0/50 lost. | `/workspace/orblx-w18-proof/w25-d-nat-realism.log` |

## 5. Caveats

- HTTP/2 and the HTTP/2 extended CONNECT for WebSocket (RFC 8441) are not supported. serve uses HTTP/1.1 only.
- serve does not read or check the WebSocket frames after `101`. The app checks them.
- serve does not check `Origin`. The ACL decides who can connect. The app can check `Origin`.
- An open tunnel has no idle timeout in serve. It closes when a side closes, or when serve stops the listener.
- The proof runs on one Linux host in containers [C]. macOS runs only the unit tests (CI).

Note: a first W23-4 run on the same host during `cargo test --workspace` failed the sym_sym relay gate
(relay 4.280 ms, direct 2.129 ms). The host CPU was busy. The rerun on an idle host passed.
Log: `/workspace/orblx-w18-proof/w25-d-nat-realism-run1-under-cargo-test.log`.
