# W21-4 serve and funnel

`orblx serve PORT` publishes the local TCP port `127.0.0.1:PORT` over HTTPS on the overlay address of the node.
`orblx funnel on --listen IP:PORT` also publishes it on one outside address. Funnel is off by default.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test`.
- **[C]**: a container. The nodes, the outside host, and both networks are [C].

## Commands

```bash
orblx serve PORT [--https-port N] [--state-dir DIR]
orblx serve off [--state-dir DIR]
orblx serve status [--state-dir DIR]
orblx funnel on --listen IP:PORT [--state-dir DIR]
orblx funnel off [--state-dir DIR]
orblx funnel status [--state-dir DIR]
orblx audit verify-config --file DIR/serve-audit.jsonl
```

The default HTTPS port is 443. The default state directory is `/var/lib/orblx`.

## How it works

- The CLI writes `serve.json` in the node state directory. The CLI is the only writer of `serve.json` and of `serve-audit.jsonl`.
- The node daemon (`orblx up`) reads `serve.json` again every 300 ms. It opens and closes the listeners.
  The daemon prints `serve_listen`, `funnel_listen`, `serve_closed`, and `funnel_closed` lines.
- The overlay listener binds `OVERLAY_IP:HTTPS_PORT`. It does not bind `0.0.0.0`.
- The funnel listener binds the one address from `--listen`.
  The CLI refuses `0.0.0.0` and an address in `100.64.0.0/10`. Funnel needs serve on.
- When funnel goes off, the daemon stops the funnel listener and all open funnel connections.

### Certificate

The TLS certificate is the node SVID (`cert.pem` and `key.pem` in the state directory). The orblx.local CA (`bundle.pem`) signs it.
The SVID has one URI SAN (`spiffe://orblx.local/node/NAME`) and no DNS name.
A client checks the chain against `bundle.pem` and checks the URI SAN. A host name check does not apply.
The daemon reads the SVID files for each new connection. A renewed SVID applies to the next connection.
The key stays in the daemon. The daemon does not log the key or the certificate.

### Access control

- The daemon maps the source address of each overlay connection to a peer in the netmap.
  The overlay authenticates each peer with its SVID, so the source address names one SPIFFE ID.
- The daemon reads `policy.hujson` in the state directory for each connection.
  It calls the policy check for that SPIFFE ID, the node SPIFFE ID, TCP, and the HTTPS port. The default is deny.
- A denied connection closes before the TLS handshake. The daemon prints `serve_deny URI from IP`.
  A source that is not a netmap peer gets `serve_deny unknown-source from IP`.
- An allowed connection prints `serve_allow URI from IP`.
- Funnel has no ACL. Funnel is a public opt-in. Any host that can reach the funnel address can open the HTTPS port.
  Turn funnel on only for a service that is safe to publish.

### Audit

Each change appends one record to `serve-audit.jsonl` with the orblx config chain (`orblx-audit`).
The actions are `serve`, `serve-off`, `funnel-on`, and `funnel-off`.
Each record has the actor (the node SPIFFE ID), the time, the SHA-256 of `serve.json` before and after, and a detail line.
The CLI checks the whole chain before it changes the state. A broken chain blocks the change.
A command that changes nothing writes no record.

## Proof

```bash
bash scripts/proof/serve-funnel.sh
```

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `node-a` | [C] | Overlay `100.64.0.1`. The ACL allows it. |
| `node-b` | [C] | Overlay `100.64.0.2`. Runs `orblx serve 8080` for a local web app. Also on the outside network at `172.30.42.12`. |
| `node-c` | [C] | Overlay `100.64.0.3`. The ACL denies it. |
| `outside` | [C] | `172.30.42.20` on the outside network only. It has no orblx node. |

The overlay network is `172.30.41.0/24`. The outside network is `172.30.42.0/24`.
The policy file is `scripts/proof/serve.hujson`. The HTTPS client is `scripts/proof/serve-get.py` (Python `ssl`).
The script does not print private keys, tickets, or SVID proofs.

### Result

The run below is [C]. Log: `/workspace/orblx-w18-proof/w21-4-dev2-serve-funnel.log` on the REAL host. It printed `proof_ok`.

| Step | Client | Target | Result |
| --- | --- | --- | --- |
| Before serve | node-a | `100.64.0.2:443` | TCP refused |
| `orblx serve 8080` | node-a (ACL accept) | `100.64.0.2:443` | `HTTP/1.0 200 OK`, TLSv1.3, SAN `spiffe://orblx.local/node/b` |
| | node-c (ACL deny) | `100.64.0.2:443` | Reset before TLS. Log: `serve_deny spiffe://orblx.local/node/c from 100.64.0.3` |
| Funnel off (default) | outside | `172.30.42.12:8443` | TCP refused |
| | outside, routed to the overlay address | `100.64.0.2:443` | Closed before TLS. Log: `serve_deny unknown-source from 172.30.42.20` |
| `orblx funnel on --listen 172.30.42.12:8443` | outside | `172.30.42.12:8443` | `HTTP/1.0 200 OK`, TLSv1.3. Log: `funnel_accept from 172.30.42.20` |
| | node-c | `100.64.0.2:443` | Still denied |
| `orblx funnel off` | outside | `172.30.42.12:8443` | TCP refused. Log: `funnel_closed 172.30.42.12:8443` |
| | node-a | `100.64.0.2:443` | `HTTP/1.0 200 OK` |

`orblx audit verify-config` on node-b printed `ok` with `serve 1`, `funnel-on 1`, `funnel-off 1`, and `records 3`.
The script then changed one byte of a copy of the chain. `verify-config` rejected the changed copy.
`orblx serve status` and `orblx funnel status` wrote no record.
The node logs had no `PRIVATE KEY` and no `BEGIN CERTIFICATE` line.

## Caveats

- All hosts are [C] containers on one REAL host. The outside network is a [C] bridge. It stands in for a public network.
- Funnel binds one address on the node. It does not configure a public DNS name, a public certificate, or a port forward.
  A browser that does not trust the orblx.local CA shows a certificate error. A public CA certificate is not in this change.
- The overlay ACL uses the source overlay address. A host on the same underlay link can send a packet to the overlay address.
  The proof shows that a source that is not a netmap peer gets `serve_deny unknown-source`.
  A packet with a forged peer source address cannot finish the TCP handshake, because the reply goes through the overlay to the real peer.
  The proof does not test a forged source address.
- The proof uses a static netmap with `orblx up --netmap`. The policy file is the same file on each node.
- Serve and funnel run in `orblx up`. `orblx nat run` does not run serve.
