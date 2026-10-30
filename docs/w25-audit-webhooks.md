# W25-7 Audit webhooks

The coordinator posts each config audit record to the audit webhook URLs in the policy (gap matrix row 52).
The events include grant, revoke, revoke-all, token-deny, lock, policy-set, and node enroll.
SIEM streaming (row 51) is not in this change.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the receiver, the owner node, nodes `a` and `b`, the client host, and the Docker network are [C].

The change adds no new crypto design. The signature is HMAC-SHA256 (RFC 2104) from the `hmac` 0.12 crate.
That crate was already in `Cargo.lock` (`orblx-crypto` uses it). The change does not touch the datapath files.

## 1. Policy

```json
{
  "owners": ["spiffe://orblx.local/node/owner"],
  "auditWebhooks": ["https://siem.example.net/orblx/hook"],
  "acls": []
}
```

- `auditWebhooks` is optional. The default is an empty list (webhooks off).
- 8 URLs maximum. Each URL is 256 bytes maximum. The policy parser removes duplicate URLs.
- The scheme is `http` or `https`. The parser refuses user info, a query, a fragment, a bad host, and a bad port.
- `http` is for a receiver on a private network. Use `https` across a network that you do not control.
- The policy has no secret. The secret is not a policy field.
- Only an owner SVID (mTLS) can add, remove, or change a webhook URL. A scoped API token gets `403`
  (reason `webhooks`), for all scopes. A token that could remove a webhook could hide its later calls from the receiver.

## 2. Secret

- `ORBLX_AUDIT_WEBHOOK_SECRET_FILE` names a file with the secret. This is the preferred way.
- `ORBLX_AUDIT_WEBHOOK_SECRET` holds the secret. The file has priority.
- The secret is 32 to 1024 bytes. The coordinator removes one line end.
- Without a valid secret, the coordinator sends no webhooks. It writes one log line that says so.
- The coordinator does not write the secret to the log, the audit chain, the state dir, or a body.

## 3. Request

```
POST <url path>
Content-Type: application/json
X-Orblx-Signature: sha256=<hex HMAC-SHA256(secret, body)>
X-Orblx-Event-Id: <record hash>
X-Orblx-Seq: <record index>

{"type":"orblx.config-audit","version":1,"id":"<record hash>","seq":<record index>,"record":{...}}
```

- `record` is the audit record, as in `config-audit.jsonl`. `id` and `seq` are the `hash` and the `index` of the record.
- The receiver must compute the HMAC over the raw body bytes and compare in constant time.
  `scripts/proof/audit-webhook-receiver.py` is an example.
- A `2xx` reply is a delivery. All other replies, and connection errors, are failures.
- The connect timeout is 2 s. The reply timeout is 5 s. `https` uses rustls with the webpki roots.
- Log lines show only `scheme://host:port`. They do not show the URL path.

## 4. Delivery

- The audit chain is the durable outbox. The coordinator writes each record with fsync before the admin reply.
  The webhook path does not add work to the admin request.
- Delivery runs on its own OS thread (`orblx-audit-webhook`) with its own runtime. A slow or dead receiver cannot block an admin request.
- Each URL has one task and one cursor file: `audit-webhooks/<sha256(url)[..16]>.json` in the state dir
  (`{"version":1,"url":...,"next":N}`). The task writes the cursor with fsync and rename after each `2xx`.
- The task posts one record at a time, in chain order. It never skips a record.
  After a failure it waits 250 ms, then 500 ms, 1 s, 2 s, and 4 s (maximum), and sends the same record again.
- A new URL starts at the last `policy-load` or `policy-replace` record. That record is the change that added the URL.
- When you remove a URL from the policy, its task stops and its cursor file is deleted.
- Delivery is at least once. If the coordinator stops after a `2xx` and before the cursor write, it sends that record again after a start.
  **The receiver must remove duplicates by `id`** (`X-Orblx-Event-Id`).

## 5. Proof

Script: `scripts/proof/audit-webhooks.sh` (compose file `scripts/proof/compose.audit-webhooks.yml`).
Branch run: commit `473ab70`, release binary. Log: `/workspace/orblx-w18-proof/w25-g-audit-webhooks-branch-473ab70.log`.

| Gate | Result |
| --- | --- |
| 1. Each event in 2 s or less, same id and seq [C] | 22 of 22 delivered, id_seq_match 22, latency min 2.6 ms, p50 82.7 ms, max 104.5 ms (limit 2000 ms) |
| 2. HMAC-SHA256 header, secret from a file [C] | sig_ok 22 of 22. Original body `verify ok`, changed body `verify fail`, POST of a changed body with the old signature `401`. Token `webhooks_remove` and `webhooks_add`: `403` |
| 3. Receiver down 30 s [C] | down 30090 ms, 11 retries for seq 24, 5 events while down, all delivered within 1848 ms after up. Window 24..28: 5 of 5, order ok, 0 duplicates. All 0..28: 29 of 29 |
| 4. Coordinator SIGKILL with waiting events [C] | cursor next 29 before and after the kill. Window 29..35: 7 of 7, 0 lost, 0 duplicates. All 0..35: 36 of 36 |
| 5. Admin p50, on vs off, dead receiver [C] | n 40 each, 0 failures. p50 on 88.127 ms, dead 88.170 ms, off 87.125 ms. Delta on +1.002 ms, dead +1.045 ms (limit 10 ms). Owner policy-set with a dead receiver ok |
| 6. No secret or token text [C] | controls: secret file 1 of 1, token files 3 of 3. Hits: state 0, receiver files 0 (158 bodies), logs 0 (458 lines), audit records 0 (168), proof log 0. `verify ok records 168`, `verify-config ok` |
| 7. W23-4 gates [C] | `nat-realism.sh` prefix `orblx-w25g-natr-`: rtt limit 5 ms ok, relay prc_prc 0.602 ms lost 0/50 ok, relay sym_sym 0.551 ms lost 0/50 ok, `proof_ok`. Log: `/workspace/orblx-w18-proof/w25-g-nat-realism-branch-473ab70.log` |

Notes:

- The latency in gate 1 is from the Docker log time of the `config audit N` line to the receive time on the receiver.
  The two clocks are on the same REAL host. The task polls the chain every 100 ms, so most values are under 100 ms.
- Gate 3 uses a stopped receiver container. On this box, a stopped container name resolves to a proxy that replies `500`.
  The coordinator counts this as a failure and sends the record again, as for a refused connection.
- Gate 5 also adds `http://192.0.2.1:9000/hook` (TEST-NET-1, no route) to test the connect timeout.
- `cargo test --workspace --locked` [REAL]: exit 0. The unit tests include an RFC 4231 HMAC known answer,
  a changed body check, the URL rules, the token `webhooks` refusal, and in-order delivery after `500` replies with a resume from the cursor.
