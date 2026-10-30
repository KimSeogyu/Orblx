# W25-13 SIEM log streaming

The coordinator streams each config audit record to the SIEM sinks in the policy (gap matrix row 51).
The SIEM can check from the sink output alone that no record is missing and that no record was changed.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the receivers, the owner node, the client host, and the Docker network are [C].
  The receivers stand in for a SIEM. The proof did not use a real Splunk or Datadog service.

The change adds no vendor SDK, no new crate, and no datapath change.
It uses the W25-7 delivery queue: the same thread, the same chain outbox, the same cursor files, and the same retry loop.
Out of scope: network flow logs, S3 or object sinks, and parsers for one SIEM vendor.

## 1. Policy

```json
{
  "owners": ["spiffe://orblx.local/node/owner"],
  "auditSinks": [
    {"name": "splunk", "type": "https", "url": "https://splunk.example.net:8088/services/collector/event",
     "format": "splunk-hec", "credentialFile": "splunk.token"},
    {"name": "dd", "type": "https", "url": "https://http-intake.logs.example.net/api/v2/logs",
     "format": "datadog", "credentialFile": "dd.key"},
    {"name": "lake", "type": "https", "url": "https://collector.example.net/orblx", "format": "ndjson"},
    {"name": "syslog", "type": "syslog-tls", "address": "syslog.example.net:6514", "caFile": "siem-ca.pem"}
  ],
  "acls": []
}
```

- `auditSinks` is optional. The default is an empty list. 8 sinks maximum. Each `name` is unique
  (1 to 32 characters: letters, digits, `-`, `_`).
- `type` is `https` or `syslog-tls`.
  - `https`: `url` is a plain `https://` URL (no user part, no query, no fragment). `format` is `ndjson` (default),
    `splunk-hec`, or `datadog`. Plain `http` is not accepted.
  - `syslog-tls`: `address` is `host:port`. It has no `url`, no `format`, and no credential file.
- `credentialFile` and `caFile` are plain file names (no `/`, no leading `.`) in the directory `ORBLX_AUDIT_SINK_DIR`
  of the coordinator. **The policy holds no secret.**
- Without `caFile`, the coordinator checks the server certificate with the public web roots (webpki).
  With `caFile`, it checks the certificate with the CA certificates in that PEM file only.
  There is no option to skip the certificate check.
- Only an owner SVID (mTLS) can add, change, or remove a sink. A scoped API token gets `403` (reason `sinks`) for all
  scopes, and the chain gets a `token-deny` record. A token that could remove a sink could hide its later calls from the SIEM.

## 2. Credential

- The file holds one printable token (no space). The coordinator removes one line end.
- `splunk-hec`: `Authorization: Splunk <token>`. `datadog`: `DD-API-KEY: <key>`. `ndjson`: `Authorization: Bearer <token>`
  (only when `credentialFile` is set).
- The coordinator reads the file when the sink task starts. A missing or bad file is a failure with step `credential`
  (or `ca`, or `sink-dir`), and the task tries again with the backoff.
- The coordinator does not write the credential to a log, the audit chain, the state dir, the policy, or a body.
  Log lines show the sink name and the failed step only. They do not show the URL path.

## 3. Wire formats

Each record becomes one body object, the same object as a W25-7 webhook body:

```
{"type":"orblx.config-audit","version":1,"id":"<record hash>","seq":<record index>,"record":{...}}
```

`record` is the audit record from `config-audit.jsonl`: `index`, `prev_hash`, `hash`, `at_unix`, `at_utc`, `actor`,
`action`, `target`, `before`, `after`, and `detail`. So each record has `seq`, `id`, and the chain hash.

| Format | Body of one POST (a batch of up to 500 records, about 1 MiB) |
| --- | --- |
| `ndjson` | One body object on each line. `Content-Type: application/x-ndjson` |
| `splunk-hec` | One HEC event on each line: `{"time":<at_unix>,"host":..,"source":"orblx-coord","sourcetype":"orblx:config-audit","event":<body object>}` |
| `datadog` | A JSON array: `{"ddsource":"orblx","service":"orblx-coord","hostname":..,"ddtags":"action:<a>,seq:<n>","message":"<body object as a string>"}` |
| `syslog-tls` | RFC 5425 octet-counting frames. Each frame is one RFC 5424 message: `<110>1 <at_utc> <host> orblx-coord - config-audit [orblx@32473 seq="<n>" id="<hash>" action="<a>"] <body object>` |

- HTTPS: a `2xx` reply is a delivery of the whole batch. All other replies and connection errors are failures.
  Headers `X-Orblx-First-Seq` and `X-Orblx-Count` give the batch range.
- Syslog TLS: the coordinator opens one TLS connection for each batch, writes the frames, and sends `close_notify`.
  The batch is delivered only when the server answers with its own `close_notify`. A TCP close without `close_notify`
  is a failure. A server that wants to ack must keep the frames before it sends `close_notify`.
- `host` is the coordinator `HOSTNAME`, or `-`.
- The connect timeout is 2 s. The reply (or ack) timeout is 5 s. TLS uses rustls (TLS 1.3 and 1.2).

## 4. Delivery

- The W25-7 queue delivers the sinks. One task for each sink reads `config-audit.jsonl` from its cursor and sends
  the records in chain order. It never skips a record.
- The cursor file is `audit-webhooks/<sha256("sink:<name>")[..16]>.json`:
  `{"version":1,"url":"sink:<name>","next":N,"failing":false}`. The task writes it with fsync after each delivered batch.
- A new sink starts at record 0, so the SIEM gets the full chain from the genesis record and can check every link.
- A change of the sink fields (not the name) restarts the task and keeps the cursor. A new name is a new sink.
  When you remove a sink from the policy, its task stops and its cursor file is deleted.
- After a failure the task waits 250 ms, then 500 ms, 1 s, 2 s, and 4 s (maximum), and sends the same batch again.
- When a sink starts to fail, the task writes **one** `sink-error` record (action code 34) with target `<name>` and detail
  `step <step> status <http status> seq <first seq>`. It writes no other `sink-error` record until a batch is delivered.
  The `failing` flag is in the cursor file, so a restart does not write a second record.
- An admin request only writes the chain. It never waits for a sink.
- Delivery is at least once. If the coordinator stops after a delivery and before the cursor write, it sends that batch again.
  **The SIEM must remove duplicates by `id`.** The verifier reports a duplicate as a failure, so that the proof can count them.

## 5. Verifier

`scripts/siem/orblx-siem-verify.py --format ndjson|hec|datadog|syslog [--count N] [--tip HASH] FILE...`

- It reads only the sink output and the Python standard library. It does not need the coordinator.
- It checks: the body type and version, `seq` 0, 1, 2, ... with no gap and no copy, `seq == record.index`,
  `id == record.hash`, the `prev_hash` link, SHA-256 over the canonical bytes (the same bytes as `orblx audit verify-config`),
  and `at_utc`. For HEC it also checks `time`, for Datadog `ddtags`, and for syslog the structured data.
- `--count` and `--tip` catch a removed last record. Get them from the coordinator (`orblx admin audit`) or from a later record.
- A Rust test checks that the action code table in the script is the same as `ConfigAction::ALL`.
  Another Rust test runs the script on all four formats, and on a changed copy and a short copy (they fail).

## 6. Proof

Script: `scripts/proof/siem-streaming.sh` (compose file `scripts/proof/compose.siem-streaming.yml`, receivers
`scripts/proof/siem-sink-receiver.py`). The script takes the W25-5 proof lock.

The sinks in the proof: `hec` (splunk-hec), `datadog`, `ndjson` (all on the HTTPS receiver `siemhttp`), `syslog`
(syslog TLS, certificate from the lab CA), and `bad` (syslog TLS, certificate from a different CA).
The lab CA, the server certificates, and the three credentials are files that the script makes with `openssl` and
Python `secrets`. The coordinator gets them read-only in `/sinks`.

Branch run: 2026-10-31 01:12 to 01:14 KST, commit `1013d94`, log `w25-m-siem-streaming-branch-1013d94.log`.

| Gate | Result | Mark |
| --- | --- | --- |
| 1. 1000 events to each sink | Each of the 4 sinks: 1000 of 1000 (records 50..1049), 0 gaps, 0 duplicates, order ok. Record latency max 107.3 to 114.0 ms. First write to last arrival 5116 to 5215 ms (limit 10000 ms). | [C] |
| 2. Verifier from sink output only | 4 of 4 formats `siem_verify_ok` (1050 records, the tip of the coordinator chain). A changed record, a removed middle record, and a removed last record each fail in each format (12 of 12). | [C] |
| 3. 60 s outage | Sinks down 60094 ms, 248 records written in that time. After recovery each sink got 248 of 248, 0 gaps, 0 duplicates, order ok. Admin p50: off 120.260 ms, on 116.374 ms (delta -3.886), sinks dead 119.615 ms (delta -0.645), limit 10 ms. | [C] |
| 4. SIGKILL restart | 104 records waiting. The cursors (`next` 1341) were the same after the restart. Each sink got 106 of 106 (records 1341..1446), 0 gaps, 0 duplicates. Final: 1447 records in each sink, `arrivals.jsonl` 1447 lines (no duplicate body). | [C] |
| 5. TLS certificate check | Sink `bad`: 0 records received, 28 server handshake failures, 28 coordinator `tls` failures, 1 `sink-error` record. | [C] |
| 6. Owner only; credential files only | Token `policy:write`: remove, add, and change a sink each get 403; the same sinks with a new ACL gets 200; 3 `token-deny` records with reason `sinks`. Credential hits 0 in the coordinator state, the 9 sink output files, 3657 container log lines, 1452 audit records, the policy, and the proof log. The control check found 3 of 3 credential files and 2 of 2 token files. | [C] |
| 7. W23-4 nat-realism | See below. | [C] |

Notes:

- The record latency is the receiver arrival time minus the Docker log time of the `config audit N` line. The Docker log
  time is up to about 60 ms late, so the minimum latency is negative (-61.1 ms).
- In gate 3 the records written during the outage wait for the sinks, so their latency is 50.8 to 60.6 s.
  The retry backoff maximum is 4 s.
- Gate 4 stops the receivers before the SIGKILL, so no batch is in flight. A kill between a delivery and the cursor
  write sends that batch again (at least once, section 4). The proof does not test that window.
- The receivers stand in for Splunk HEC, Datadog intake, and a syslog server. They check the auth header and keep the bytes.
  The proof did not send to a real vendor service.
