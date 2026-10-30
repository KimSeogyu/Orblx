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
