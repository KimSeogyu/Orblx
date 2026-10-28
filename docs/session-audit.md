# Session audit hash chain

The product name is Orblx.
The command name is gyeol.
The crate is `gyeol-audit`.
The chain records three session events.
The events are session start, session end, and session deny.
Each record stores the previous SHA-256 hash.
The hash covers the previous hash and the canonical event bytes.
An auditor can check the export file.
The check does not use the data path.
The check does not open a TUN device.
The check does not use WireGuard.
The check does not use Headscale.
The check does not use DERP.

The Relay session id is `RelaySessionId` from `gyeol-relay`.
The frame session id is the datapath frame `session_id`.
The peer is a SPIFFE ID from `gyeol-identity`.
The ticket hash is `gyeol_identity::ticket_hash`.
That function returns the first 16 bytes of SHA-256 over the ticket bytes.

## Export

Run the demo.
The demo writes one deny and one successful session.
The successful session is one start and one end.
The ids and the times are fixed.

```bash
cargo run -p gyeol-cli -- audit demo --out chain.jsonl
```

The command prints the file path.
The command prints the tip hash.
The command prints the start counter.
The command prints the end counter.
The command prints the deny counter.
The demo tip is `7292992ea22a6755b81526c80ae3adfdf601a8753c3a4303b9a3f8509b552e92`.

The demo deny uses these values:

- The peer is `spiffe://gyeol.local/agent/worker`.
- The Relay session id is 16 bytes of `0xde`.
- The frame session id is 7.
- The ticket bytes are `w10-deny-ticket`.
- The reason is `destination`.
- The Unix time is `1700000000`.

The demo session uses these values:

- The peer is `spiffe://gyeol.local/user/ada`.
- The Relay session id is 16 bytes of `0x11`.
- The frame session id is 42.
- The ticket bytes are `w10-ok-ticket`.
- The start time is `1700000001`.
- The end time is `1700000061`.

The file is JSONL.
Each line is one record.
The fields are `index`, `prev_hash`, `hash`, `kind`, `at_unix`, `relay_session`, `frame_session`, `peer`, `ticket_hash`, and `reason`.
Hex values use lowercase characters.
`kind` is `start`, `end`, or `deny`.
`reason` is empty for start and for end.
A deny reason is `destination`, `revoked`, `ticket`, `expired`, or `missing`.

## Check

```bash
cargo run -p gyeol-cli -- audit verify --file chain.jsonl
```

A valid file prints `ok`.
The command then prints the tip hash and the three counters.
The counters come from the checked records.
The command reads the file again.
The command does not trust a side counter.

[`scripts/audit-smoke.sh`](../scripts/audit-smoke.sh) runs the demo and the check.

A changed event fails the check.
A broken previous hash fails the check.

## Hash bytes

The first previous hash is 32 zero bytes.
The hex form is `0000000000000000000000000000000000000000000000000000000000000000`.

The event bytes use this order:

1. One version byte. The value is 1.
2. One kind byte. 1 is start. 2 is end. 3 is deny.
3. Eight bytes. The time is Unix seconds. The order is big-endian.
4. Sixteen bytes. The Relay session id.
5. Four bytes. The frame session id. The order is big-endian.
6. Two bytes. The peer length. The order is big-endian.
7. The peer bytes. The text is the SPIFFE URI.
8. Sixteen bytes. The ticket hash.
9. Two bytes. The reason length. The order is big-endian.
10. The reason bytes. The text is the reason token.

The record hash is SHA-256.
The input is the previous hash and then the event bytes.
The check rebuilds those bytes from the JSONL fields.
The check compares the stored hash with the new hash.
The check compares each previous hash with the prior record hash.

The check proves that each record links to the previous record.
The check proves that each hash matches the event bytes.
