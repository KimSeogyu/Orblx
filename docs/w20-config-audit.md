# Config audit log

The coordinator writes each control-plane change to a hash chain.
The chain file is `config-audit.jsonl` in the coordinator state directory.
Each line is one record.
The crate `orblx-audit` owns the record format and the chain check.
The session chain from W10 stays in its own file.

## Record fields

| Field | Content |
| --- | --- |
| `index` | Zero-based position in the chain |
| `prev_hash` | Hash of the previous record. The first record uses 32 zero bytes |
| `hash` | SHA-256 over `prev_hash` and the canonical record bytes |
| `at_unix` | Unix time in seconds (UTC) |
| `at_utc` | The same time as `YYYY-MM-DDTHH:MM:SSZ`. The check compares it to `at_unix` |
| `actor` | Who made the change |
| `action` | The change class |
| `target` | The node name or the policy file name |
| `before` | SHA-256 of the state before the change |
| `after` | SHA-256 of the state after the change |
| `detail` | A short note. The note does not hold tokens or keys |

The canonical bytes are version, action code, `at_unix`, actor, target, `before`, `after`, and detail.
Each text has a big-endian u16 length before its bytes.
The time is big-endian.

## Actions

| Action | Actor | `before` and `after` |
| --- | --- | --- |
| `policy-load` | Coordinator SVID `spiffe://orblx.local/coord/{name}` | Last good policy digest in the chain, and the loaded file digest |
| `policy-replace` | Coordinator SVID | Old policy file digest, and new policy file digest |
| `policy-reject` | Coordinator SVID | Kept policy digest, and the refused file digest. `detail` holds the parse or test error |
| `enroll` | Enroll principal: `token:{token_id}` or `oidc:{subject}` | Zero digest, and the node state digest |
| `approve` | Admin caller SVID | Node state digest |
| `expire` | Admin caller SVID | Node state digest |
| `revoke` | Admin caller SVID | `deny.json` digest |
| `routes` | Node SVID that sent `advertise` | Node state digest. `detail` holds the old and new CIDR lists |
| `exit-node` | Node SVID that sent the exit offer | Node state digest |

The node state digest is SHA-256 over the JSON of name, overlay IP, SVID, owner, routes, exit-node offer, approval, and expiry.
The digest does not include endpoints, because NAT candidates change often.
An absent state uses 32 zero bytes.
A `routes` or `exit-node` call that does not change the node state does not write a record.
The coordinator writes `policy-load` one time at each start.
The policy file has no admin caller, so the policy actor is the coordinator SVID.
The token id is the first 16 hex characters of the token hash. The token id is not the token.

The serve path opens the chain at start.
The start stops when the chain fails the check.
An admin change, an enroll, a route change, or an exit-node change fails when the record write fails.
A policy record write failure prints `config audit write failed: ACTION` and keeps the policy decision.

## Commands

```bash
orblx admin audit --coord ADDR [--since TIME] [--json] [--verify] [--state DIR] [--coord-name NAME] [--bundle FILE]
orblx audit verify-config --file FILE
orblx coord advertise --coord ADDR --bundle FILE --state DIR [--route CIDR]... [--exit-node on|off]
```

`orblx admin audit` needs an owner SVID, like the other admin commands.
The coordinator checks the full chain on each call and sends the result with the records.
`TIME` is Unix seconds, `YYYY-MM-DDTHH:MM:SSZ`, or an age such as `30m`, `2h`, or `7d`.
`--since` filters the printed records. The check always covers the full chain.
`--json` prints one record on each line. The check line goes to stderr.
`--verify` prints only the check line.
The command exits 1 when the check fails.
`orblx audit verify-config` reads the file and checks the chain without the coordinator.
It prints the tip, a count for each action, and the record count.
`orblx coord advertise --exit-node on` sends the exit-node offer without `orblx up`.

## Container proof

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image, runs Compose, and changes the policy file |
| `coord` container | [C] | Coordinator. UDP 443. Policy file mount. Holds `config-audit.jsonl` |
| `owner` container | [C] | Owner SVID. Runs `orblx admin` |
| `a` container | [C] | Node a. Enrolls. Gets approve, expire, and revoke |
| `b` container | [C] | Node b. Enrolls. Sends a route change and an exit-node change |

The image is `orblx-audit:w20`.
The proof script is `scripts/proof/config-audit.sh`.
The Compose file is `scripts/proof/compose.audit.yml`.
The policy files are `scripts/proof/audit.hujson` and `scripts/proof/audit-v2.hujson`.
The proof uses enroll tokens. The script does not print tokens or private keys.

Run this command on the REAL Linux host:

```bash
scripts/proof/config-audit.sh
```

The script does these steps:

1. It starts the coordinator with `audit.hujson`.
2. It enrolls owner, a, and b.
3. It approves a and b.
4. Node b advertises `10.77.0.0/24` and offers to be an exit node.
5. It expires a, approves a again, and revokes a.
6. It writes `audit-v2.hujson` to the policy file. This is a policy replace.
7. It writes text that is not HuJSON to the policy file. This is a rejected load.
8. It prints `orblx admin audit` and `orblx admin audit --json --since START`.
9. It checks the chain with `orblx admin audit --verify` and `orblx audit verify-config`.
10. It changes one byte in the file: the target `a` of record 4 becomes `x`.
11. It checks that both checks fail, then prints `proof_ok`.

The recorded run output starts after the image build.
Times are UTC.

```text
=== [C] admin approve a and b ===
approved a
approved b
=== [C] route change on b ===
approved route 10.77.0.0/24
advertised 1
=== [C] exit-node change on b ===
exit_node approved
=== [C] admin expire a ===
expired a
=== [C] admin approve a ===
approved a
=== [C] admin revoke a ===
revoked a
deny_version 1
=== [C] policy replace ===
node owner 100.64.0.1 approved
node a 100.64.0.2 approved
node b 100.64.0.3 approved
nodes 3
=== [C] policy reject ===
node owner 100.64.0.1 approved
node a 100.64.0.2 approved
node b 100.64.0.3 approved
nodes 3
=== [C] coordinator log lines for the config audit ===
=== [C] admin audit ===
record 0 2026-10-29T23:52:19Z policy-load policy.hujson actor spiffe://orblx.local/coord/coord before 0000000000000000 after f081d14f3381ed35 detail start
record 1 2026-10-29T23:52:20Z enroll owner actor token:f912bdc2a90dc651 before 0000000000000000 after 8b2c59f190d1473c detail svid spiffe://orblx.local/node/owner ip 100.64.0.1 approved
record 2 2026-10-29T23:52:21Z enroll a actor token:c2e536c9b6b201fa before 0000000000000000 after d437fe3aeb5493b5 detail svid spiffe://orblx.local/node/a ip 100.64.0.2 pending
record 3 2026-10-29T23:52:22Z enroll b actor token:9ea07b06f8b36c32 before 0000000000000000 after 00afff0901e0ba27 detail svid spiffe://orblx.local/node/b ip 100.64.0.3 pending
record 4 2026-10-29T23:52:22Z approve a actor spiffe://orblx.local/node/owner before d437fe3aeb5493b5 after d3f636e2e1098f86
record 5 2026-10-29T23:52:23Z approve b actor spiffe://orblx.local/node/owner before 00afff0901e0ba27 after 5e7a5ce4425b266b
record 6 2026-10-29T23:52:23Z routes b actor spiffe://orblx.local/node/b before 5e7a5ce4425b266b after 663bc799d0933ce3 detail from [] to [10.77.0.0/24]
record 7 2026-10-29T23:52:24Z exit-node b actor spiffe://orblx.local/node/b before 663bc799d0933ce3 after fc892ab584815b84 detail offer on
record 8 2026-10-29T23:52:24Z expire a actor spiffe://orblx.local/node/owner before d3f636e2e1098f86 after 51777e9b3601a6cc
record 9 2026-10-29T23:52:25Z approve a actor spiffe://orblx.local/node/owner before 51777e9b3601a6cc after d3f636e2e1098f86
record 10 2026-10-29T23:52:26Z revoke a actor spiffe://orblx.local/node/owner before 0000000000000000 after c0dd6b0ec2b2b712 detail svid spiffe://orblx.local/node/a deny_version 1
record 11 2026-10-29T23:52:26Z policy-replace policy.hujson actor spiffe://orblx.local/coord/coord before f081d14f3381ed35 after 392a4d0ae55edbe6 detail file
record 12 2026-10-29T23:52:27Z policy-reject policy.hujson actor spiffe://orblx.local/coord/coord before 392a4d0ae55edbe6 after 87fe8a25bad51545 detail The policy file is not valid. expected ident at line 1 column 14
verify ok records 13 tip c3251ebfb5a6ac5258239b58670936a0a42128a422b0a23cb338878cb36e11e7
=== [C] admin audit --json --since START (first two lines) ===
{"index":0,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"ca63dfff8c5d371e9d5747d039ff31e8879c294f56654bc0efbfebb28a0ea19d","at_unix":1793317939,"at_utc":"2026-10-29T23:52:19Z","actor":"spiffe://orblx.local/coord/coord","action":"policy-load","target":"policy.hujson","before":"0000000000000000000000000000000000000000000000000000000000000000","after":"f081d14f3381ed35ad7067ba3734f704641a645634e8c3d25e3b7b4d3d6a8228","detail":"start"}
{"index":1,"prev_hash":"ca63dfff8c5d371e9d5747d039ff31e8879c294f56654bc0efbfebb28a0ea19d","hash":"a790aa6c4878fa34f96700a9e522866983668d86d30c164acec2ec30c760bb34","at_unix":1793317940,"at_utc":"2026-10-29T23:52:20Z","actor":"token:f912bdc2a90dc651","action":"enroll","target":"owner","before":"0000000000000000000000000000000000000000000000000000000000000000","after":"8b2c59f190d1473cafaf03854450a3475a1568abb332e1c5370eaeeb2fe366c5","detail":"svid spiffe://orblx.local/node/owner ip 100.64.0.1 approved"}
=== [C] admin audit --since 1h ===
verify ok records 13 tip c3251ebfb5a6ac5258239b58670936a0a42128a422b0a23cb338878cb36e11e7
=== [C] audit verify-config in the coordinator ===
ok
tip c3251ebfb5a6ac5258239b58670936a0a42128a422b0a23cb338878cb36e11e7
policy-load 1
policy-replace 1
policy-reject 1
approve 3
revoke 1
expire 1
routes 1
exit-node 1
enroll 3
records 13
=== [C] change one byte in the chain ===
changed byte offset 2271 from 'a' to 'x'
=== [C] admin audit --verify after the change ===
verify failed: The hash check failed at index 4.
The config audit chain check failed.
exit 1
=== [C] audit verify-config after the change ===
The hash check failed at index 4.
exit 1
proof_ok
```

The coordinator log has one line for each record:

```text
config audit 0 policy-load policy.hujson spiffe://orblx.local/coord/coord
config audit 1 enroll owner token:f912bdc2a90dc651
config audit 2 enroll a token:c2e536c9b6b201fa
config audit 3 enroll b token:9ea07b06f8b36c32
config audit 4 approve a spiffe://orblx.local/node/owner
config audit 5 approve b spiffe://orblx.local/node/owner
config audit 6 routes b spiffe://orblx.local/node/b
config audit 7 exit-node b spiffe://orblx.local/node/b
config audit 8 expire a spiffe://orblx.local/node/owner
config audit 9 approve a spiffe://orblx.local/node/owner
config audit 10 revoke a spiffe://orblx.local/node/owner
config audit 11 policy-replace policy.hujson spiffe://orblx.local/coord/coord
policy load failed: The policy file is not valid. expected ident at line 1 column 14
config audit 12 policy-reject policy.hujson spiffe://orblx.local/coord/coord
```

## Unit tests

`crates/orblx-audit/src/config.rs`:

- `every_record_kind_round_trips_and_verifies` writes one record for each of the 9 actions and checks the chain.
- `each_record_kind_has_its_own_line_and_utc_text` checks the action token and the UTC text on each line.
- `a_changed_byte_fails_the_check` changes one byte in a target, a detail, and an actor, and removes one line.
- `a_changed_digest_or_time_fails_the_check` changes an `after` digest and an `at_utc` text.
- `append_refuses_bad_text` refuses an actor with a space and a detail with a line break.
- `utc_text_matches_known_values` checks the UTC text encoder and parser.

`crates/orblx-coord/src/lib.rs`:

- `every_control_plane_change_writes_one_config_record` runs each change through the coordinator.
  It checks the record order, the actors, and the digests.
  It checks the `policy-load` record after a restart.
  It changes one byte, and then the admin check fails and the coordinator start fails.

## Limits

- The chain shows a change. The chain does not stop a person with root on the coordinator host from writing a new chain.
  Copy the tip to a second place to detect a full rewrite.
- `orblx coord token create` runs in its own process and does not write a record.
- One admin reply holds at most 160 KiB of records. Use `--since` for a long chain.
