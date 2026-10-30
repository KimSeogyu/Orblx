# W25-3 Scoped API tokens for the admin API

This change adds scoped API tokens to the coordinator admin API (gap matrix row 35).
The owner makes a token with a set of scopes and an expiry time.
The coordinator accepts a token call only for an operation in one of the token scopes.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the owner node, node `a`, the client host, and the Docker network are [C].

The change adds no new crypto design. It uses the primitives of the enroll token store (`store.rs`):
32 random bytes from `OsRng`, a SHA-256 digest, and a constant-time compare.

## 1. Token

- Text: `orblx-at1.` and the base64url text of 32 random bytes from `OsRng`.
- ID: the first 16 hex characters of the SHA-256 digest of the token text.
- The coordinator keeps only the SHA-256 digest (`hash_hex`) in `api-tokens.json` in the state directory (mode 0600).
  The store refuses to write a file that contains the token prefix or `PRIVATE KEY`.
- The coordinator compares the digest with a constant-time compare.
- Expiry: 1 second to 30 days, the same limit as an enroll token. The coordinator keeps the time in milliseconds.
  A token is expired from the millisecond `expires_unix_ms`.
- The coordinator reads the store at each call. A revoke has an effect at the next call. There is no cache.
- The coordinator shows the token text one time, in the `admin-token-create` reply.
  `orblx admin token-create --out FILE` writes it to FILE (mode 0600, new file only) and does not print it.
  Without `--out`, the CLI prints `api_token TOKEN` one time.
- Error text that contains the token prefix is not sent (`sanitize_protocol`).
  Log lines and audit records show only the token ID.

## 2. Scopes

Each admin operation has exactly one scope. The dispatch list comes from the same table (`apitoken::SCOPES`),
so an admin operation cannot be added without a scope decision.

| Scope | Operations |
| --- | --- |
| `nodes:read` | `admin-nodes`, `admin-users`, `admin-routes` |
| `nodes:write` | `admin-approve`, `admin-revoke`, `admin-revoke-all`, `admin-expire` |
| `grants:read` | `admin-grants` |
| `grants:write` | `admin-grant-approve`, `admin-grant-revoke` |
| `audit:read` | `admin-audit` |
| `lock:read` | `admin-lock` |
| `lock:write` | `admin-lock-init`, `admin-lock-sign`, `admin-lock-update` |
| `policy:read` | `admin-policy` (new) |
| `policy:write` | `admin-policy-set` (new) |
| none (owner SVID only) | `admin-token-create`, `admin-token-list`, `admin-token-revoke` |

- A token cannot make, list, or revoke tokens. Only the owner SVID (mTLS) can do this.
- `policy:write` replaces the policy. Since W25-3b, a token cannot add, remove, or change the policy owners
  (`403`, reason `owners`). Only the owner SVID can change the owners. See `docs/w25-token-no-escalation.md`.
- `admin-policy-set` checks the new text with `Policy::from_hujson` before it writes the file.
  The write uses a temporary file and a rename. The coordinator then writes a `policy-replace` audit record.

## 3. Call path

- A request with `api_token` uses only the token. A client certificate in the same connection does not add access.
- A request without `api_token` uses the owner SVID path of W19. This path did not change.
- Order of checks:
  1. An unknown, expired, or revoked token gets status `401`.
  2. An operation outside the token scopes gets status `403`.
  3. The coordinator runs the operation. A good result gets `200`. An operation error gets `400`.
  4. If the token check or the audit write fails, the call gets `500` and does not run (fail closed).
- The admin API is QUIC with JSON frames, so the status is in the new `Response.status` field.
- The CLI sends a token call with no client certificate. It prints `status N done_ms MS` and fails when the status is not `200`.

## 4. Audit

New config audit actions (in `orblx-audit`): `token-create`, `token-use`, `token-deny`, and `token-revoke`.

| Event | Records | Actor | Target | Detail |
| --- | --- | --- | --- | --- |
| Create | 1 | owner SPIFFE ID | token ID | `scopes S expires_unix_ms N` |
| Allowed call | 1 `token-use` | `api-token:ID` | token ID | `op X scope S` |
| Refused call | 1 `token-deny` | `api-token:ID` (`unknown` for an unknown token) | token ID | `op X scope S reason R status N` |
| Revoke | 1 | owner SPIFFE ID | token ID | `revoked_unix_ms N` |

The records are part of the hash chain. `orblx admin audit --verify` and `orblx audit verify-config` check the chain.

## 5. CLI

```text
orblx admin token-create --scope nodes:read[,SCOPE] --ttl 10m --out FILE --coord ADDR
orblx admin token-list --coord ADDR
orblx admin token-revoke ID --coord ADDR
orblx admin nodes --coord ADDR --token-file FILE --bundle trust-bundle.pem
orblx admin call admin-OP [ARG] --coord ADDR --token-file FILE --bundle trust-bundle.pem
orblx admin policy --coord ADDR
orblx admin policy-set FILE --coord ADDR
```

`--ttl` accepts `90`, `90s`, `30m`, `2h`, and `7d`. `call` sends a raw admin operation. The proof uses it to call every operation.

## 6. Tests

| Test | Label | What it shows |
| --- | --- | --- |
| `server::tests::a_token_gets_403_for_every_operation_outside_its_scope` | REAL | For each scope and each admin operation, a call through the coordinator dispatch gets `200`/`400` only in scope, and `403` for every other operation. An unknown token gets `401`. |
| `apitoken::tests::each_scope_allows_only_its_own_operations` | REAL | The full scope and operation matrix of the check. |
| `apitoken::tests::token_management_has_no_scope` | REAL | A token with all scopes gets `403` for the token operations. |
| `apitoken::tests::an_expired_token_is_refused_from_the_expiry_millisecond` | REAL | 1 ms before the expiry: allowed. At the expiry: `401`. |
| `apitoken::tests::a_revoked_or_unknown_token_is_refused` | REAL | A revoked token and an unknown token get `401`. |
| `apitoken::tests::create_use_deny_and_revoke_write_one_record_each_and_no_secret` | REAL | One record for each event. No token text in the state files. Store mode 0600. The chain check is ok. |
| `apitoken::tests::scopes_and_life_are_checked` | REAL | Unknown scopes, an empty list, and an expiry outside 1 s to 30 d are refused. |
| `admin::tests::token_create_needs_known_scopes_and_a_life`, `token_file_and_call_parse` | REAL | CLI parse of the token commands. |

## 7. Proof

Script: `scripts/proof/api-tokens.sh` (compose `scripts/proof/compose.api-tokens.yml`, policy `scripts/proof/api-tokens.hujson`).
The `client` host [C] has no SVID. It has only the trust bundle and the token files.
The script never prints a token. It prints `proof_ok`.

Branch log: `/workspace/orblx-w18-proof/w25-c-api-tokens-branch-644d7fd.log` (project `orblx-w25c-tokens`).

| Gate | Label | Result (branch) |
| --- | --- | --- |
| 1. `nodes:read` token on all 20 admin operations | [C] | `200` for `nodes`, `users`, `routes`. `403` for the other 17 (`approve`, `revoke`, `revoke-all`, `expire`, `grants`, `grant-approve`, `grant-revoke`, `audit`, `lock`, `lock-init`, `lock-sign`, `lock-update`, `policy`, `policy-set`, `token-create`, `token-list`, `token-revoke`). After the calls, node `a` is still enrolled and the policy owners did not change. |
| 1b. `policy:write` token | [C] | `policy-set` `200`, `nodes` `403`, `grant-approve` `403`. |
| 2. Expired token (TTL 3 s) | [C] | 21 calls `200`. First `401` (`The API token is expired.`) at expiry +185 ms. Limit 1000 ms. |
| 3. Revoked token | [C] | 19 calls `200` before the revoke. First `401` (`The API token is revoked.`) at revoke +114 ms. Limit 1000 ms. A later call also gets `401`. |
| 4. Audit | [C] | Each of the 4 tokens: exactly 1 `token-create` and 1 `token-revoke`. The `token-use` and `token-deny` counts are equal to the calls (read 3/17, policy 1/2, expire 21/1, revoke 19/2). `verify ok records 78`. `audit verify-config` ok. |
| 5. No token text | [C] | 0 hits in the coordinator state files, 0 in 167 container log lines, 0 in the audit records, 0 in the proof log. Control: the same check finds 4 of 4 token files. `api-tokens.json` mode 600. |
| 6. Owner SVID (mTLS) | [C] | `admin nodes` and `admin policy` work. Node `a` (not an owner) gets `The caller is not an owner.` |

The delta for gates 2 and 3 is the client time at the end of the first refused call minus the coordinator
expiry time or revoke time. All containers use the clock of the same host. One call takes about 110 ms in [C],
so the delta includes the time of one call.

After the merge, the proof runs again on `main`. Logs: `/workspace/orblx-w18-proof/w25-c-api-tokens-main-*.log`.
On `main` be8cbece, 2 of 3 runs failed at `audit verify-config did not print ok` while `verify ok` passed. The cause was a
pipe into `head -n 1` and `grep -q` with `pipefail`: the reader stopped early, the CLI got `SIGPIPE`, and the pipe failed.
The script now keeps each output in a variable before it checks it. 5 of 5 runs printed `proof_ok` after the fix.

## 8. W23-4 gates

The change does not touch the datapath. `scripts/proof/nat-realism.sh` (`ORBLX_NATR_PROFILE=release`) ran with
private names and subnets (`orblx-w25c-natr-`, `172.29.125.0/24`, `10.125.2x.0/24`), so it did not touch other proof stacks.
Log: `/workspace/orblx-w18-proof/w25-c-nat-realism-branch-644d7fd.log`. Result: `proof_ok` [C].

| Gate | Result (branch) |
| --- | --- |
| Direct RTT: direct avg at most plain avg + 5 ms | plain 0.038 ms, direct 0.228 ms. `rtt limit_ms 5 ok`. |
| prc relay: relay avg at most direct avg + 1 ms, 0 lost | 0.709 ms. 0/50 lost. `relay_gate ok`. |
| sym relay: relay avg at most direct avg + 1 ms, 0 lost | 0.822 ms. 0/50 lost. `relay_gate ok`. |

TCP bulk throughput (5 s, measured, not a gate): plain 35642.67, prc direct 972.93, prc relay 788.73,
sym relay 1101.61 Mbit/s. Other workers used the same host during the run. A run of `main` 8972192 by another track
on the same day gave 1413.70, 960.55 and 1050.48 Mbit/s (`w24f-base-8972192-run1-release-nat-realism.log`).

## 9. Shared files

These files are shared with other tracks. The diff in each is small.

- `crates/orblx-audit/src/config.rs`: 4 new `ConfigAction` values (26 to 29). `ALL` has 29 values.
- `crates/orblx-coord/src/state.rs`: a new `policy_file()` accessor.
- `crates/orblx-coord/src/proto.rs`: `Request.api_token` (optional) and `Response.status` (optional). Old clients and old replies stay valid.
- `crates/orblx-coord/src/error.rs`: `sanitize_protocol` also refuses text with the token prefix.

## 10. Caveats

- A token is a bearer secret. Keep the token file at mode 0600. Revoke a token that you do not use.
- The coordinator reads `api-tokens.json` at each token call. This is a small file read and a lock.
- `policy:write` cannot change the owners since W25-3b (see section 2).
- The proof uses one host clock. On real hosts, the client clock can differ from the coordinator clock.
