# W25-38 deny.json fails closed

Before this change, the node used an empty deny list when `deny.json` was not valid, could not be read, or was missing.
An empty deny list lets each revoked SVID and each revoked ticket nonce in again.
After this change, the node refuses SSH, file receive, new QUIC sessions, and `orblx ping` until it has a valid deny list.
The change adds no new key and no new crypto. Signing the deny list is W25-37.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts.
The results in this file come from `cargo test` only. This change has no [C] result and no REAL result yet.
The [C] proof `scripts/proof/w25-38-deny-damage.sh` is ready. Run it on the merge commit.

## Rules on the node

| State of `deny.json` | Node enrolled (`node-name` exists) | Node never enrolled |
|---|---|---|
| Valid | Use the list. | Use the list. |
| Not valid (corrupt or truncated) | Refuse. | Refuse. |
| Cannot read (not `NotFound`) | Refuse. | Refuse. |
| Missing | Refuse. | Empty list, as before. |

"Refuse" means:

1. The SSH server refuses each new login.
2. The SSH deny watch (each 100 ms) and the SSH recheck close the open SSH sessions.
3. The file receiver refuses each transfer.
4. The datapath refuses each new QUIC session and each frame.
5. `orblx up` starts with a refuse-all list and prints the error.
6. `orblx ping` stops with the error.

The error text names the file and ends with:
`The node refuses SSH, file receive, and new sessions until it has a valid deny list.`

The marker of enroll is the `node-name` file. Only `EnrollResult::write_state` writes it.
Lab nodes from `orblx issue` have no `node-name`, so they keep the old behavior for a missing file.
A `node-name` that the node cannot stat counts as enrolled.

## Reload: keep the last good set and make it stale

Each long-running reader (SSH server, file receiver, datapath) keeps one `DenyCache`. This is the same model as the agent guard (W25-38 E: no change).

1. A reader starts with a refuse-all set. The first good read replaces it.
2. A failed reload keeps the last good set and marks it stale. A stale set refuses each identifier and each nonce. It keeps its version and its entries.
3. A valid file with a higher version makes the set current. The same file again (same version, same `generated_at`, same lists) also makes the set current.
4. A valid file with a lower version does not change the set. A stale set stays stale. So a damaged file followed by an old file cannot move the list back.
5. The reader never uses an empty set in place of a bad file. An empty set comes only from "missing, never enrolled".

### What makes the datapath deny set stale

Only a local read, parse, or check failure of `deny.json` makes the set stale. The age of a valid list never makes it stale. No deny code reads a clock.

- `crates/orblx-identity/src/deny_file.rs:243` `DenyCache::stale` is the only function that marks a reader set stale. It calls `DenySet::mark_stale` (`crates/orblx-identity/src/deny.rs:72`).
- `crates/orblx-identity/src/deny_file.rs:224` calls it when `read_deny_file` fails (cannot read, or missing after enroll).
- `crates/orblx-identity/src/deny_file.rs:239` calls it when `DenySet::apply_json` refuses the text (not valid JSON, unknown fields, or a value that is not valid).
- The datapath calls `DenyCache::reload` each 100 ms (`crates/orblx-datapath/src/node.rs:807-850`). A failed blocking read task also counts as "cannot read".

The coordinator being offline does not change `deny.json`. The deny refresh of `orblx up` writes the file only after a good fetch. So a valid list stays current for as long as the coordinator is offline.
The "stale" path kind in `orblx status` (`crates/orblx-datapath/src/node.rs:60-63`) is a different thing. It shows that a peer sent no frame in the last 2 s. It does not gate frames and does not touch the deny set.

## Write

`orblx_identity::store_deny_file` is the only node writer. `orblx up`, `orblx ping --coord`, and the first deny fetch after enroll use it.

1. It parses the text. It refuses text that is not a valid deny document and keeps the old file.
2. It does not write when the text is the same as the file (`DenyStore::Same`).
3. It does not write when the file is valid and has the same or a higher version (`DenyStore::KeptCurrent`). So the list never moves back.
4. A file that is not valid does not block a valid new list.
5. It writes a temp file `.deny.json.tmp.<pid>.<n>` in the same directory with `create_new`, then calls `fsync` on the file.
6. It renames the temp file to `deny.json`, then calls `fsync` on the directory.
7. On an error, it removes the temp file and returns the error.

The callers do not ignore the result. `orblx up` prints each error and each `KeptCurrent`. `orblx ping --coord` stops on an error.

A crash before the rename leaves the temp file and the old `deny.json`. The reader uses the old file.
A crash before the first rename after enroll leaves no `deny.json`. The reader refuses.

## Enroll: refuse-all until the first mutual TLS deny fetch

The enroll reply has no deny list. Enroll is not mutual TLS, because the node has no certificate before enroll. So the node takes its deny list only from a mutual TLS request with its new SVID.

1. The enroll reply gives the node its SVID. Right after the reply, with no wait for a poll tick, the enroll client (`enroll_with_token`, `enroll_with_oidc`) opens a new mutual TLS connection with the new SVID and sends the `deny` request. The result is `EnrollResult::first_deny` (`FirstDeny::Fetched` or `FirstDeny::Failed`).
2. `write_state` writes `node-name` and the other node files, then writes the list with `store_deny_file` as the last file. Between `node-name` and `deny.json`, the file is "missing after enroll", and each reader refuses each peer.
3. `orblx coord enroll` and `orblx login` print `deny_list ready_ms N`. N is the refuse-all window, from the time the node got its SVID to a valid `deny.json` on disk. When the first fetch failed, the command tries one more fetch with `orblx_coord::fetch_first_deny_blocking`.
4. When both fetches fail (for example, the coordinator is not reachable), the command prints this error and `deny_list pending`, and the enroll stays done:
   `The node is enrolled, but it did not get its deny list from the coordinator. <error> The node refuses SSH logins, file receive, new sessions, and ping until it gets the list. `orblx up` gets the list when the coordinator is reachable.`
5. The node then stays refuse-all. The deny refresh of `orblx up` tries `policy-wait`, then `deny-wait`, then a `deny` fetch each 500 ms. Each fetch has a limit of 10 s (`DENY_FETCH_LIMIT`), so a stopped coordinator does not hold a fetch for the QUIC idle timeout (60 s). When the coordinator comes back, the node gets the list with no manual step.

This change needs no coordinator change. The `deny` request exists since W25-2. A node of this version enrolls with an older coordinator.

### Refuse-all window (`cargo test`, debug build, local coordinator)

`w25_38_enroll_test::w25_38_refuse_all_window_after_enroll_is_two_seconds_or_less`, 10 enrolls, gate 2000 ms or less:

| Run | Values (ms) | Max (ms) |
|---|---|---|
| 1 | 189, 186, 191, 192, 189, 190, 191, 192, 183, 189 | 192 |

The [C] proof gate 4 measures the same window with the release binary in containers.

### Coordinator not reachable after enroll (`cargo test`)

- `w25_38_enroll_test::w25_38_unreachable_coordinator_after_enroll_keeps_the_node_refuse_all`: the coordinator stops after the enroll reply. The fetch fails after the 10 s limit (10002 ms), and each reader still refuses.
- `up::tests::w25_38_node_recovers_its_deny_list_when_the_coordinator_comes_back_after_enroll`: the node is refuse-all with no coordinator. The deny refresh of `orblx up` runs. The coordinator starts on the same address. The node gets the valid list in 1079 ms with no manual step. The revoked peer is refused and the good peer is accepted.

## Gate tests (`cargo test`)

| Gate | Test | Result |
|---|---|---|
| Corrupt file | `deny_file::tests::w25_38_corrupt_deny_file_refuses` | pass |
| Corrupt file, never enrolled | `deny_file::tests::w25_38_corrupt_deny_file_refuses_when_never_enrolled` | pass |
| Truncated file | `deny_file::tests::w25_38_truncated_deny_file_refuses` | pass |
| Missing after enroll | `deny_file::tests::w25_38_missing_deny_file_after_enroll_refuses` | pass |
| Missing, never enrolled | `deny_file::tests::w25_38_missing_deny_file_never_enrolled_keeps_empty` | pass |
| Cannot read | `deny_file::tests::w25_38_unreadable_deny_file_refuses` | pass |
| Refuse-all set | `deny_file::tests::w25_38_refuse_all_set_refuses_each_identifier` | pass |
| Reload failure: last good set, stale | `deny_file::tests::w25_38_reload_failure_keeps_the_last_good_set_and_goes_stale` | pass |
| Cache of a lab node | `deny_file::tests::w25_38_cache_of_a_never_enrolled_node_without_a_file_is_empty` | pass |
| Crash during write | `deny_file::tests::w25_38_crash_during_write_keeps_old_file` | pass |
| Crash during first write | `deny_file::tests::w25_38_crash_during_first_write_after_enroll_refuses` | pass |
| Writer refuses bad text | `deny_file::tests::w25_38_store_refuses_invalid_text_and_keeps_old_file` | pass |
| Writer skips same text | `deny_file::tests::w25_38_store_skips_same_text_and_leaves_no_temp` | pass |
| Writer never moves back | `deny_file::tests::w25_38_store_never_moves_the_deny_list_back` | pass |
| SSH login (4 kinds) | `server::tests::w25_38_ssh_login_refuses_when_the_deny_file_is_corrupt_truncated_missing_or_unreadable` | pass |
| SSH open session (4 kinds) | `server::tests::w25_38_ssh_open_session_stops_when_the_deny_file_is_corrupt_truncated_missing_or_unreadable` | pass |
| File receive (4 kinds) | `file::tests::w25_38_file_receive_refuses_when_the_deny_file_is_corrupt_truncated_missing_or_unreadable` | pass |
| New QUIC sessions (4 kinds), valid file traffic | `hello_tests::w25_38_new_quic_sessions_refuse_when_the_deny_file_is_corrupt_truncated_missing_or_unreadable` | pass |
| `orblx up` start (4 kinds) | `up::tests::w25_38_new_sessions_refuse_when_the_deny_file_is_corrupt_truncated_missing_or_unreadable` | pass |
| Ping (4 kinds) | `ping::tests::w25_38_ping_refuses_when_the_deny_file_is_corrupt_truncated_missing_or_unreadable` | pass |
| After enroll, each reader refuses until the first mutual TLS fetch; then the valid list is used | `w25_38_enroll_test::w25_38_after_enroll_every_reader_refuses_until_the_first_mtls_deny_fetch` | pass |
| Refuse-all window, 10 enrolls, 2000 ms or less | `w25_38_enroll_test::w25_38_refuse_all_window_after_enroll_is_two_seconds_or_less` | pass |
| Coordinator not reachable after enroll: refuse-all, clear error | `w25_38_enroll_test::w25_38_unreachable_coordinator_after_enroll_keeps_the_node_refuse_all` | pass |
| Coordinator comes back: recovery with no manual step | `up::tests::w25_38_node_recovers_its_deny_list_when_the_coordinator_comes_back_after_enroll` | pass |
| renew_test (file not changed; it uses `write_state` with the first deny list from the enroll client) | `renew_test::*` | pass |

Each 4-kind test uses corrupt, truncated, missing after enroll, and unreadable (a directory in place of the file), and counts 0 accepted.

## [C] proof (run on the merge commit)

`scripts/proof/w25-38-deny-damage.sh` with `compose.w25-38-deny-damage.yml` and `w25-38-deny-damage.hujson`.

1. Nodes a, b, and allowed enroll. With a valid `deny.json` on b, a and allowed can SSH to b and ping b. The name `allowed` sorts before `b`, so b accepts its new QUIC sessions (the node with the lower name dials).
2. The owner revokes a. a is refused. allowed is still accepted (traffic with a valid file does not change).
3. Gate 3 (merge blocker): the coordinator stops for `ORBLX_DENY_OFFLINE_SECS` (default 600 s) and `deny.json` on b stays valid. Node a stops, so its dial attempts do not count. allowed sends ICMP to the overlay IP of b each 0.5 s, and each 30 s allowed makes one SSH login and one `orblx ping` (a new QUIC session) to b. Pass: 0 ICMP loss, each probe accepted, the b counter `orblx_node_refused` (new in this change: sessions and frames that the identity, ticket, or deny check refused) does not change, no new deny file error in the b log, and the same valid deny version. The proof prints `summary w25_38_gate3 ... refused_frames 0`.
4. The coordinator stays stopped, so b cannot get a new list. For each kind (corrupt, truncated, missing, unreadable), the proof takes `ORBLX_DENY_SAMPLES` (default 3) samples. Each sample is one SSH login and one ping from a to b. Each must be refused. The proof checks that the file is still damaged and that b still runs.
5. The coordinator starts again. b gets a valid list. allowed is accepted again and a is still refused.
6. Gate 4: `ORBLX_DENY_WINDOW_ENROLLS` (default 10) more enrolls. Each prints `deny_list ready_ms N`. Each N must be 2000 ms or less. The proof prints `summary w25_38_window ... over 0`.

Pass: `summary ... samples N accepted 0 unknown 0` with N >= 1, then `proof_ok`, and a `proof_contention` line with `unknown_samples 0`.

## Known limits

- The coordinator writes its own `deny.json` with temp file, `fsync`, and rename, but without a directory `fsync`. This item does not change it. The directory `fsync` on the coordinator moves to W25-37 (deny signing).
- A crash can leave `.deny.json.tmp.*` files on the node. The reader ignores them. This item does not remove them.
- A stale set also stops open SSH sessions and datapath frames. The datapath does not close the open links when the set goes stale, but it refuses each frame.
- After enroll, the node refuses each peer until its first deny fetch over mutual TLS. When the coordinator is not reachable, this time has no upper limit. The node does not use a list from the enroll reply.
