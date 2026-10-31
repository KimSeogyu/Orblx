# W25-38 deny.json fails closed

Before this change, the node used an empty deny list when `deny.json` was not valid, could not be read, or was missing.
An empty deny list lets each revoked SVID and each revoked ticket nonce in again.
After this change, the node refuses SSH, file receive, new QUIC sessions, and `orblx ping` until it has a valid deny list.
The change adds no new key and no new crypto. Signing the deny list is W25-37.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts.
The results in this file come from `cargo test` only. This change has no [C] result and no REAL result yet.
The [C] proof `scripts/proof/w25-38-deny-damage.sh` is ready. Run it on the merge commit.

## Release note

The enroll reply now has the deny list of the node. A node of this version does not enroll with an older coordinator.
**Upgrade the coordinator and all nodes together.**

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

## Write

`orblx_identity::store_deny_file` is the only node writer. `orblx up`, `orblx ping --coord`, and enroll use it.

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

## Enroll

The coordinator puts the deny list of the node in the `detail` field of the enroll reply.

- The list comes only on the enroll connection to the coordinator. The node verifies the coordinator certificate with the trust bundle. Enroll is not mutual TLS, because the node has no certificate before enroll. There is no new key and no new crypto. The list is not signed (W25-37).
- `write_state` writes the list with `store_deny_file`, so the version rule above applies.
- A coordinator before this change sends no list. The enroll then fails with:
  `Version mismatch: the coordinator did not send a deny list at enroll. Upgrade the coordinator and all nodes together.`
- A list that is not valid fails the enroll.

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
| Enroll list never moves back | `w25_38_enroll_test::w25_38_enroll_deny_list_never_moves_back` | pass |
| Old coordinator: version mismatch | `w25_38_enroll_test::w25_38_enroll_with_an_old_coordinator_fails_closed_with_version_mismatch` | pass |
| Enroll writes `deny.json` | `tests::two_nodes_keep_ips_after_restart` (orblx-coord) | pass |
| renew_test (assertions not changed) | `renew_test::*` | pass |

Each 4-kind test uses corrupt, truncated, missing after enroll, and unreadable (a directory in place of the file), and counts 0 accepted.

## [C] proof (run on the merge commit)

`scripts/proof/w25-38-deny-damage.sh` with `compose.w25-38-deny-damage.yml` and `w25-38-deny-damage.hujson`.

1. Nodes a, b, and c enroll. With a valid `deny.json` on b, a and c can SSH to b and ping b.
2. The owner revokes a. a is refused. c is still accepted (traffic with a valid file does not change).
3. The coordinator stops, so b cannot get a new list. For each kind (corrupt, truncated, missing, unreadable), the proof takes `ORBLX_DENY_SAMPLES` (default 3) samples. Each sample is one SSH login and one ping from a to b. Each must be refused. The proof checks that the file is still damaged and that b still runs.
4. The coordinator starts again. b gets a valid list. c is accepted again and a is still refused.

Pass: `summary ... samples N accepted 0 unknown 0` with N >= 1, then `proof_ok`, and a `proof_contention` line with `unknown_samples 0`.

## Known limits

- The coordinator writes its own `deny.json` with temp file, `fsync`, and rename, but without a directory `fsync`. This item does not change it.
- A crash can leave `.deny.json.tmp.*` files. The reader ignores them.
- A stale set also stops open SSH sessions and datapath frames. The datapath does not close the open links when the set goes stale, but it refuses each frame.
- Enroll uses server-verified TLS with the trust bundle, not mutual TLS.
