# W25-38 deny.json fails closed

Before this change, the node used an empty deny list when `deny.json` was not valid, could not be read, or was missing.
An empty deny list lets each revoked SVID and each revoked ticket nonce in again.
After this change, the node refuses SSH, file receive, and new sessions until it has a valid deny list.
The change adds no new key and no new crypto. Signing the deny list is W25-37.

Marks: **[C]** = shown in the container proof. **REAL** = shown on real hosts.
This change has no [C] result and no REAL result. The results come from `cargo test` only.

## Rules on the node

| State of `deny.json` | Node enrolled (`node-name` exists) | Node never enrolled |
|---|---|---|
| Valid | Use the list. | Use the list. |
| Not valid (corrupt or truncated) | Refuse. | Refuse. |
| Cannot read (not `NotFound`) | Refuse. | Refuse. |
| Missing | Refuse. | Empty list, as before. |

"Refuse" means:

1. The SSH server refuses each login. The deny watch and the recheck close open SSH sessions.
2. The file receiver refuses each transfer.
3. The datapath refuses each new session and each frame. The datapath does not keep the last good list when the file becomes bad.
4. `orblx up` starts with a refuse-all list and prints the error.
5. `orblx ping` without a coordinator returns the error.

The error text names the file and ends with:
`The node refuses SSH, file receive, and new sessions until it has a valid deny list.`

The marker of enroll is the `node-name` file. Only `EnrollResult::write_state` writes it.
Lab nodes from `orblx issue` have no `node-name`, so they keep the old behavior for a missing file.
A `node-name` that the node cannot stat counts as enrolled.

## Write

`orblx_identity::store_deny_file` is the only node writer.

1. It parses the text. It refuses text that is not a valid deny document and keeps the old file.
2. It does not write when the text is the same as the file.
3. It writes a temp file `.deny.json.tmp.<pid>.<n>` in the same directory with `create_new`, then calls `fsync`.
4. It renames the temp file to `deny.json`, then calls `fsync` on the directory.
5. On an error, it removes the temp file.

A crash before the rename leaves the temp file and the old `deny.json`. The reader uses the old file.
A crash before the first rename after enroll leaves no `deny.json`. The reader refuses.

Enroll now writes `deny.json`. The coordinator puts the deny list of the node in the `detail` field of the enroll reply.
The client keeps the list only when it is a valid deny document. `write_state` writes it with `store_deny_file`.
Without this step, a new node refuses all sessions until the first netmap pull.

## Gate tests

| Gate | Test | Result |
|---|---|---|
| Corrupt file | `deny_file::tests::w25_38_corrupt_deny_file_refuses` | pass |
| Corrupt file, never enrolled | `deny_file::tests::w25_38_corrupt_deny_file_refuses_when_never_enrolled` | pass |
| Truncated file | `deny_file::tests::w25_38_truncated_deny_file_refuses` | pass |
| Missing after enroll | `deny_file::tests::w25_38_missing_deny_file_after_enroll_refuses` | pass |
| Missing, never enrolled | `deny_file::tests::w25_38_missing_deny_file_never_enrolled_keeps_empty` | pass |
| Cannot read | `deny_file::tests::w25_38_unreadable_deny_file_refuses` | pass |
| Crash during write | `deny_file::tests::w25_38_crash_during_write_keeps_old_file` | pass |
| Crash during first write | `deny_file::tests::w25_38_crash_during_first_write_after_enroll_refuses` | pass |
| SSH | `server::tests::w25_38_ssh_refuses_when_the_deny_file_is_corrupt_truncated_or_missing` | pass |
| File receive | `file::tests::w25_38_file_receive_refuses_when_the_deny_file_is_corrupt_truncated_or_missing` | pass |
| New sessions | `up::tests::w25_38_new_sessions_refuse_when_the_deny_file_is_corrupt_truncated_or_missing` | pass |
| Enroll writes `deny.json` | `tests::two_nodes_keep_ips_after_restart` (orblx-coord) | pass |

## Known limits

- The coordinator writes its own `deny.json` with temp file, `fsync`, and rename, but without a directory `fsync`. This item does not change it.
- A crash can leave `.deny.json.tmp.*` files. The reader ignores them.
- A bad file stops open SSH sessions and datapath frames too. This is stricter than "new sessions only".
