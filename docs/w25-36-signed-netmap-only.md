# W25-36: the node parses only the signed netmap

Marks: REAL means a result from a run on this host. [C] means a result from code or a unit test, not from a live node.

## Change

- An enrolled node has `netmap.pub`. Such a node now parses the netmap only from `netmap.signed.json`, after the signature check with the pinned key in `netmap.pub` (`orblx_coord::read_verified_netmap`). The check is the existing `verify_signed_netmap`. There is no new key.
- `orblx up` uses this path when the netmap comes from the coordinator, or when the netmap path is the state `netmap.json`. Then the node applies node lock to the verified netmap. [C]
- `orblx file send` and `orblx file receive` use `orblx_coord::read_node_netmap`. An enrolled node uses the verified path. A node without `netmap.pub` (no coordinator) reads `netmap.json`, as before. [C]
- A node that runs with its own `--netmap` file and no coordinator fetch keeps that file. [C]
- The `locked_netmap` function is not changed (W25-34 owns it).

## Tamper tests

The tests write valid files, then change the bytes on disk. [C]

| Test | Files changed | Accepted |
|---|---|---|
| `tampered_netmap_json_is_never_parsed` | 6 | 0 |
| `tampered_signed_netmap_is_rejected` | 7 | 0 |
| `untampered_files_give_the_same_netmap_as_before` | 0 | same netmap as before |
| `a_node_without_a_coordinator_reads_netmap_json` | 0 | same netmap as before |
| `an_enrolled_node_without_the_signed_file_fails` | 1 removed | 0 |

## Limits

- `deny.json` is not in this change. The coordinator does not sign the deny list. See the PR text.
- The runtime readers of `netmap.json` (datapath netmap watch, DNS, serve) still read the file. They are not in this change.
- A node with `netmap.pub` removed is a node without a coordinator. It reads `netmap.json`.
- No live node run (REAL) is in this change.
