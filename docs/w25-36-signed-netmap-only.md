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

## Running readers and fail closed (W25-36 b, c)

- REAL: `orblx-datapath` has `read_running_netmap` (`netmap_source.rs`). The netmap watcher,
  `fresh_netmap`, the DNS watcher, `orblx status`, and the serve check use it.
- REAL: coordinator state is one of `node.crt.pem`, `netmap.signed.json`, `coord-addr`,
  `node-name`. `netmap.pub` alone is not coordinator state, because a static
  `orblx issue --policy` node has it too.
- REAL: with coordinator state, the readers watch `netmap.signed.json` and parse the netmap only
  through the signature check from `orblx-coord` (`install_netmap_check`). They never read
  `netmap.json`. `orblx up` uses the signed netmap also with a `--netmap` option.
- REAL: coordinator state without `netmap.pub` or without `netmap.signed.json` fails closed with
  a clear error. A process without the installed check also fails closed.
- REAL tests: `tampers_while_the_node_reads_are_never_accepted` (9 files, 0 accepted),
  `an_enrolled_node_without_netmap_pub_fails_closed` (4 markers, 0 accepted),
  `a_static_node_with_netmap_pub_reads_netmap_json`, `an_enrolled_node_does_not_admit_from_netmap_json`,
  and the `netmap_source` tests.
- [C] The running test drives the same read function as the node tasks. A full `run_node` needs
  a TUN device (root), so CI does not run it.
- [C] A local user who can delete all coordinator files can also change every other state file.
  This change does not defend against that user.

## Release notes

- A local user who deletes all 4 enrollment markers (`node.crt.pem`, `netmap.signed.json`,
  `coord-addr`, `node-name`) can make the node read `netmap.json`. This is outside the threat model.

## Open gate

- OPEN: a REAL run with a full TUN node (root) that tampers with both netmap files while the node
  runs, with 0 accepted. W25-36 does not close before this run passes.
