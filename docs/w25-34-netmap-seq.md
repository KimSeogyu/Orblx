# W25-34: signed netmap seq and signed issue time

Status: code done. Do not merge until the PO accepts the gates.
Source of truth: the W25-34 PO rulings. A later ruling replaces an earlier one.

## What changed

- `Netmap` has two new fields: `seq` (u64) and `issued_at_ms` (u64, Unix ms).
  Both are inside the existing Ed25519 netmap signature. There is no new key, no new
  signature, and no new token format. The value 0 means "no stamp". The JSON omits a 0 value.
- The coordinator gives `seq = max(last seq + 1, issued_at_ms)`. It writes the new `seq` to
  `netmap-seq` in the coordinator state directory and syncs the file and the directory
  before it signs the netmap. A restart or a state reload never gives a lower `seq`.
- The coordinator signs a new stamp when the netmap, the grants, or the endpoints of a node
  change, and at least each 15 s (the signed heartbeat, `HEARTBEAT_MS`). `policy-wait`
  replies at the heartbeat time. The same content within 15 s gets the same signed bytes.
- The coordinator writes `ALERT netmap seq ...` when `seq` is more than 60 s ahead of its clock.

## Node intake

The node checks each signed netmap in this order. Each refusal writes one log line.

1. `seq` is 0 or `issued_at_ms` is 0: refuse (`netmap refuse no-stamp`).
2. `seq` or `issued_at_ms` is more than 60 s after the node clock: refuse (`seq-future`).
3. `seq` is more than 60 s above `issued_at_ms` (the coordinator clock went back): refuse
   with an alert (`ALERT ... coord-clock-back`). The node accepts again when the coordinator
   clock passes the `seq`. There is no reset.
4. `seq` is lower than the last accepted `seq`: refuse (`seq-lower`).
5. `seq` is equal and the signed bytes are the same: a no-op. The node changes no file.
   The freshness does not change.
6. `seq` is equal and the signed bytes are different: refuse with an alert (`seq-replay`).
7. Else the node syncs `netmap.seq` ("SEQ SHA256") first, then writes the netmap files.

- `netmap.json` has no stamp. A heartbeat changes only `netmap.signed.json`, so the datapath,
  the DNS responder, and the packet filter do not reload. A file with the same text is not
  written again.
- There is no command and no field that accepts a lower `seq`. The only reset is local:
  `orblx coord enroll`, `orblx login`, or a new state directory. After a state loss, the
  node accepts the first valid netmap. The 60 s issue-time limit bounds that rollback.

## Verify, then parse

- The wire types `SignedNetmapWire` and `SignedGrantsWire` keep the received bytes of the
  `netmap` and `grants` objects (serde_json `RawValue`). The node checks the signature over
  those exact bytes, then parses them with `deny_unknown_fields`.
- `SignedNetmap` and `SignedGrants` have no `Deserialize`. A reader gets them only from
  `verify_netmap_wire`, `verify_grants_wire`, `netmap_from_slice`, or `grants_from_slice`.
  All grant file readers (`file.rs`, `policy.rs`, `up.rs`) use that path.
- The CI guard test `signed_structs_keep_a_strict_form` fails when a signed netmap or grant
  struct loses `deny_unknown_fields`, or gets a map, a float, `untagged`, or `flatten`.

## SSH age check (Q13 = A)

- `orblx_datapath::netmap_fresh(issued_at_ms, now_ms)` is true only when
  `now - issued_at <= 60 s` and `issued_at <= now + 60 s`. No other grace.
- `orblx_coord::read_verified_netmap(state_dir)` reads and checks `netmap.signed.json`.
- All SSH certificate logins use these two (W25-31, #127). A stale netmap stops new SSH
  certificate logins only. Mesh traffic continues.

## Hardening

- The node lock drop path writes `netmap.json` with the atomic writer (temp file, sync,
  rename). Before, it used `fs::write`.
- `NetmapView::write_state` sets the state directory mode to 0700 again.
- `orblx up` refuses to start when the state directory, the netmap file, or the netmap
  directory (no sticky bit) is group-writable or world-writable, or has another owner.

## Upgrade

Mixed versions fail closed. An old node refuses the new fields (`deny_unknown_fields`).
A new node refuses a netmap with no stamp. Upgrade the coordinator and the nodes together.

## Release notes

- Keep --state-dir private (0700).
- SSH certificate logins need a coordinator reachable within the last 60 s. Mesh traffic does not.
