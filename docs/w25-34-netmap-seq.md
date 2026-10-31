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
- `Netmap` has a third new field, `grants_sha256`: the SHA-256 (hex) of the signed grants
  bytes that come with the netmap. It is inside the same netmap signature (Crypto grants
  binding, Fix 5). The node refuses a netmap when the field does not match its grants
  (`ALERT netmap refuse grants-mismatch`), so a fresh netmap cannot carry older grants.
  The node-local `netmap.json` copy has no value.
- CLOCK-FORWARD (Fix 4): the coordinator refuses to sign or write a `seq` more than 60 s
  ahead of its clock (`ALERT netmap seq refuse clock-forward`). The request fails. This
  occurs after the coordinator clock went forward and then back. To correct it, an owner runs
  `orblx admin netmap-seq-reset`. The command sets the stored `seq` to the coordinator clock
  time. It works only when the stored `seq` is ahead of the clock, and it never sets a value
  below the clock time. Only an owner SVID can run it (no API token). It writes one audit
  record with the action `netmap-seq-reset`, code 41 (codes 39 and 40 are reserved for other
  open items). The nodes never accepted the far `seq` (it was more than 60 s in the future for
  them), so they accept the next netmap with no step.
- At load, the coordinator refuses a stored `seq` above `u64::MAX / 2` (`SEQ_MAX`).
- One signing coordinator process holds the lock file `netmap-seq.lock` in the state
  directory. A second process that signs with the same directory gets an error.
- After the start, the coordinator logs the first `seq` one time:
  `netmap seq first after start: persisted none|P seq S issued_at_ms I`.

## Node intake

The node checks each signed netmap in this order. Each refusal writes one log line.

0. Before the intake: `grants_sha256` does not match the signed grants: refuse with an alert.
1. `seq` is 0 or `issued_at_ms` is 0: refuse (`netmap refuse no-stamp`).
2. `issued_at_ms` is more than 60 s before the node clock: refuse (`netmap refuse stale`).
   This check applies always, with or without a `netmap.seq` file (Fix 2).
   `seq` or `issued_at_ms` is more than 60 s after the node clock: refuse (`seq-future`).
3. `seq` is more than 60 s above `issued_at_ms` (the coordinator clock went back): refuse
   with an alert (`ALERT ... coord-clock-back`). The node accepts again when the coordinator
   clock passes the `seq`. There is no reset.
4. The node reads `netmap.seq`. A corrupt file (Fix 3) is an alert: the node moves it to
   `netmap.seq.corrupt-NOW_MS` and continues as with a missing file. Step 2 limits the
   rollback to 60 s. `orblx up` does not fail at the start for a missing or corrupt file.
   `seq` is lower than the last accepted `seq`: refuse (`seq-lower`).
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
  It also fails on a parse-changing serde attribute (`from`, `try_from`, `transparent`,
  `remote`, `deserialize_with`, `with`, `alias`, `other`, `bound`), on a field that is not
  `pub`, and on a new struct in the datapath netmap file or a new grant struct in the
  identity policy file that is not in the guard list.

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

## With the W25-16 view cache (#109)

Eng Lead rule, PO accepted (2026-10-31 KST):

- The W25-16 cache gives a cached signed view only while its stamp is younger than
  `HEARTBEAT_MS` (15 s). When the heartbeat is due, `netmap_cached` signs a new view with a
  new `seq` and `issued_at_ms`, also when no input changed (`heartbeat_due` in `state.rs`).
- `policy-wait` wakes at the heartbeat time. It then signs again and sends the full reply.
  It never sends the short `unchanged` reply for a heartbeat. The new stamp changes the view
  digest, so the ETag changes.
- The short reply of W25-16 does not change. It goes out only at the end of the hold when
  no heartbeat is due. Note: the hold is 20 s and the heartbeat is 15 s, so an idle hold
  ends at the heartbeat first. Thus in a steady idle state each idle hold ends with a full
  reply about each 15 s. The bytes of this are in the proof results.
- `orblx admin netmap-seq-reset` clears the cached views, because the book forgets all stamps.
- Tests: `an_idle_waiter_gets_a_fresh_signed_view_at_each_heartbeat` (3 idle heartbeats
  through `PolicyWaiter`: each reply has a new seq and a new signature, and the old stamp is
  at most 15 s plus one poll (100 ms) old when the reply comes), and
  `a_cached_view_is_due_at_the_heartbeat`.

## Upgrade and mixed versions

Mixed versions fail closed with a clear error.

- A new node sends `proto: 1` in each coordinator request. An old coordinator ignores the
  field. A new coordinator refuses a request with no `proto` (an old node) with the text
  `version mismatch, upgrade: the node is older than the coordinator ...` and logs
  `coord rejected: version mismatch, upgrade node NAME op OP protocol 0 (need 1)`.
  The coordinator still answers `deny` and `deny-wait` for an old node, so an old node
  continues to get revocations and sends no traffic to a revoked peer.
- A new node refuses a netmap with no stamp from an old coordinator with the text
  `version mismatch, upgrade: the coordinator is older than the node ...`. The node logs
  an ALERT at once and then each 300 s, and writes the state file `coord-mismatch`.
  `orblx status` then shows the line `coord version mismatch, upgrade ...` (JSON key
  `coord`). When the coordinator matches again, the node clears the file.
- A coordinator before W25-6 (for example the `v0.1.0-rc.2` tag, b9cae9c) does not know
  `policy-wait`. It replies `The request is not valid.`. A new node shows that reply as the
  same version mismatch.
- Limit: an old node does not log the mismatch. A d9704cfb node (with `policy-wait`) is
  silent and falls back to `deny-wait` each 30 s. A `v0.1.0-rc.2` tag node only fetches the
  deny list each 10 s, so the new coordinator refuses none of its calls and logs nothing for
  it. An old `orblx coord enroll` prints the coordinator text. The new coordinator log and
  the new node status show the mismatch.
- Proof: `scripts/proof/netmap-mixed.sh` (gates X1, U, X2) with `MIX_OLD_BIN` set to the
  old binary and `MIX_OLD_POLICY_WAIT=1` (d9704cfb) or `0` (the rc.2 tag).
- A new node on an rc.2 state directory (no `netmap.seq`) starts with no manual step.
  A new coordinator on an rc.2 state directory (no `netmap-seq`) gives the first
  `seq = max(persisted + 1, issued_at_ms)` and logs `persisted none`.

## Release notes

These notes go in the first release that contains W25-34 (not rc.3).

- Upgrade the coordinator and all nodes together. Mixed versions do not connect.
- Keep --state-dir private (0700).
- SSH certificate logins need a coordinator reachable within the last 60 s. Mesh traffic does not.
- After a coordinator clock that went forward and then back, run `orblx admin netmap-seq-reset`.
