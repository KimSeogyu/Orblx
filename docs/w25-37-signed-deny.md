# W25-37: signed deny list

Status: design for the Crypto review. No code. Do not implement before the Crypto review accepts this file.
Base: main `995ea4d`. Depends on W25-38 (#136, head `3570668`) and W25-34 (#131, head `7dab6a9`). Both are open. This item does not change their branches.
Line references: `main:` is `995ea4d`, `#136:` is `3570668`, `#131:` is `7dab6a9`.

## Goal

The coordinator signs each deny list that it sends to a node. Each node reader accepts a deny list only after it verifies the signature, the node name, and the seq. A deny list that fails a check is not valid. The reader then uses the W25-38 fail-closed behavior (last good set, marked stale; or refuse-all).

Rules from the PO:

- Use the EXISTING netmap Ed25519 key (`NetmapKey`, `main:crates/orblx-coord/src/netmap.rs:48`). No new key. No new crypto primitive. No new key file.
- Use a domain-separation prefix that is different from each other signature of the netmap key.
- Use the W25-34 seq for replay protection. The seq never moves back.
- Cover all 5 deny readers.
- The coordinator writes its `deny.json` with a directory `fsync` (moved here from W25-38, see `#136:docs/w25-38-deny-fail-closed.md:151`).

## Threat model

The signature protects against:

- a deny list that did not come from the coordinator signing key (for example a TLS front, proxy, or replica that has the coordinator TLS key but not the netmap key),
- a change to `deny.json` on the node by a party that cannot also change `netmap.pub`,
- the deny list of a different node (the lists are per node since W25-1, `main:crates/orblx-coord/src/admin.rs:52-72`),
- a replay of an older signed list (seq rule).

The signature does not protect against:

- local root on the node. Root can replace `netmap.pub` and `deny.json` together. The W25-34 start check on the state directory owner and mode (#131 "Hardening") limits the other local users.
- a party that holds back new lists (a freeze). W25-38 says that a valid list never becomes stale because of its age (`#136:crates/orblx-identity/src/deny_file.rs:243`). This item keeps that rule. See question Q4.

## Signatures of the netmap key today

| Document | Signed bytes | Code |
|---|---|---|
| Netmap | canonical JSON of `Netmap` (starts with `{`), no prefix | `main:crates/orblx-coord/src/netmap.rs:94-103`, `:198-200` |
| Receiver grants | JSON of `ReceiverGrants` (starts with `{`), no prefix | `main:crates/orblx-coord/src/netmap.rs:110-122` |
| Endpoint | `orblx-endpoint-v1\n{name}\n{endpoint}\n` | `main:crates/orblx-edge/src/candidate.rs:73-82` |
| Agent grant | prefix `orblx-agent-grant-doc-v1\n` + document bytes | `main:crates/orblx-agent/src/grant.rs:22`, `:132-143` |
| Deny list (new) | prefix `orblx-deny-list-v1\n` + deny object bytes | this file |

## Signed payload format

Wire and file form (the node writes these exact bytes to `deny.json`):

```
{"deny":{...deny object...},"sig":"<base64 Ed25519 signature>","key_id":"<hex netmap public key>"}
```

Signed message:

```
b"orblx-deny-list-v1\n" || <exact bytes of the "deny" object as received>
```

- The prefix is 19 bytes and ends with `\n`. It is not a prefix of another label in the table, and no other label is a prefix of it.
- The netmap and grants messages start with `{`. The deny message starts with `o`. Thus no deny message is a netmap or grants message, and the reverse.
- The endpoint and agent-grant messages start with a different label. Thus no message of one type verifies as another type.
- The verifier adds the prefix itself. A sender cannot choose the prefix.

Deny object (`deny_unknown_fields`, no map, no float, no `flatten`; the W25-34 guard test `signed_structs_keep_a_strict_form` also covers this struct):

| Field | Type | Meaning |
|---|---|---|
| `version` | u64 | The deny version (unchanged meaning, `main:crates/orblx-coord/src/admin.rs:25-29`). |
| `generated_at` | u64 | Unix seconds (unchanged). |
| `revoked_uris` | [string] | Unchanged. |
| `revoked_ticket_nonces` | [string] | Unchanged. |
| `node` | string | NEW. The node name that the list is for. |
| `seq` | u64 | NEW. From the W25-34 seq book. Not 0. |
| `issued_at_ms` | u64 | NEW. Coordinator clock at the stamp. Not 0. |

Verify, then parse (the W25-34 rule): the reader keeps the raw bytes of `deny` (serde_json `RawValue`, as `SignedNetmapWire`, `#131:crates/orblx-coord/src/netmap.rs:71`), checks the signature over the prefix plus those bytes, and only then parses the object.

## Coordinator: sign and seq

- New `NetmapKey::sign_deny(&self, deny_object_bytes) -> SignedDeny`, next to `sign_endpoint` (`main:crates/orblx-coord/src/netmap.rs:142-151`). It uses `sign_checked` (`:125-132`).
- The coordinator signs at reply time. Its own `deny.json` stays unsigned (it is the input, `main:crates/orblx-coord/src/admin.rs:567-595`).
- Sign points (each reply that carries a deny list to a node):
  - `deny` op: `main:crates/orblx-coord/src/server.rs:467-478`.
  - `deny-wait` op: `main:crates/orblx-coord/src/server.rs:479-485`, which calls `deny_wait` (`:125-145`).
  - `policy-wait` reply, field `deny`: `main:crates/orblx-coord/src/server.rs:150-170` (`PolicySync.deny`, `main:crates/orblx-coord/src/client.rs:543-547`).
  - The first deny fetch after enroll uses the `deny` op (`#136:crates/orblx-coord/src/client.rs:50`, `:549-556`). No extra sign point.
- Seq: the W25-34 `SeqBook` (`#131:crates/orblx-coord/src/seq.rs:86`, `stamp` at `:174-225`). It gives `seq = max(last + 1, now_ms)` and syncs `netmap-seq` and the directory before the sign. The deny list uses the book key `deny\n<node>`. A node name has no `\n`, so the key never matches a netmap key.
- No deny heartbeat: the same deny content keeps the same stamp (new `SeqBook::stamp_once`, the same as `stamp` without the `HEARTBEAT_MS` refresh at `#131:seq.rs:182`). Thus the same content gives the same signed bytes, and the node writes no file. A coordinator restart gives a new, higher seq for the same content. The node then writes the file one time.
- The ETag stays over the unsigned per-node list with `generated_at` 0 (`main:crates/orblx-coord/src/admin.rs:78-91`, `server.rs:212-218`). The seq and the signature are not in the ETag, so a new stamp does not wake the waiters.
- The CLOCK-FORWARD refusal of W25-34 (`#131:seq.rs:190-200`) also applies: no signed deny list then. The node keeps its last good list.

## Coordinator: directory fsync (from W25-38)

- Today the two coordinator writers of `deny.json` use `write_text`: `revoke_undo` (`main:crates/orblx-coord/src/admin.rs:227`) and `push_deny` (`main:crates/orblx-coord/src/admin.rs:593`). `write_bytes` (`main:crates/orblx-coord/src/files.rs:16-37`) syncs the file and renames it, but does not sync the directory.
- Change: both writers use the W25-34 `write_synced` (`#131:crates/orblx-coord/src/seq.rs:281-305`: temp, sync, rename, sync directory). `write_synced` moves to `files.rs` as `pub(crate)`. Other coordinator files do not change in this item.
- Mode: `write_synced` creates the file with mode 0600. The coordinator `deny.json` is 0644 today. The implementation keeps 0644 (one mode argument).

## Node: the 5 readers and the writers

All node readers go through the W25-38 functions in `#136:crates/orblx-identity/src/deny_file.rs`. The verify step goes in those functions, so each reader gets it with no reader change.

| # | Reader | Code (#136) | Path to the check |
|---|---|---|---|
| 1 | SSH server: login and open-session recheck | `crates/orblx-ssh/src/server.rs:338-343` (`reload_deny`), `:758-794` (`DenyWatch`), cache `:47`, `:1040` | `DenyCache::reload` |
| 2 | File receiver | `crates/orblx-cli/src/file.rs:227-247` (`load_gate`), `:283` | `DenyCache::reload` |
| 3 | Datapath (new QUIC sessions, frames) | `crates/orblx-datapath/src/node.rs:811-849`; `orblx up` start `crates/orblx-cli/src/up.rs:1273-1288` | `DenyCache::apply_read`, `load_deny_file` |
| 4 | `orblx ping` | `crates/orblx-cli/src/ping.rs:150-173` | `store_deny_file`, `load_deny_file` |
| 5 | Agent guard | `main:crates/orblx-agent/src/guard.rs:183-200` (`apply_deny`), `:645-660` (`spawn_poll`); fetch `crates/orblx-cli/src/agent.rs:554-579` (coordinator or `deny.json`) | `GuardCore::apply_deny` (new verify call, key from `GuardConfig.netmap_public`, `main:guard.rs:51`) |

Writers on the node (all call `store_deny_file`, `#136:deny_file.rs:121`): `orblx up` (`#136:crates/orblx-cli/src/up.rs:766`, `:776`, `:790`, `:822-827`), `orblx ping --coord` (`#136:ping.rs:160`), enroll and login `write_state` (`#136:crates/orblx-coord/src/state.rs:2335`), and `fetch_first_deny_blocking` (`#136:client.rs:549-556`).

### Verify (each reader)

New function `orblx_identity::verify_signed_deny(bytes, public, node) -> Result<VerifiedDeny, DenyFileError>` in a new file `crates/orblx-identity/src/signed_deny.rs`. `orblx-identity` already depends on `ed25519-dalek` 2.2 and `base64` (`main:crates/orblx-identity/Cargo.toml:10-11`). The steps:

1. Parse the envelope (`deny_unknown_fields`, `deny` as `RawValue`).
2. `key_id` equals the hex of `netmap.pub` in the state directory (written before `deny.json`, `#136:crates/orblx-coord/src/state.rs:2318-2321`). The agent guard uses `GuardConfig.netmap_public`.
3. Ed25519 `verify_strict` over `prefix || raw deny bytes`. (Q2: `verify` or `verify_strict`.)
4. Parse the deny object. `seq` and `issued_at_ms` are not 0.
5. `node` equals the node name in `node-name` (`#136:deny_file.rs:24`). The agent guard uses its node name.
6. Give the object to `DenySet::apply_json` (`main:crates/orblx-identity/src/deny.rs:58`) as before.

The readers do not read a clock (the W25-38 rule stays). A failure in any step is `DenyFileError::Invalid`. Thus:

- `DenyCache::apply_read` marks the last good set stale (`#136:deny_file.rs:239` to `stale` at `:243`; `DenySet::mark_stale`, `#136:crates/orblx-identity/src/deny.rs:72`). A stale set refuses each identifier and nonce.
- `load_deny_file` returns the error (`#136:deny_file.rs:90-97`). `orblx up` uses refuse-all (`#136:up.rs:1288`). `orblx ping` stops.
- The agent guard keeps its last set and its `deny_ok_at` does not move. The guard already fails closed on an old set (`main:crates/orblx-agent/tests/guard.rs:323`).
- A node that was never enrolled with no `deny.json` keeps the empty set (W25-38 lab rule, `#136:deny_file.rs:70-87`). A never-enrolled node has no `netmap.pub`, so it cannot verify. A `deny.json` on such a node is a refusal.

### Seq rule (writer)

`store_deny_file` (`#136:deny_file.rs:121`) verifies the offered bytes (steps 1-5). Then it compares with the current file:

| Current file | Offered | Result |
|---|---|---|
| missing, not valid, or a different `key_id` | valid | write (W25-38 rule 4: a file that is not valid does not block a valid list). This covers a re-enroll with a new coordinator. |
| valid | `seq` lower | refuse, log `deny refuse seq-lower`, keep the file (`DenyStore::KeptCurrent`) |
| valid | `seq` equal, same bytes | `DenyStore::Same`, no write |
| valid | `seq` equal, other bytes | refuse, log `ALERT deny refuse seq-replay`, keep the file |
| valid | `seq` higher, `version` lower | refuse, log `ALERT deny refuse version-lower`, keep the file (the W25-38 "never move back" rule stays) |
| valid | `seq` higher, `version` same or higher | write (temp, fsync, rename, fsync directory: W25-38 writer) |

- Future check, only in the writer: `seq` or `issued_at_ms` more than 60 s after the node clock: refuse (`deny refuse seq-future`). This stops a far-future seq from locking the node out of later lists. The 60 s is the W25-34 limit (`NETMAP_MAX_SKEW_MS`).
- Coordinator clock back: `seq` more than 60 s above `issued_at_ms`: refuse with `ALERT deny refuse coord-clock-back` (the W25-34 node rule 3).
- No age refusal. `stamp_once` can keep an old `issued_at_ms` for content that does not change.
- The last accepted seq is the seq in the current `deny.json`. There is no second file, so there is no crash order between two files. A deleted `deny.json` after enroll is refuse-all (W25-38) until the next fetch over mutual TLS. That fetch gives the current list.
- `DenySet` keeps its version rule (`main:crates/orblx-identity/src/deny.rs:71-76`). `DenyCache` compares the seq of the new bytes with the seq of `last` (`#136:deny_file.rs:174`) with the same table. A lower seq in the file is `Invalid` (stale), not `IgnoredOlder`.

## Migration and mixed versions

The W25-34 rule stays: mixed versions fail closed with a clear error. The coordinator still sends each revoke to an old node.

- `NODE_PROTO` goes from 1 to 2 (`#131:crates/orblx-coord/src/proto.rs:12`). A node with proto 2 gets signed lists. `version_gate` (`#131:proto.rs:41-45`) refuses proto 1 for all ops except `OLD_NODE_OPS` (`#131:proto.rs:21`).
- New coordinator, old node (proto 0 or 1): `deny` and `deny-wait` reply with the unsigned list as today. An old node keeps its revocations. `policy-wait` from proto 1 gets `version mismatch, upgrade: the node is older than the coordinator`.
- Old coordinator, new node: the reply has no signature. The writer refuses it with `version mismatch, upgrade: the coordinator is older than the node` and writes the W25-34 `coord-mismatch` state (`#131:crates/orblx-cli/src/up.rs:840-880`, `orblx status`). The node keeps its last valid file. A node with no valid file stays refuse-all.
- Upgrade of a node with an unsigned `deny.json` on disk: each reader refuses the old file (stale or refuse-all) until the first signed fetch. The [C] proof measures this window (gate S4).
- Release note (first release with W25-37, not rc.3): upgrade the coordinator and all nodes together.

## Tests and proof gates (after the Crypto review)

Unit tests (`cargo test`):

- S1 domain: a netmap, grants, endpoint, or agent-grant signature with the same key does not verify as a deny list, and the reverse. A deny envelope with the deny bytes moved into a netmap field does not verify.
- S2 tamper: one changed byte in the object, the signature, or the `key_id` is refused by each of the 5 readers (refuse-all or stale, 0 accepted).
- S3 node binding: the list of node `a` is refused on node `b`.
- S4 seq table: each row of the seq table, plus future and clock-back.
- S5 crash: a crash before the rename keeps the old signed file; coordinator `deny.json` survives a crash after the rename (directory fsync).
- S6 mixed: new node + old coordinator, old node + new coordinator (as `scripts/proof/netmap-mixed.sh`).

[C] proof (release build, proof lock): revoke a peer, then (a) replace `deny.json` on b with an older signed list, (b) with the list of another node, (c) with an unsigned list. Each case: 0 accepted sessions from the revoked peer, samples >= 1, unknown 0.

## Questions for the Crypto review

- Q1 Domain separation: is the prefix `orblx-deny-list-v1\n` enough, given that the netmap and grants signatures have no prefix (they start with `{`)?
- Q2 Use `verify_strict` for the new deny verify (the other netmap-key verifies use `verify`, `main:netmap.rs:188-196`)?
- Q3 Is one global seq counter (shared with the netmap, book key `deny\n<node>`) correct, or must the deny list have its own counter file?
- Q4 Freeze: the design has no age limit (W25-38 rule: a valid list is never stale by age). Is the holdback risk accepted for rc.3+1, with mutual TLS on each fetch?
- Q5 Is `node` in the signed object enough as the audience binding, or must the trust domain or the coordinator name also be in it?
- Q6 Is the last accepted seq in `deny.json` itself enough, or must the node keep a separate `deny.seq` (like `netmap.seq`) so that a deleted `deny.json` cannot reset the seq?

## Not in this item

- No new key, no key rotation, no change to the netmap, grants, endpoint, or agent-grant signatures.
- No change to the #136 or #131 branches. The code lands after both are on main.
- The coordinator does not sign its own `deny.json` on disk.
