# W25-37: signed deny list

Status: design. Crypto review 1 (on `5a08084`): CHANGES R1-R6, applied in this version. No code. Do not implement before the Crypto review accepts this file.
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

The signature stops:

- forgery: a deny list that did not come from the netmap signing key (for example a TLS front, proxy, or replica that has the coordinator TLS key but not the netmap key),
- cross-node use: the deny list of a different node (the lists are per node since W25-1, `main:crates/orblx-coord/src/admin.rs:52-72`) is refused (`node_uri`, R3),
- a change to `deny.json` by a party that cannot write the state directory.

The signature does NOT stop:

- a rollback by a party that can write the state directory. That party can put an older valid signed `deny.json` in place, or replace `netmap.pub` and `deny.json` together. The W25-34 start check on the state directory owner and mode (#131 "Hardening") limits who can write it.
- cold start: `orblx up` accepts an older valid signed `deny.json` from disk until the next fetch, as it does for `netmap.json`. The node has no last seq in memory at start (Q6: no `deny.seq` file). See "Cold start".
- a party that can block the coordinator fetches (a freeze). See "Freeze (Q4)".

## Signatures of the netmap key today

| Document | Signed bytes | Code |
|---|---|---|
| Netmap | canonical JSON of `Netmap` (starts with `{`), no prefix | `main:crates/orblx-coord/src/netmap.rs:94-103`, `:198-200` |
| Receiver grants | JSON of `ReceiverGrants` (starts with `{`), no prefix | `main:crates/orblx-coord/src/netmap.rs:110-122` |
| Endpoint | `orblx-endpoint-v1\n{name}\n{endpoint}\n` | `main:crates/orblx-edge/src/candidate.rs:73-82` |
| Agent grant | prefix `orblx-agent-grant-doc-v1\n` + document bytes | `main:crates/orblx-agent/src/grant.rs:22`, `:132-143` |
| Deny list (new) | `DENY_SIGN_PREFIX` = `orblx-deny-list-v1\n` + raw deny object bytes | this file (R1) |

## Signed payload format

Wire and file form (the node writes these exact bytes to `deny.json`):

```
{"deny":{...deny object...},"sig":"<base64 Ed25519 signature>","key_id":"<hex netmap public key>"}
```

Signed message (R1): one shared function in `orblx-identity`, used by the signer and by the verifier:

```rust
pub const DENY_SIGN_PREFIX: &[u8] = b"orblx-deny-list-v1\n";
/// DENY_SIGN_PREFIX || raw. The only way to make the deny sign message.
pub fn deny_sign_message(raw: &[u8]) -> Vec<u8>;
```

- `NetmapKey::sign_deny` and `verify_signed_deny` both call `deny_sign_message`. No other code builds the message.
- The verifier refuses a raw `deny` value whose first byte is not `{`.
- The prefix is 19 bytes and ends with `\n`. The netmap and grants messages start with `{`. The deny message starts with `o`. Thus no deny message is a netmap or grants message, and the reverse.
- The endpoint and agent-grant messages start with a different label. Thus no message of one type verifies as another type.
- The verifier adds the prefix itself. A sender cannot choose the prefix.
- S1 test: one const list of ALL netmap-key labels (`orblx-endpoint-v1\n`, `orblx-agent-grant-doc-v1\n`, `DENY_SIGN_PREFIX`). The test checks that they are pairwise distinct, that none is a prefix of another, and that none starts with `{`. A new netmap-key label must be added to that list.

Deny object (`deny_unknown_fields`, no map, no float, no `flatten`; the W25-34 guard test `signed_structs_keep_a_strict_form` also covers this struct):

| Field | Type | Meaning |
|---|---|---|
| `version` | u64 | The deny version (unchanged meaning, `main:crates/orblx-coord/src/admin.rs:25-29`). |
| `generated_at` | u64 | Unix seconds (unchanged). |
| `revoked_uris` | [string] | Unchanged. |
| `revoked_ticket_nonces` | [string] | Unchanged. |
| `node_uri` | string | NEW (R3). The SVID URI of the node that the list is for, for example `spiffe://orblx.local/node/a`. It contains the trust domain. |
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
- Seq: the W25-34 `SeqBook` (`#131:crates/orblx-coord/src/seq.rs:86`, `stamp` at `:174-225`). It gives `seq = max(last + 1, now_ms)` and syncs `netmap-seq` and the directory before the sign (kept). The deny list shares the book (Q3 accepted).
- Book key (R4): one function `deny_book_key(node: &str) -> Result<String, CoordError>` makes `deny\n<node>`. It refuses a node name that contains `\n`. Test: a name with `\n` is refused, and `deny_book_key("a")` never equals a netmap book key. No other code builds the key.
- No deny heartbeat (R4): new `SeqBook::stamp_once(key, content_sha256, now_ms)`. The memo stores the SHA-256 of the unsigned per-node deny content with the stamp (the `Stamp.content` field, `#131:seq.rs:78-82`). It gives the old stamp only when the digest matches. Any other content gets a new stamp. There is no `HEARTBEAT_MS` refresh (`#131:seq.rs:182`). Thus the same content gives the same signed bytes, and the node writes no file. A coordinator restart gives a new, higher seq for the same content. The node then writes the file one time.
- The ETag stays over the unsigned per-node list with `generated_at` 0 (`main:crates/orblx-coord/src/admin.rs:78-91`, `server.rs:212-218`). The seq and the signature are not in the ETag, so a new stamp does not wake the waiters.
- The CLOCK-FORWARD refusal of W25-34 (`#131:seq.rs:190-200`) also applies to `stamp_once` (kept): no signed deny list then. The node keeps its last good list.

## Coordinator: directory fsync (from W25-38)

- Today the two coordinator writers of `deny.json` use `write_text`: `revoke_undo` (`main:crates/orblx-coord/src/admin.rs:227`) and `push_deny` (`main:crates/orblx-coord/src/admin.rs:593`). `write_bytes` (`main:crates/orblx-coord/src/files.rs:16-37`) syncs the file and renames it, but does not sync the directory.
- Change: both writers use the W25-34 `write_synced` (`#131:crates/orblx-coord/src/seq.rs:281-305`: temp, sync, rename, sync directory). `write_synced` moves to `files.rs` as `pub(crate)`. Other coordinator files do not change in this item.
- Mode: `write_synced` creates the file with mode 0600. The coordinator `deny.json` stays 0644 (confirmed): `write_synced` gets a mode argument.

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

New function `orblx_identity::verify_signed_deny(bytes, public, node_uri) -> Result<VerifiedDeny, DenyFileError>` in a new file `crates/orblx-identity/src/signed_deny.rs`. `orblx-identity` already depends on `ed25519-dalek` 2.2 and `base64` (`main:crates/orblx-identity/Cargo.toml:10-11`). The steps:

1. Parse the envelope (`deny_unknown_fields`, `deny` as `RawValue`). The first byte of the raw `deny` value is `{` (R1).
2. The key (R2) comes ONLY from `netmap.pub` in the state directory (written before `deny.json`, `#136:crates/orblx-coord/src/state.rs:2318-2321`). The agent guard uses ONLY `GuardConfig.netmap_public` (`main:guard.rs:51`). `key_id` is a selector: it must equal the lowercase hex of that key exactly. The verifier never makes a key from `key_id`.
3. Ed25519 `verify_strict` (Q2, R2) over `deny_sign_message(raw)`.
4. Parse the deny object. `seq` and `issued_at_ms` are not 0.
5. `node_uri` (R3) equals the SVID URI of this node, byte for byte. The reader gets the URI from the node leaf `node.crt.pem` in the state directory with `extract_spiffe_id` (`main:crates/orblx-identity/src/cert.rs:42`), in `deny_file.rs`, so readers 1-4 need no change. The SSH server has it as `Shared.node_id` (`main:crates/orblx-ssh/src/server.rs:41`), the file receiver as `self_id` (`main:crates/orblx-cli/src/file.rs:237`), the agent guard as `GuardConfig.node` (`main:guard.rs:45`). Each reader can get the URI, so the `trust_domain` plus `node` fallback is not needed.
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
| valid | `seq` equal, same raw deny object bytes (R2: compare the raw `deny` bytes, not the envelope) | `DenyStore::Same`, no write |
| valid | `seq` equal, other raw deny object bytes | refuse, log `ALERT deny refuse seq-replay`, keep the file |
| valid | `seq` higher, `version` lower | refuse, log `ALERT deny refuse version-lower`, keep the file (the W25-38 "never move back" rule stays) |
| valid | `seq` higher, `version` same or higher | write (temp, fsync, rename, fsync directory: W25-38 writer) |

- Future check, only in the writer: `seq` or `issued_at_ms` more than 60 s after the node clock: refuse (`deny refuse seq-future`). This stops a far-future seq from locking the node out of later lists. The 60 s is the W25-34 limit (`NETMAP_MAX_SKEW_MS`).
- Coordinator clock back: `seq` more than 60 s above `issued_at_ms`: refuse with `ALERT deny refuse coord-clock-back` (the W25-34 node rule 3).
- No age refusal. `stamp_once` can keep an old `issued_at_ms` for content that does not change.
- The last accepted seq is the seq in the current `deny.json` (Q6: no `deny.seq` file). There is no second file, so there is no crash order between two files. A deleted `deny.json` after enroll is refuse-all (W25-38) until the next fetch over mutual TLS. That fetch gives the current list.
- A running reader keeps the last accepted seq in memory. `DenySet` keeps its version rule (`main:crates/orblx-identity/src/deny.rs:71-76`). `DenyCache` compares the seq of the new bytes with the in-memory seq of `last` (`#136:deny_file.rs:174`) with the same table. A lower seq in the file is `Invalid` (stale), not `IgnoredOlder`. Thus a running node refuses an older signed list that someone puts in place.

### Cold start (R6)

At start, a reader has no seq in memory. `orblx up` (and each other reader at its first read) accepts any valid signed `deny.json` for this node, also an older one, until the next fetch from the coordinator. This is the same as `netmap.json` at start. Only a party that can write the state directory can put an older file in place (see "Threat model"). This item does not close this gap. See "Later items".

### Freeze (Q4, R5)

Q4: the risk is accepted with these conditions.

- The node records the time of the last good deny fetch (a fetch that gave a valid signed list: `Written`, `Same`, or `KeptCurrent`). The value is in memory and in the state file `deny-fetch-ok` (Unix ms, atomic write, no secret).
- `orblx status` shows `deny_fetch_ok_ms <ms> age_s <s>` (JSON key `deny_fetch`).
- While the node is up, the node logs `ALERT deny-fetch-old age_s <s>` when the age is more than 5 min, then again each 5 min. This is a warning only. It never refuses a session or a frame. Readers never read a clock (the W25-38 rule stays).
- SSH revoke does not depend only on the deny list. Each new SSH certificate login uses the netmap path (W25-31 gate 2, #127): the revoked list (`ssh_revoked`) in the signed netmap, and the 60 s netmap freshness (`netmap_fresh`, #131). A frozen netmap stops new SSH certificate logins after 60 s.
- Residual risk: a party that can block the coordinator fetches keeps an old deny list in force for mesh traffic (QUIC sessions, frames, file receive, ping, agent guard), with no time limit. The ALERT shows it. The node does not refuse because of it.

## Migration and mixed versions

The W25-34 rule stays: mixed versions fail closed with a clear error. The coordinator still sends each revoke to an old node.

- `NODE_PROTO` goes from 1 to 2 (`#131:crates/orblx-coord/src/proto.rs:12`). A node with proto 2 gets signed lists. `version_gate` (`#131:proto.rs:41-45`) refuses proto 1 for all ops except `OLD_NODE_OPS` (`#131:proto.rs:21`).
- New coordinator, old node (proto 0 or 1): `deny` and `deny-wait` reply with the unsigned list as today. An old node keeps its revocations. `policy-wait` from proto 1 gets `version mismatch, upgrade: the node is older than the coordinator`.
- Old coordinator, new node: the reply has no signature. The writer refuses it with `version mismatch, upgrade: the coordinator is older than the node` and writes the W25-34 `coord-mismatch` state (`#131:crates/orblx-cli/src/up.rs:840-880`, `orblx status`). The node keeps its last valid file. A node with no valid file stays refuse-all.
- There is NO flag, option, or environment variable that makes a node accept an unsigned list. A node with `NODE_PROTO` 2 never accepts one. Old nodes get unsigned lists only through `OLD_NODE_OPS`.
- Upgrade of a node with an unsigned `deny.json` on disk: each reader refuses the old file (stale or refuse-all) until the first signed fetch. The [C] proof measures this window (gate S4).
- Release note (first release with W25-37, not rc.3): upgrade the coordinator and all nodes together.

## Tests and proof gates (after the Crypto review)

Unit tests (`cargo test`):

- S1 domain: the const label list test (R1). A netmap, grants, endpoint, or agent-grant signature with the same key does not verify as a deny list, and the reverse. A raw `deny` value that does not start with `{` is refused.
- S2 tamper: one changed byte in the object, the signature, or the `key_id` is refused by each of the 5 readers (refuse-all or stale, 0 accepted). An uppercase `key_id` is refused. A signature from another key with a matching `key_id` is refused. A non-canonical signature that `verify` accepts and `verify_strict` refuses is refused.
- S3 node binding (R3): the list of node `a` is refused on node `b`. A list for the same node name in a different trust domain (`spiffe://other.local/node/b`) is refused on `b`.
- S4 seq table: each row of the seq table, plus future and clock-back. `deny_book_key` refuses a name with `\n`. `stamp_once` gives the same stamp only for the same content digest.
- S7 freeze ALERT: no good fetch for more than 5 min gives `ALERT deny-fetch-old` and the `orblx status` age, and 0 refused sessions because of it.
- S5 crash: a crash before the rename keeps the old signed file; coordinator `deny.json` survives a crash after the rename (directory fsync).
- S6 mixed: new node + old coordinator, old node + new coordinator (as `scripts/proof/netmap-mixed.sh`).

[C] proof (release build, proof lock): revoke a peer, then on b:

- (a1) While b runs, replace `deny.json` with an older signed list for b. b refuses it (in-memory last seq, stale). 0 accepted sessions from the revoked peer.
- (a2) Cold start with an older signed list is documented (see "Cold start") and out of scope. The proof makes no 0-accepted claim for it.
- (b) Replace `deny.json` with the list of another node. 0 accepted.
- (c) Replace `deny.json` with an unsigned list. 0 accepted.

Each case: samples >= 1, unknown 0.

## Crypto review 1 answers (on `5a08084`)

- Q1: the prefix is enough. R1 adds the shared message function, the `{` check, and the label list test.
- Q2: `verify_strict` (R2).
- Q3: the shared `SeqBook` with key `deny\n<node>` is OK. R4 adds `deny_book_key` and the digest rule of `stamp_once`.
- Q4: the freeze risk is accepted with the R5 conditions (see "Freeze").
- Q5: bind to the node SVID URI (`node_uri`, R3).
- Q6: no `deny.seq` file. R6 states the cold start gap.
- Confirmed with no change: verify before parse; unknown fields refused; readers never read a clock; each failure is stale or refuse-all; the writer seq table; `NODE_PROTO` 2 never accepts an unsigned list; old nodes get unsigned lists only through `OLD_NODE_OPS`; the coordinator `deny.json` uses `write_synced` with mode 0644.

## Not in this item

- No new key, no key rotation, no change to the netmap, grants, endpoint, or agent-grant signatures.
- No change to the #136 or #131 branches. The code lands after both are on main.
- The coordinator does not sign its own `deny.json` on disk.

## Later items (not in scope)

- The signed netmap carries `deny_seq`: the lowest deny seq that the node must have. A node with a lower deny seq refuses until it fetches. This closes the cold start gap and limits the freeze to the netmap freshness.
