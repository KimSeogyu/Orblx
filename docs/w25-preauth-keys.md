# W25 Pre-auth keys

An owner can make a pre-auth key for an agent node.
The key is one use by default. It can be reusable, short lived, ephemeral, and tagged.
It can set one grant ceiling. The enrolled node cannot get more than that ceiling.
The node enrolls on the existing agent SVID path. This change does not change SVID, ticket, or crypto code.

## Gap matrix row

The gap matrix is not in this repo.
`docs/rc3-release-sweep.md` names the private page "Orblx vs Tailscale 기능 격차 매트릭스 + Wave 계획".
Row 33 is shipped. It is the one-use enroll token (`docs/w18-coord-enroll.md`).
Row 35 is shipped. It is the scoped API token (`docs/w25-api-tokens.md`).
This change is row 34. Eng Lead confirmed that number.

## Marks

- **REAL**: `cargo test` on the Linux host. The tests are in the table below.
- **[C]**: `scripts/proof/preauth-keys.sh`. It needs Linux, Docker, and the test OIDC issuer.
  The proof was not run for this change. A missing `proof_ok` line is not a pass.

## What the key is

- Text: `orblx-pak1.` and the base64url text of 32 random bytes from `OsRng`.
- ID: the first 16 hex characters of the SHA-256 digest.
- The store is `preauth-keys.json` in the coordinator state directory. The mode is 0600.
  The file holds the digest only. It refuses text that contains `orblx-pak1.` or `PRIVATE KEY`.
- The compare is the same constant-time compare as the enroll token store.
- Life: 1 second to 1 hour. A value outside that range is refused.
- Uses: 1 to 16. The default is 1.
- The coordinator keeps at most 128 keys.
- `orblx admin preauth-create --out FILE` writes the key once. The mode is 0600.
  The command does not print the key.
- `orblx admin preauth-list` prints the id, the state, the use count, the tags, and the expiry.
  It does not print the key.
- `orblx admin preauth-revoke ID` refuses a later enroll.
- Log lines and audit records show the id only.
  Error text that contains the prefix is not sent.

## Who can make a key

The caller is an owner SVID, or a scoped API token.

| Call | Scope |
| --- | --- |
| `preauth-list` | `nodes:read` |
| `preauth-create` | `nodes:write` |
| `preauth-revoke` | `nodes:write` |

A grant ceiling also needs `grants:write` on a token. An owner SVID does not need that scope.
A token cannot set a tag. A tag is allowed only when the caller SVID owns that tag in `tagOwners`.
The tag must exist in the policy. The key can hold at most 8 tags.
The target node of a grant ceiling must be enrolled, approved, and not removed.
The grant life in the ceiling is 1 to 300 seconds.

These checks follow the token-no-escalation rule. A key cannot grant more than the caller can grant.

## Enroll

`orblx coord enroll --token-file FILE` sends `preauth-enroll` when the file text starts with `orblx-pak1.`.
An OIDC ID token uses `--id-token-file`. A one-use enroll token (`ge1.`) still uses `--token-file` and `enroll`.
The node is approved even when `nodeApproval` is on.
The coordinator writes the use count and the `preauth-use` record before it enrolls the node.
If either write fails, the enroll does not run. A one-use key cannot enroll a second node.
The use lock is inside one coordinator process. One-use is atomic for one coordinator on one state directory.
Two coordinator processes on the same state directory are outside this rule.
The node SVID is the existing enroll SVID. The agent SVID is issued later by the existing grant fetch.
The agent name on that grant must be the node name.

An empty grant ceiling means the node can receive no agent grant.
A grant inside the ceiling is approved at the request. The approver is the key creator.
A wider grant is refused. No grant is stored.

## Ephemeral nodes

`--ephemeral` marks the node. A node without the flag stays until an owner revokes it.
The coordinator removes an ephemeral node when either time is reached:

- The key expiry time.
- 15 seconds after the last time the node was seen.

A seen time is written at enroll and on a later peer call (netmap, renew, policy wait).
The seen time is in memory and in `presence.json` (mode 0600). It is not in `nodes.json`.
A restart drops the memory map. The grace timer then uses the last `presence.json` write.
It does not start again at zero. A node that was already offline is removed on the original 15 second mark.
If `presence.json` is missing, the seen time is the enroll time.
A node without `--ephemeral` stays after key expiry. That matches the Tailscale rule for a non-ephemeral node.
Revoke that node with the existing admin path.

Removal uses the existing revoke path (`revoke_principal`).
That path writes the node SVID and each issued agent SVID into the deny file, so open sessions close.
The node stays in the store as removed. It leaves the netmap.
One `node-remove` record is written. The revoke path itself writes no audit record.
If both times are reached, the record says `expiry`.

## Tags and ACL

A pre-auth node keeps the tags from its key.
An ACL rule that names `tag:NAME` matches a node that carries that tag.
The match is for the packet filter only.
Tag route `autoApprovers` and exit nodes are follow-up issue https://github.com/KimSeogyu/Orblx/issues/159.

## Audit

| Event | Action | Code |
| --- | --- | --- |
| Create | `preauth-create` | 39 |
| Use (enroll) | `preauth-use` | 40 |
| Deny | `preauth-deny` | 41 |
| Revoke | `preauth-revoke` | 42 |
| Ephemeral removal | `node-remove` | 37 |

A create also writes the existing `enroll` record when the node enrolls.
A pre-approved grant also writes `agent-grant` and `agent-approve`.
A token scope miss stays `token-deny`. A tag, grant, or life miss is `preauth-deny` only.
Deny reasons: `life`, `tag`, `grant`, `used`, `expired`, `revoked`, `unknown`.
`create` writes one `preauth-deny` for an owner and for a token caller.
Unknown keys share one `preauth-deny` record per second per state directory. Each call is still refused.
An ephemeral removal retry does not add the SVID to the deny file a second time.
A second pass writes no second `node-remove` record.

## Tests (REAL)

| Test | What it shows |
| --- | --- |
| `preauth::tests::one_use_reusable_expiry_revoke_and_unknown_are_refused` | One use, max uses, expiry, revoke, unknown key, hashed store, mode 0600, one audit record per event, no key text in the audit |
| `preauth::tests::a_tag_or_grant_outside_the_caller_is_refused` | Tag owner check, token cannot set a tag, grant needs `grants:write`, life bound |
| `preauth::tests::an_ephemeral_node_is_removed_on_grace_and_on_expiry` | Grace 15 seconds, expiry, deny list contains the SVID, one `node-remove` each |
| `preauth::tests::a_restart_resumes_grace_from_presence_json` | REAL. After a restart, grace resumes from the last `presence.json` write. It does not start again at zero |
| `preauth::tests::one_use_key_enrolls_exactly_one_node_under_parallel_calls` | REAL. Eight parallel enrolls of one one-use key. Exactly one succeeds |
| `preauth::tests::a_token_refusal_in_create_writes_one_deny` | REAL. A token caller refusal in `create` writes one `preauth-deny` |
| `preauth::tests::unknown_key_denies_share_one_record_per_second` | REAL. Six unknown keys in one second write one `preauth-deny`. The next second writes one more |
| `preauth::tests::an_ephemeral_removal_retry_does_not_duplicate_the_deny_entry` | REAL. A removal retry keeps one deny entry and one `node-remove` record |
| `preauth::tests::a_grant_inside_the_ceiling_is_preapproved_and_a_wider_grant_is_refused` | Ceiling auto-approve, wider grant refused, fetch issues the existing agent SVID |
| `policy::tests::a_preauth_tag_matches_the_tag_rule` | A node tag matches an ACL tag rule |
| `admin::tests::preauth_create_writes_the_ask_and_keeps_the_key_out_of_the_command` | CLI ask JSON, life bound, list, revoke |

## Proof ([C], not run)

`scripts/proof/preauth-keys.sh` runs under `scripts/proof/proof-lock.sh`.
It builds a release binary because the gates have a time limit.
It starts `orblx-test-idp`. The owner enrolls with an ID token.
The script checks the gates in the header of that file.
Gate 1 enrolls the owner with `--id-token-file`.
Each deny reason and each ephemeral removal has an exact audit count.
It does not print key text. It was not executed on this head.

## Open points

- Run the proof on a Linux host with Docker. This change does not claim `proof_ok`.
- Tag route `autoApprovers` and exit nodes are follow-up issue https://github.com/KimSeogyu/Orblx/issues/159.
- A non-ephemeral node is not removed at key expiry. Revoke it with the existing admin path.
