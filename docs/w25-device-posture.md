# Device posture checks in grants

This change adds named device posture rules to the policy. A grant or an SSH rule can name those rules. The coordinator checks the rules before it issues a capability ticket or an agent grant. When a node leaves posture, the coordinator revokes the ticket and the issued agent grants on the existing deny path.

The proposed gap-matrix row is 37. The PO confirms the row number. Rows 32, 33, and 35 are on `main`. Row 34 is open pull request 158. Row 36 is open pull request 161. This change does not edit the files those pull requests add.

Labels:

- **REAL**: `cargo test`, `cargo fmt --check`, and `cargo clippy` on this Linux host.
- **[C]**: `scripts/proof/device-posture.sh`. That script needs a Linux host and Docker. This host did not run it.

The change adds no new crypto. `os` and `clientVersion` are self-reported on the existing node channel. They are not attestation. The coordinator does not sign or check a device quote for them.

## 1. Facts

The coordinator stores one row per node in `posture.json` (mode 0600) in the state directory.

| Fact | Source | Unknown when |
| --- | --- | --- |
| `os` | Self-reported. This is not attestation. The node sends `std::env::consts::OS`, or `ORBLX_CLIENT_OS` when that variable is set. | The node sent no value, or the text is not a known token. |
| `clientVersion` | Self-reported. This is not attestation. The node sends the package version, or `ORBLX_CLIENT_VERSION` when that variable is set. | The node sent no value, or the text has no leading `major.minor.patch`. |
| `nodeLock` | Coordinator fact. The node-lock store says whether the current key set accepts the owner signature. Node lock off is `unsigned`. That value is known, so `nodeLock == signed` fails closed. | Node lock is on and the key set does not load. |
| `lastSeen` | Coordinator fact. The age is the coordinator clock minus the last authenticated coordinator event for that node. A report body does not set this clock. | The node has no authenticated coordinator event. |

Known `os` tokens: `linux`, `macos`, `windows`, `freebsd`, `openbsd`, `ios`, `android`.

`ORBLX_CLIENT_OS=unknown` and `ORBLX_CLIENT_VERSION=unknown` omit that fact. An omitted field clears the stored fact, so the next check fails closed. A bad token also clears the fact.

The version check uses the leading `major.minor.patch`. The suffix `-rc.3-dev` does not change the numbers.

## 2. Policy

`postures` maps a name to a list of predicates. Every predicate in one rule must pass. A flow is allowed when one covering accept row passes. A row with no `srcPosture` passes without a posture check.

| Predicate | Meaning |
| --- | --- |
| `os == TOKEN` | The self-reported OS is that token. |
| `os in [linux, macos]` | The self-reported OS is one token in the list. |
| `clientVersion >= X` | The self-reported version is `X` or newer. |
| `nodeLock == signed` | The coordinator has a good owner signature. |
| `nodeLock == unsigned` | The coordinator has no good owner signature. |
| `lastSeen <= N` or `lastSeen <= Ns` | The last report is at most `N` seconds old. |

An accept row or an SSH rule sets `srcPosture` to a list of rule names. A name that the file does not define is a policy error. A repeated name in one list is a policy error.

`postureTests` is the inline test list. `orblx policy test` prints `allow posture NAME` or `deny posture NAME`. The port `tests` list does not read posture, so an old policy file still loads.

A missing fact blocks the grant. The coordinator does not issue the capability ticket when any posture-gated flow for that source has no row without posture and the rule fails.

One node has one capability ticket. A posture fall closes every open session of that node. The coordinator puts that ticket nonce in the deny file and adds the node SVID to the deny list that peers already poll. A peer then refuses DATA on an open session and refuses a new handshake. The bound is the deny fetch period plus the 100 ms datapath read. The SVID is not written into the stored deny file, so the node can still reach the coordinator and post a posture report. Grants that still pass stay in the next grant document. The coordinator checks posture again at each ticket issue and each agent-grant issue. A new ticket is issued when every blocking rule passes. Old ticket nonces stay in the deny file after the node returns to posture.

## 3. Audit

| Action | Code | When |
| --- | --- | --- |
| `posture-deny` | 43 | The coordinator withholds a ticket or an agent grant. One record for each fall. |
| `posture-revoke` | 44 | The coordinator revokes a live ticket or issued agent grants. One record for each fall. |
| `posture-restore` | 45 | The node returns to posture. One record for each recovery. |

Codes 37 and 39 to 42 stay unused here. Code 37 is reserved for `node-remove`. Codes 39 to 42 stay free for the open pre-auth and admin-role changes. The SIEM list has `reserved-N` for those codes.

A node that stays out of posture does not add another record. A return to posture writes one `posture-restore` record and clears the latch. The next fall writes one record again. Old ticket nonces stay denied. The detail names the rule. It has no ticket nonce, no private key, and no enroll token.

Issued agent grants of an out node are marked revoked and their nonces go through the same deny file. A pending agent grant stays pending. A fetch or a new request while the node is out writes `posture-deny` when that fall has no revoke record yet.

## 4. Tests

| Test | Label | What it shows |
| --- | --- | --- |
| `posture::tests::a_version_suffix_does_not_change_the_numbers` | REAL | `-rc.3-dev` does not change `0.1.0`. A text with no numbers is rejected. |
| `posture::tests::an_unknown_fact_fails_closed` | REAL | A missing OS blocks `os in [linux, macos]`. `windows` fails. `macos` passes. |
| `posture::tests::inline_posture_tests_fail_closed_and_cover_each_fact` | REAL | Six inline tests cover OS, version, node lock, and last-seen. A missing OS blocks the grant and the ticket. An unknown `srcPosture` name rejects the file. |
| `posture::tests::node_lock_and_last_seen_use_coordinator_facts` | REAL | `signed`, `unsigned`, and a missing lock each have one result. Age `30` passes a `30s` limit. Age `31` and a missing age do not. |
| `posture::tests::a_posture_fall_revokes_once_and_a_second_fall_revokes_again` | REAL | In posture: 0 posture records and 1 grant. First fall: 1 `posture-revoke`. A repeat stays at 1. Recovery: 1 `posture-restore`, and the old nonce stays denied. Second fall: 2 `posture-revoke` records and 2 nonces. The audit text has no nonce and no key. |
| `posture::tests::a_peer_refuses_data_and_a_new_handshake_and_the_node_can_still_report` | REAL | After a fall, a new handshake fails on the peer deny list and DATA on the open session fails. The stored deny file has no node SVID, so the leaf still authenticates to the coordinator and a later posture report adds no record. After restore, the old ticket nonce still fails DATA. A renew while the node is out issues no ticket. |
| `posture::tests::a_pending_agent_grant_is_not_issued_while_the_node_is_out` | REAL | An approved agent grant is not issued while the node is out. The first fetch writes 1 `posture-deny`. A second fetch and a direct issue call add 0. The grant stays `approved`. |
| `posture::tests::an_unknown_os_withholds_the_ticket_and_denies_once` | REAL | A bad OS yields no ticket and exactly 1 `posture-deny`. Further checks and a renew stay at 1. |
| `posture::tests::an_agent_grant_request_denies_once_while_the_node_is_out` | REAL | An agent grant request while the node is out writes exactly 1 `posture-deny`. A second request adds 0. |
| `posture::tests::a_last_seen_age_past_the_limit_revokes_once` | REAL | A report older than the limit writes exactly 1 `posture-revoke` and removes the grant. A second check stays at 1. |
| `posture::tests::node_lock_off_fails_a_rule_that_requires_a_signature` | REAL | Node lock off is known `unsigned`. `nodeLock == signed` fails closed: the coordinator withholds the ticket and writes exactly 1 `posture-deny`. |
| `posture::tests::an_unauthenticated_report_changes_nothing_and_writes_no_restore` | REAL | A bad enroll token does not change `posture.json` and writes no `posture-restore`. |
| `posture::tests::a_report_for_another_node_is_refused` | REAL | Peer `b` cannot store a report for fallen node `a`. `a` stays `windows` and the restore count stays 0. |
| `posture::tests::junk_names_do_not_consume_posture_capacity` | REAL | 5000 names that are not enrolled add 0 rows. |
| `posture::tests::an_omitted_os_or_version_clears_the_stored_fact` | REAL | An omitted OS clears the stored OS. An omitted client version clears the stored version. The node then fails closed. |
| `the_siem_verifier_knows_each_action_code` | REAL | Codes 43, 44, and 45 match `posture-deny`, `posture-revoke`, and `posture-restore` in the SIEM list. |
| `scripts/proof/device-posture.sh` | [C] | Enroll, one OS fall, a second fall, and one unknown OS. Exact record counts. Not run on this host. |

## 5. Proof

`scripts/proof/device-posture.sh` runs under `scripts/proof/proof-lock.sh`. It uses `scripts/proof/compose.device-posture.yml` and `scripts/proof/device-posture.hujson`.

The script checks exact counts:

| Step | `posture-deny` | `posture-revoke` | `posture-restore` | Grants on `b` | Ticket nonces in `deny.json` |
| --- | --- | --- | --- | --- | --- |
| Enroll `a` and `b` in posture | 0 | 0 | 0 | 1 | 0 |
| `a` reports `windows` | 0 | 1 | 0 | 0 | 1 |
| `a` reports `windows` again | 0 | 1 | 0 | 0 | 1 |
| `a` reports `linux` and renews | 0 | 1 | 1 | 1 | 1 |
| `a` reports `windows` again | 0 | 2 | 1 | 0 | 2 |
| Enroll `c` with an unknown OS | 1 | 2 | 1 | 0 | 2 |
| `c` reports again while still out | 1 | 2 | 1 | 0 | 2 |

The script also checks that the audit chain verifies, that `orblx policy test` prints the three posture lines, and that logs and the audit file contain 0 copies of `PRIVATE KEY`, `ge1.`, `orblx-at1.`, and the revoked ticket nonces.

## 6. Limits

- One ticket and the projected SVID close every open session of that node. The close is not limited to the failing port.
- A return to posture writes one `posture-restore` record. Old ticket nonces stay denied.
- The stored deny file does not list the node SVID. The peer deny projection does. An owner revoke of that SVID is a separate stored entry.
- A pending agent grant is not issued while the node is out. The posture check and the ticket issue hold one lock. The first refusal in that fall writes `posture-deny` when the fall has no deny record yet.
- A posture report is stored only after authentication, and only for that peer. Last-seen changes only on that authenticated coordinator event.
- An omitted `os` or `clientVersion` clears the stored fact.
- Node lock off is `unsigned`. `nodeLock == signed` fails closed until an owner signs the node.
- `os` and `clientVersion` are self-reported. They are not attestation.
