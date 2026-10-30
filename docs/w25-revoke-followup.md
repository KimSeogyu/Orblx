# W25-2 Revoke follow-up: open sessions, undo, and the deny-list cost

This change continues W24-D (`orblx admin revoke-all`).
It has three parts:

1. An open SSH session on a node closes when the deny list of that node names the session peer.
2. `orblx admin revoke-undo SPIFFE_ID` gives the SVID back to a principal after `revoke-all`.
3. The nodes wait for a change of the deny list (long poll with an ETag). They do not fetch it each 500 ms.

Marks: **[C]** = shown in the container proof. **REAL** = shown on a real host (Linux host, Docker engine, `cargo test`).
The unit tests are REAL. The network results are [C].

## 1. Open SSH sessions close on revoke

Before this change, the SSH server checked an open session only at each `checkPeriod` (30 s in the proof policy).
A revoked peer could keep an open shell or command for up to that time.

Now each session on the SSH server reads `deny.json` of the node each 100 ms (`DenyWatch`).
It parses the file only when the file changes.
When the deny list names the session peer, the server:

- stops the process group of the session (shell or command),
- writes one `deny` record (reason `revoked`) into the SSH audit chain of the node,
- closes the channel.

The node gets the new deny list from the coordinator in ≤ about 100 ms (part 3).

The server now runs an `exec` command on a blocking thread (`spawn_blocking`).
Before, the command ran on a runtime worker thread. Two long commands could stop a shell session on the same node from starting until one command ended. The proof found this problem.

### Limit: the client side

`revoke-all` also puts the peer on the datapath deny list, so the node closes the overlay link to the revoked peer.
Thus the close message of the server does not get to the revoked client.
The client process stops only when its connection times out.
In the proof, the client processes on node a stopped 20 to 35 s after the revoke. The session on node b stopped in ≤ 206 ms.
The gate measures the session on the server (the last write of the session process), because that is the access that the revoke must stop.

## 2. Revoke undo

```
orblx admin revoke-undo spiffe://orblx.local/node/a --coord ... --admin-token-file ...
```

| Item | Rule |
|---|---|
| Scope | API token scope `nodes:write` (op `admin-revoke-undo`). |
| What it restores | The SVID of the principal only. The coordinator removes the URI from the revoked list and increases the deny version. The node then gets a new SVID at its next renew. |
| What it does not restore | Grants and grant nonces that `revoke-all` revoked stay revoked. The owner issues new grants. |
| Audit | Exactly 1 config record `unrevoke` (code 33). The detail is `principal URI scope all svid restored deny_version V`. |
| Errors | An undo for a principal that is not revoked fails and writes no record. |

New audit code: `unrevoke` = 33. W25-1 uses 30 (`share`) and 31 (`unshare`). W24-A uses 32 (`packet-deny`).

## 3. Deny list: wait for a change

Request op `deny-wait` with the field `deny_etag`.

- The ETag is the SHA-256 (hex) of the deny JSON of the caller with `generated_at` set to 0.
- When the ETag of the caller is not the current ETag, the coordinator replies at once.
- Otherwise the coordinator holds the request for up to 20 s (`DENY_WAIT_HOLD`). A watcher checks the deny file, the config audit file, the nodes file, and the policy file each 100 ms. When one changes and the ETag of the caller changes, the coordinator replies.
- The node sends the next wait 100 ms after a reply.
- When a wait fails (for example an old coordinator), the node goes back to the 500 ms fetch, and tries the wait again after 30 s.

No new crypto: the request uses the same mTLS channel and the same SVID check as the `deny` op.

## Proof

`scripts/proof/revoke-followup.sh` (release build). Nodes: `owner`, `a`, `b`, `c`, and `load` (50 more enrolled node identities).

| Gate | Check |
|---|---|
| 1 | a opens a PTY shell and a command on b. c opens a command on b. Each session writes the time (ms) to a file on b each 50 ms. Then `owner revoke-all a`. Close time = last write − `revoke_done_ms`. Limit 1000 ms. The session of c must continue to the end. The SSH chain of b must verify and have ≥ 2 `revoked` deny records. |
| 2 | SSH from a is refused. Then `owner revoke-undo a`. The script tries SSH until it works and prints the time. A second undo must fail. Exactly 1 new config record, and it is `unrevoke`, actor owner, target a. |
| 3 | 50 node identities fetch the deny list for 60 s, first with the 500 ms fetch (`poll`), then with the wait (`wait`). The coordinator CPU (utime + stime from `/proc`) is measured for each mode, and for 30 s with no load. The shipped mode (`wait`) must be ≤ 5% of one core. |

## Results [C]

Log: `/workspace/orblx-w18-proof/w25b-revoke-followup-branch-1f284f8-run2.log` (start 21:17:38 KST, 18 other proof containers).
Branch commit 1f284f8 plus the proof-script fix of the tick read (in this PR).

| Gate | Result |
|---|---|
| 1 shell session of a | closed 157 ms after `revoke_done` (limit 1000) [C] |
| 1 command session of a | closed 206 ms after `revoke_done` (limit 1000) [C] |
| 1 session of c | continued 5180 ms after the revoke and printed `finished` [C] |
| 1 SSH chain of b | verify ok, 10 records, 2 `revoked` deny records [C] |
| 2 undo | 1 new record, 1 `unrevoke` record, SSH of a works again 1627 ms after the undo, a second undo is refused [C] |
| 3 poll (500 ms fetch), 50 nodes | coordinator 12.11% of one core (11.98% net of the no-load base 0.13%), 5997 replies, 0 fail [C] |
| 3 wait (shipped), 50 nodes | coordinator 0.59% of one core (0.46% net), 200 replies, 0 fail [C] |
| secrets in logs | 0 tokens, 0 private keys [C] |

The 500 ms fetch costs more than 5% of one core for 50 nodes. Thus this change uses the wait (part 3).

A second run with 1 load node (debug, stack kept) gave 124 ms (shell) and 88 ms (command) for gate 1.

Unit tests (REAL):

- `deny_wait_replies_when_the_list_changes` (orblx-coord): the first wait replies at once, a second wait is held, and `revoke_all` makes it reply in < 1 s.
- `revoke_undo_restores_the_svid_with_one_record` (orblx-coord agent).
- `a_session_on_the_overlay_address_audits_start_end_and_deny` (orblx-ssh): a `sleep 5` command ends < 1 s after the deny file names the peer.
- `revoke-undo` arguments (orblx-cli).
