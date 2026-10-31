# W25-31 SSH user certificates from the coordinator

Gap matrix rows 40 and 41. The coordinator issues short OpenSSH user certificates. The SSH server
on each node accepts a certificate login only when the certificate passes the checks below.

SSH identity = the user who owns the client node. Do not enroll a multi-user host as a personal node.

Marks: **REAL** = shown on a real host (Linux host, Docker engine, `cargo test`). **[C]** = a claim
that the container proof (`scripts/proof/ssh.sh`) or a unit test checks, or that comes from a
design rule, with no measured number. The unit tests are REAL. The network results are [C].

This item depends on #119 (W25-27, coordinator tickets). It merges only after #119 is on main.

## Trust note

- The coordinator is the SSH user CA. A user who controls the coordinator can log in as each user
  on each node that trusts the CA. Protect the coordinator state directory.
- The certificate principal is the owner of the client node in the coordinator store
  (`oidc:SUBJECT`). The client does not choose the principal.
- A local user on the client node who can read the node SVID key can ask for a certificate as the
  node owner. Thus the key and the request path are root-only (mode 0600, owner root).
- The CA keys are in `ssh-user-ca.json` in the coordinator state directory, mode 0600. The keys are
  not encrypted at rest. This is the same level as the other coordinator keys. [C]

## Keys

There are 3 separate keys:

| Key | Where | Use |
|---|---|---|
| SSH user CA (ed25519) | coordinator only | Signs the user certificates. The coordinator rotates it each 24 h. The netmap has `ssh_user_ca = [current, next]`. |
| Node SVID key | client node, root-only | Signs the request (SSHSIG, namespace `cert-request@orblx`). |
| Session key (ed25519) | client process memory | A new key for each login. The certificate certifies this key. The key is not written to disk. |

## Issue

The client node asks over its node mTLS session to the coordinator.

1. The client gets a single-use nonce (`ssh-cert-nonce`) on the connection.
2. The client signs `TLS exporter ('EXPORTER-orblx-ssh-cert-v1', 32 B) || nonce` with the node SVID
   key as an SSHSIG, namespace `cert-request@orblx`.
3. The coordinator checks the signature against the exporter of the same connection and takes the
   nonce. Another connection or a replayed nonce gets deny.
4. The coordinator reads the owner from its store and decides.

The coordinator refuses:

- agent SVIDs, coordinator SVIDs, and user SVIDs (only node SVIDs);
- a node that is revoked, not approved, expired, unknown, or that has no owner;
- an owner that is pending, rejected, or revoked;
- an owner with no ssh rule to any node (`no-grant`).

The certificate:

| Field | Value |
|---|---|
| Type | OpenSSH ed25519 user certificate |
| Principal | the owner, for example `oidc:alice` (one principal) |
| key_id | node URI + owner + serial |
| serial | a unique u64 from a counter in the store |
| valid_after | now - 60 s |
| valid_before | min(now + 15 min, SVID not_after) |
| Extensions | only `permit-pty` |
| Critical options | only `source-address` = the mesh IP of the client node /32 |

Each decision (allow and deny) writes exactly 1 config audit record `ssh-cert` (code 39). The
detail has the decision, the reason, the serial, the key fingerprint, the node, the principal,
and the validity. The record has no key and no certificate. The coordinator keeps an index from
(node, owner) to the live serials.

Codes 37 and 38 are reserved for other open items.

## Verify on the node

The node SSH server (russh) checks in this order:

1. The type is a user certificate.
2. The CA is in the current netmap `ssh_user_ca`. There is no cache of the CA set: a CA that
   rotated out of the netmap gets deny at once.
3. The validity, with a clock skew of at most 60 s.
4. The userauth signature (the client proves the session key).
5. The principal and the policy: exactly 1 principal, `oidc:SUBJECT`, and an ssh rule from
   `user/SUBJECT` to this node for the login name.
6. `source-address` must contain the TCP peer. An unknown critical option gets deny.
7. The serial or the key_id is not in the netmap `ssh_revoked` list, and the client node or the
   user is not in the deny list.

The SSH server refuses a new certificate login when the netmap is older than 60 s (the node writes
`netmap-fresh` after each good policy-wait reply; the reply comes at most each 20 s).
Each deny writes 1 deny record in `ssh-audit.jsonl`.

## Sharing and agents

- A sharee gets a certificate for the sharee principal only. A login as the sharer is refused.
- Agents get no certificate. The ssh policy rules decide each login.
- The old agent one-shot SSH path is not in the new proof (no node-issued tickets). [C]

## Revoke

- The netmap has the list `ssh_revoked` of `{serial, key_id}` for the live certificates of a
  revoked node or user.
- The node closes the matching SSH sessions and the mesh QUIC connections to the revoked node.
- The node gets the change by push (policy-wait, deny-wait) and polls at least each 30 s.
- The node refuses new certificate logins when its netmap is older than 60 s.

## CLI

```bash
# As root on the client node. The state directory has the node SVID and the coordinator address.
sudo orblx ssh alice@b --state /var/lib/orblx --peer-cert B.pem --command 'id'
sudo orblx ssh alice@b --state /var/lib/orblx --peer-cert B.pem --shell
```

A non-root caller gets: `The SSH certificate request needs root. The node SVID key is root-only.`

## Limits

- No OIDC step-up at login. That is W25-32.
- A CA rotation or a certificate expiry does not end an open session. Revoke ends it. [C]
- A node from before W25-31 rejects a netmap with the new fields (`deny_unknown_fields`). Update
  the nodes before the coordinator. [C]
- The Docker proof does not test a wrong private key with a real coordinator certificate. The
  russh unit test covers it (REAL).

## Results

PROOF_RESULTS
