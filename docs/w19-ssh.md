# SSH with an SVID

`orblx ssh user@node` signs in with an SVID.
The node daemon accepts SSH on the overlay address at port 22.
The server does not read `authorized_keys`.
The server does not write an SSH key file.
The host key is the node SVID key. The key stays in memory.
ADR 0005 records the russh choice.

The policy file is HuJSON.
An `ssh` rule names `src`, `dst`, `users`, and `checkPeriod`.
`checkPeriod` is `30s` or `1m`.
The default is deny.
An agent source needs one host and one user.
The agent ticket sets `FLAG_AGENT_JIT` and `FLAG_ONE_SHOT`.
The ticket names that host, TCP, and port 22.
The server spends the ticket once.
A new session reads `deny.json`.
A revoked SVID fails that check.
`orblx admin revoke` writes the node SVID into that deny file.
The SSH server refuses a new session when the node SVID is in the file.
The audit chain is `ssh-audit.jsonl` in the node state directory.

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the image and runs Compose |
| `node-a` container | [C] | SSH client. Overlay `100.64.0.1` |
| `node-b` container | [C] | SSH server for user `alice`. Overlay `100.64.0.2` |
| `node-c` container | [C] | SSH server that denies `alice`. Overlay `100.64.0.3` |

The image is `orblx-ssh:local`.
The proof script is `scripts/proof/ssh.sh`.
The Compose file is `scripts/proof/compose.ssh.yml`.
The policy file in the proof is `scripts/proof/ssh.hujson`.
The script does not print private keys, tickets, or SVID proofs.

## Commands

```bash
orblx ssh USER@NODE --identity DIR --netmap FILE --peer-cert FILE [--command TEXT]
orblx node-issue --out DIR --node NAME=OVERLAY_IP [--user NAME] [--agent NAME --agent-parent USER --agent-host ADDR --agent-user USER]
orblx audit verify --file FILE
```

The client checks the SSH host key against `--peer-cert`.
The client then sends one SVID proof.
The default command prints `ORBLX_SSH_USER`.

## Proof

Run this command on the Linux host:

```bash
bash scripts/proof/ssh.sh
```

The run on 2026-10-29 used one REAL Linux x86_64 host.
Docker built `orblx-ssh:local`.
Three [C] containers stood in for the other hosts.
The script printed this result:

```text
=== [REAL] one Linux host ===
Linux
x86_64
=== [C] issue SVIDs ===
The command wrote the node a material for overlay 100.64.0.1 in /tmp/tmp.1xeD9C42Ft/a.
The command wrote the node b material for overlay 100.64.0.2 in /tmp/tmp.1xeD9C42Ft/b.
The command wrote the node c material for overlay 100.64.0.3 in /tmp/tmp.1xeD9C42Ft/c.
The command wrote the user alice material in /tmp/tmp.1xeD9C42Ft/users/alice.
The command wrote the user mallory material in /tmp/tmp.1xeD9C42Ft/users/mallory.
The command wrote the agent helper ticket for host 100.64.0.2 user alice in /tmp/tmp.1xeD9C42Ft/agents/helper.
=== [C] start nodes ===
=== [C] alice to node b ===
alice
=== [C] admin revoke of node b through deny.json ===
The SSH session was refused.
denied node-b
node_revoke_seconds 1
alice
=== [C] mallory denied ===
The SSH session was refused.
denied mallory
=== [C] alice to node c denied ===
The SSH session was refused.
denied host
=== [C] agent one shot ===
alice
The SSH session was refused.
denied replay
=== [C] revoke alice ===
The SSH session was refused.
denied revoked
revoke_seconds 0
=== [C] audit chain on node b ===
ok
tip cf472d20339d58e85a511c22dddc05a34a4fc04738fb5076c1e812182311663b
start 3
end 3
deny 4
records 10
=== [C] audit chain on node c ===
ok
tip 605f402a05def3a947ffbe0fdbadcc7db5dac40daa4fe962e0a5cb461a930642
start 0
end 0
deny 1
records 1
proof_ok
```

`alice` on node `b` returned the login name.
The deny file then named `spiffe://orblx.local/node/b`.
That is the URI `orblx admin revoke` writes.
The next SSH session failed in 1 second.
A later deny file with no URIs allowed alice again.
Mallory was denied.
Alice to node `c` was denied.
The agent ticket worked once and the replay was denied.
After the deny file revoked the alice SVID, the next session failed in 0 seconds.
The node `b` chain has start 3, end 3, and deny 4.
The node `c` chain has deny 1.
