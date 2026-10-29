# ADR 0005: SSH with an SVID

- Status: Accepted
- Language: English ASD-STE100 (Eng Lead rule)
- Date: 2026-10-29
- Related: [ADR 0001](0001-stack.md), [ADR 0002](0002-frame-hello-quic.md)

## Context

`orblx ssh user@node` must sign in with the node SVID or the user SVID.
The node daemon must accept SSH only on its overlay address.
The design must not use a static SSH key.
The design must not use `authorized_keys`.
An agent must present one JIT ticket for one host and one user.
The ticket reuses `FLAG_AGENT_JIT` and `FLAG_ONE_SHOT`.
A revoked SVID must make a new session fail within 60 seconds.
The audit chain must record start, end, and deny.

Two designs were compared.

1. An in-daemon SSH server. The server is russh. The host key is the node SVID key. The key stays in memory.
2. Short-lived OpenSSH certificates. The daemon mints a certificate from the SVID. OpenSSH `sshd` accepts the certificate.

## Decision

Use the in-daemon russh server.

The server binds `overlay:22`.
The server rejects the unspecified address.
The password method carries one SVID proof.
The proof is a signature.
The server does not log the proof.
The server does not write an SSH key file.
The server does not read `authorized_keys`.

A human SVID and a node SVID do not send a ticket.
An agent SVID sends one ticket.
The ticket names the overlay host `/32`, TCP, and port 22.
The ticket sets `FLAG_AGENT_JIT` and `FLAG_ONE_SHOT`.
The SSH policy names the one login user for that agent.
The server spends the ticket nonce in memory and in `ssh-spent.txt`.

Each new session reads `deny.json`.
A revoked SVID fails at that check.
An open command reads the policy again after the check period.

The audit chain is `ssh-audit.jsonl` in the node state directory.

OpenSSH certificates stay out of this design.
`sshd` would keep a host key file and an `authorized_keys` path.
Those files are outside the SVID check and the audit chain.

## Consequences

The node process links russh `0.54.1`.
The crate uses the `ring` feature.
The workspace does not add WireGuard, Headscale, DERP, or Tailscale crates.
The client checks the SSH host key against the peer SVID before it sends the proof.
