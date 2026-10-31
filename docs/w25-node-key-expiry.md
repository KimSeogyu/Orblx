# W25-20 Node key expiry and auth period (row 28)

This document describes the row 28 proof `scripts/proof/node-key-expiry.sh`.
The proof adds no datapath change and no handshake change.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the nodes `owner`, `a`, `a2`, `b`, `c`, and the Docker network are [C].

## Release note

An expired credential is refused at most 60 s after expiry (clock-skew allowance). For immediate cut-off, use revoke.

## Limits

The proof reads the limits from `crates/orblx-identity/src/clock.rs`. It does not hardcode them.

- `MAX_SKEW`: the clock-skew allowance. A leaf is refused when the time is more than `not_after + MAX_SKEW`.
- `MAX_USER_TTL`: the maximum node leaf life (15 min).
- `MAX_AGENT_TTL`: the maximum agent grant life (5 min).

The proof uses a short test setting `ORBLX_SVID_TTL` (default 60 s, `NKE_SVID_TTL`). Do not use this setting in production.

## Gates

1. Peer cut-off on two paths.
   - New handshake: node `a2` (no daemon, no renewal) sends a one-shot hello to `b`.
     The hello must pass at expiry + 30 s. The hello must fail at expiry + `MAX_SKEW` + 2 s.
   - Existing session: node `a` pings `b` each 0.2 s. The coordinator is blocked for `a` before the renewal time.
     Replies must arrive before expiry and from expiry + 29 s to expiry + 31 s.
     0 replies must arrive at or after expiry + `MAX_SKEW` + 1 s.
   - Control: node `c` renews and pings `b`. Replies must continue after expiry + `MAX_SKEW` + 1 s.
2. The coordinator refuses the lapsed leaf: `orblx coord netmap` from `a` fails, and the renewer logs `The SVID renewal failed`.
3. `admin expire a` writes 1 audit record, and the audit chain verifies.
4. A revoked node (`c`) cannot renew. Its `svid_expiry` does not change.
5. An offline node (`a`) is refused after TTL + skew (gate 1, existing session).
6. A new enroll of `a` restores access: `ping -c 5` to `b` has 0% loss.
7. `ORBLX_SVID_TTL` = `MAX_USER_TTL` + 1 s is refused. `agent grant request --ttl` = `MAX_AGENT_TTL` + 1 s is refused.

The proof waits for fixed clock points (expiry + 30 s, expiry + `MAX_SKEW` + 2 s). These waits are a schedule. They are not retries.
The proof has no retry loop for a gate.

## Status gap

The node `orblx status` shows `svid_expiry`. The proof prints `lapsed_by_s` from that value.
The coordinator `admin nodes` output shows only `approved`, `expired` (admin flag), and `pending`.
The coordinator cannot show a lapsed leaf without new code. This change adds no code for it.

## Finding: renewal does not replace the in-memory capability ticket

Dev run 2 (`/workspace/orblx-w18-proof/w25t-nke-dev2.log`, `ORBLX_SVID_TTL=60`) failed closed at the control gate.

- The renewal replaces only the leaf and the key in the running node (`apply_leaf`, `crates/orblx-datapath/src/node.rs`).
- The coordinator issues a new ticket at renewal, and the client writes it to the state directory.
  The running node does not load it. The node keeps the ticket from enroll. The ticket life is the SVID TTL.
- After the ticket end + skew, the peers refuse the node:
  `The capability ticket check rejected the peer. The end time has passed.`
  This occurred for `b`, `c`, and `owner`, which all renewed.
- With the default TTL (15 min), a node that runs `orblx up --coord` loses its peers about 16 min after enroll.
- `svid-renew.sh` does not find this, because it uses lab tickets with a long life.

The fix is a datapath change. W25-20 must not change the datapath. A separate change must fix it.
The row 28 proof stays fail-closed until that fix is on main.

Dev run 2 numbers (one run, `MAX_SKEW` = 60 s, E = leaf expiry of `a`):

| Check | Result |
| --- | --- |
| a2 hello before expiry | exit 0, path direct, start E - 57.391 s |
| a2 hello at E + 30 s | exit 0, path direct, start E + 30.003 s, end E + 30.154 s |
| a2 hello at E + 62 s | exit 1, start E + 62.085 s |
| b expired-leaf handshake rejects | 8 before, 35 after |
| a replies before E | 280 |
| a replies E + 29 s to E + 31 s | 9 |
| a replies at E + 61 s or later | 0 |
| a last reply | E + 57.900 s |
| c replies at E + 61 s or later | 0 (gate failed) |

The last reply of `a` came before E + 60 s. The ticket of `b` ended before the leaf of `a`, so the cut-off of `a` in this run is not only the leaf check.
After the ticket fix, the proof must run again.
