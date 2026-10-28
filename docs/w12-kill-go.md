# Week 12 kill or go

The base commit is `f4ce5c86d18108ffe71d70325a8f958230d60147`.
This packet records measured items only.

## K4

Status: defer.

K4 is the SVID PEM load from disk.
Read the K4 section in [connector-hub.md](connector-hub.md).
Pass is not measured.
Fire is not measured.

Checks on `main` at `f4ce5c86d18108ffe71d70325a8f958230d60147`:

- [connector-hub.md](connector-hub.md) says this week does not replace the PEM load from disk.
- `crates/gyeol-cli/src/ticket_load.rs` reads `ticket-verifier.pem` from disk.
- `crates/gyeol-datapath/src/connector/lab.rs` writes SVID PEM files and reads those files.
- `crates/gyeol-identity/src/ca.rs` returns `certificate_pem` and `private_key_pem`.
- `TrustBundle::from_pem` in `crates/gyeol-identity/src/cert.rs` reads PEM text in memory.
- `decode_certificate_pem_file` is absent.
- `TrustBundle::from_pem_file` is absent.
- `IssuedSvid::from_pem` is absent.
- `IssuedSvid::from_pem_files` is absent.
- The City Breeze feed test in `crates/gyeol-sim/src/sim.rs` rejects the strings `BEGIN` and `PRIVATE` in the event JSON.
- That feed test does not remove the disk PEM load.

Open pull request: https://github.com/KimSeogyu/Orblx/pull/22
Head SHA: `bae897a312c10001858698bd50385c8979d17889`
State on 2026-10-28: open.
`mergedAt` is null.
The head commit message is `Load SVID and trust-bundle PEM from disk paths.`

That head contains these functions:

- `decode_certificate_pem_file` in `crates/gyeol-identity/src/cert.rs`
- `TrustBundle::from_pem_file` in `crates/gyeol-identity/src/cert.rs`
- `IssuedSvid::from_pem` in `crates/gyeol-identity/src/ca.rs`
- `IssuedSvid::from_pem_files` in `crates/gyeol-identity/src/ca.rs`

The residual clearance is on that open pull request.
It is not on `main`.
After pull request 22 merges, the Eng Lead or the PO may reclassify K4.
Until that merge, the status stays defer.

## K5

Status: unsigned.

The Eng Lead sign is empty.
The team sign is empty.

| Role | Name | Date | Sign |
| --- | --- | --- | --- |
| Eng Lead | | | awaiting Eng Lead |
| Team | | | awaiting Eng Lead |

## K6

Early-user notes: none observed this week.

A maintainer check of the demo is not an early-user session.

## Maintainer check

Date: 2026-10-28.
Command: `./scripts/demo.sh`
Result: `demo pass`.

The script printed these lines:

```text
easy pass
revoke pass within_s 0
medium pass
agent pass
hard pass within_s 0
udp pass
demo pass
```

Revoke `within_s` was 0.
Hard `within_s` was 0.
The page check found no animation.

Command: `./scripts/audit-smoke.sh`
Result: `The session audit chain check passed.`
`audit verify` printed `ok`, start 1, end 1, deny 1, and records 3.
The tip was `7292992ea22a6755b81526c80ae3adfdf601a8753c3a4303b9a3f8509b552e92`.

Command: `./scripts/connector-smoke.sh`
Result: `The userspace connector proof passed.`
`app-a.orblx.test` returned status 200.
`app-b.orblx.test` returned status 200.
Each app reported `mesh_to 2` and `mesh_from 2`.

Command: `cargo fmt --all -- --check`
Command: `cargo clippy --workspace --all-targets -- -D warnings`
Command: `cargo test --workspace`
Result: each command passed.

This check is not an early-user session.

## Early-user path

The browser steps and the event kinds are in the README.

Run the demo:

```bash
./scripts/demo.sh
```

A pass prints `demo pass`.

Run the session audit check:

```bash
./scripts/audit-smoke.sh
```

The script runs `audit demo` and `audit verify`.
A pass prints `The session audit chain check passed.`
Read the byte layout in [session-audit.md](session-audit.md).

Run the userspace connector check:

```bash
./scripts/connector-smoke.sh
```

A pass prints `The userspace connector proof passed.`

The harness run steps are in [demo-sim.md](demo-sim.md).
The feed fields are in [w11-feed-v1.md](w11-feed-v1.md).

## TUN

Read [w12-tun-bench.md](w12-tun-bench.md).
The command is `./scripts/tun-bench.sh`.
The measured Mbps value is pending Datapath measurement.
The supporting pull request is pending.
The Datapath agent id is `bc-551a2bb3`.

## Scope

This packet does not add a marketplace.
This packet does not add recruiting.
Stick and upgrade stay deferred.
Full OIDC polish stays out.
This packet does not add WireGuard.
This packet does not add Headscale.
This packet does not add DERP.
