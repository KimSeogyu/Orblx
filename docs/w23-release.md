# W23-5 release v0.1.0-rc.2

`v0.1.0-rc.2` is the second pre-release. It has the W23 changes:

| Item | PR | Merge commit |
| --- | --- | --- |
| W23-1 node lock | #64 | `b089a45fbf5d2616916f8e655853b6033ece79df` |
| W23-2 PTY recording | #63 | `1d56291` |
| W23-3 file send | #65 | `15a5e8e236063f5e1370f608f0402f3e2f014a01` |
| W23-4 receive path | #66 | `f5cd7426a2a6abc760ac4fe2af8e0e71442c1355` |
| Version `0.1.0-rc.2` | #67 | `b9cae9c103c04d29bb08be10c7d982ec9cffc65c` |

The release workflow, the installer, and the signature path are the same as in `docs/w20-release.md`.

Marks: **[C]** = shown in a container. **REAL** = shown on the real Linux host or on GitHub.

## Steps

After each tag, bump to the next -dev version on main (`docs/release-version.md`, W25-44).

1. PR #67 sets the workspace version to `0.1.0-rc.2` and the default tag of `scripts/proof/release-real.sh` to `v0.1.0-rc.2`.
   PR CI run 41024281783 passed on Linux and macOS. The PR merged on 2026-10-30 at 17:14 KST.
2. Main CI run 41025091764 on `b9cae9c` passed on Linux and macOS.
3. The annotated tag `v0.1.0-rc.2` (tag object `72dcade7d7dc9bed40b3e325fce07a0ff38e812d`) points to `b9cae9c`. Pushed at 17:21 KST.
4. Release workflow run https://github.com/KimSeogyu/Orblx/actions/runs/41025873236 passed on attempt 1.
   The 4 build jobs and the `sign and publish` job passed.

## Release (REAL)

| Item | Value |
| --- | --- |
| Release | https://github.com/KimSeogyu/Orblx/releases/tag/v0.1.0-rc.2 |
| Pre-release | yes |
| Draft | no |
| Published | 2026-10-30 17:25 KST |

| Asset | Bytes | SHA-256 |
| --- | --- | --- |
| `orblx-x86_64-unknown-linux-gnu.tar.gz` | 6499369 | `d982ea23aa006d8b57158d5c5ea80ff11c2af971fce1cbeb6daaef523a5c2f0a` |
| `orblx-aarch64-unknown-linux-gnu.tar.gz` | 6465180 | `6db080c3254ba871897de8c19c6078925959e060ecf6a1cf05ce4f7a8534aeaa` |
| `orblx-x86_64-apple-darwin.tar.gz` | 6237369 | `4278ebc3f394cc58073bf22de79bb5b7c3300130e4c960d85fed5dffbb3271ef` |
| `orblx-aarch64-apple-darwin.tar.gz` | 5877436 | `ef047b636d7e59f5176c145a6a94d3174c19250d528d10dc3ed55bf3638cdb93` |
| `SHA256SUMS` | 408 | `061634b85d2d1dbb69a24ec9111fb8a668cdea643388213cba0132bbb610a250` |
| `SHA256SUMS.sigstore.json` | 10331 | `bb23972717d9e21c76ae36db9d4e9b404ca3bf1fd17d8c929a76de43b9cf94b0` |
| `install.sh` | 7371 | `38f30084d84a5d94f13a0346039ca5f1dba81326787371095698401ddd5e251a` |

On the REAL host, `sha256sum -c SHA256SUMS` gives `OK` for the 4 tarballs.

## Real release proof

Command on the REAL Linux x86_64 host:

```bash
RELEASE_TAG=v0.1.0-rc.2 ./scripts/proof/release-real.sh
```

Log: `/workspace/orblx-w18-proof/rc2-b9cae9c1-release-real.log`, 2026-10-30 17:26 KST, `proof_ok`.

| Check | Result | Mark |
| --- | --- | --- |
| Clean Ubuntu 24.04 container has no `orblx` | `client has no orblx` | [C] |
| `curl .../v0.1.0-rc.2/install.sh \| sh -s -- --version v0.1.0-rc.2` from the real GitHub assets | `signature ok`, `checksum ok d982ea23…2f0a`, `orblx 0.1.0-rc.2` | [C] |
| `cosign verify-blob` with the exact identity and issuer | `Verified OK` | [C] |
| Fulcio certificate SAN | `https://github.com/KimSeogyu/Orblx/.github/workflows/release.yml@refs/tags/v0.1.0-rc.2` | [C] |
| Fulcio certificate issuer extension | `https://token.actions.githubusercontent.com` | [C] |
| Rekor entries in the bundle | 1 | [C] |
| Mirror with one changed byte (byte 3249684) in the x86_64 Linux tarball, real `SHA256SUMS` and bundle | `The checksum ... is not correct. The script installed nothing.`, `orblx_absent`, `install_exit 1` | [C] mirror, REAL download |

Identity: `https://github.com/KimSeogyu/Orblx/.github/workflows/release.yml@refs/tags/v0.1.0-rc.2`.
Issuer: `https://token.actions.githubusercontent.com`.

Extract of the log:

```text
orblx install: target x86_64-unknown-linux-gnu version v0.1.0-rc.2 source https://github.com/KimSeogyu/Orblx/releases/download/v0.1.0-rc.2
orblx install: signature ok
orblx install: checksum ok d982ea23aa006d8b57158d5c5ea80ff11c2af971fce1cbeb6daaef523a5c2f0a
orblx 0.1.0-rc.2
--- cosign verify-blob with the exact identity
Verified OK
verified_identity https://github.com/KimSeogyu/Orblx/.github/workflows/release.yml@refs/tags/v0.1.0-rc.2
verified_issuer https://token.actions.githubusercontent.com
orblx-x86_64-unknown-linux-gnu.tar.gz: OK
=== [C] install from the changed mirror must fail ===
orblx install: signature ok
orblx install: error: The checksum of orblx-x86_64-unknown-linux-gnu.tar.gz is not correct. The script installed nothing.
orblx_absent
install_exit 1
proof_ok
```

## W23 proofs on main before the tag

The W23-1 and W23-3 proofs ran again on main `f5cd7426` (all W23 items merged) on 2026-10-30 at about 17:00 KST.

| Proof | Log | Result |
| --- | --- | --- |
| `scripts/proof/node-lock.sh` [C] | `/workspace/orblx-w18-proof/main-f5cd7426-node-lock.log` | `proof_ok`. Unsigned node refused 78 times, no TCP. Signed nodes `HTTP/1.0 200`. Audit `verify ok records 22` with lock-rotate 1 and lock-remove 1. |
| `scripts/proof/file-send.sh` [C] | `/workspace/orblx-w18-proof/main-f5cd7426-file-send.log` | `proof_ok`. SHA-256 match for 8388608 bytes. Denied senders leave 0 files and 0 dot files. Audit 4 records, `ok`. |

This change did not run the NAT realism proof for this release.

## Limits

- The real release proof installs only the x86_64 Linux asset. The other 3 tarballs pass `sha256sum -c` against the signed `SHA256SUMS`, but no proof installs them.
- The macOS binaries are not signed or notarized by Apple.
- A pre-release is not the GitHub `latest` release. Give `--version v0.1.0-rc.2`.
- The installer needs cosign on the host.
