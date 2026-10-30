# Release and install

A tag `v*` starts `.github/workflows/release.yml`.
The workflow builds `orblx`, makes one tarball for each target, writes `SHA256SUMS`, signs `SHA256SUMS` with cosign, and publishes a GitHub release.
`scripts/install.sh` downloads the files, checks the signature and the checksum, and installs `orblx`.

## Targets

| Target | Runner |
| --- | --- |
| `x86_64-unknown-linux-gnu` | `ubuntu-22.04` |
| `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm` |
| `aarch64-apple-darwin` | `macos-latest` |
| `x86_64-apple-darwin` | `macos-latest` (cross build) |

The Linux builds use Ubuntu 22.04, so the binaries need glibc 2.35 or later.

## Release files

| File | Content |
| --- | --- |
| `orblx-TARGET.tar.gz` | Directory `orblx-VERSION-TARGET` with `orblx`, `LICENSE`, `NOTICE`, `README.md`, `orblxd.service`, and `dev.orblx.plist` |
| `SHA256SUMS` | One SHA-256 line for each tarball |
| `SHA256SUMS.sigstore.json` | The cosign bundle: signature, Fulcio certificate, and Rekor entry |
| `install.sh` | The installer |

`scripts/release/package.sh VERSION TARGET BIN OUT_DIR` makes one tarball.
The workflow and the proof use the same script.
The tarball has a fixed file order, owner 0, and time 0.

## Signature

The publish job signs `SHA256SUMS` with keyless cosign:

1. The job gets a GitHub OIDC token (`id-token: write`).
2. Fulcio gives a short-lived certificate for the workflow identity.
3. cosign signs `SHA256SUMS` and writes the Rekor entry into the bundle.

The repository has no signing key and no signing secret.
The signer identity is `https://github.com/KimSeogyu/Orblx/.github/workflows/release.yml@refs/tags/vX.Y.Z`.
The OIDC issuer is `https://token.actions.githubusercontent.com`.
The job checks the signature before it publishes.
The workflow also stops when the tag is not `v` plus the workspace version.

## Install

```bash
curl -fsSL https://github.com/KimSeogyu/Orblx/releases/latest/download/install.sh | sh
curl -fsSL https://github.com/KimSeogyu/Orblx/releases/latest/download/install.sh | sh -s -- --version v0.1.0 --service
```

| Option | Variable | Content |
| --- | --- | --- |
| `--version TAG` | `ORBLX_VERSION` | Release tag. Default `latest` |
| `--prefix DIR` | `ORBLX_PREFIX` | Install directory. Default `/usr/local/bin` |
| `--base-url URL` | `ORBLX_BASE_URL` | A mirror directory with the release files |
| `--cosign-key FILE` | `ORBLX_COSIGN_KEY` | Check with a cosign public key, not the keyless identity |
| `--service` | `ORBLX_SERVICE=1` | Install `/etc/systemd/system/orblxd.service` or `/Library/LaunchDaemons/dev.orblx.plist` |

The installer does these steps:

1. It finds the OS (`Linux` or `Darwin`) and the CPU (`x86_64` or `aarch64`).
2. It downloads the tarball, `SHA256SUMS`, and `SHA256SUMS.sigstore.json` into a temporary directory.
3. It checks the signature of `SHA256SUMS` with `cosign verify-blob`. Without `--cosign-key`, the certificate identity must match the release workflow on a `v*` tag, and the issuer must be GitHub Actions.
4. It checks the SHA-256 of the tarball against the one line for the tarball in `SHA256SUMS`.
5. It installs `orblx` with mode 0755 and runs `orblx --version`.
6. With `--service`, it installs the service file. On Linux with systemd, it runs `systemctl daemon-reload`. It does not enable or start the service.

Each failed check prints `orblx install: error: ...`, exits 1, and installs nothing.
The installer needs cosign. Without cosign, it stops. It has no option to skip the check.
An `http://` base URL prints a warning. The signature and the checksum still protect the files.
The installer uses `sudo` only when the prefix is not writable or `--service` is set.

## Dependabot fix

The Dependabot run "cargo in /crates/orblx-ssh for russh" failed each time.
The job was a security update for 18 open russh advisories, for example GHSA-4wc5-f2rc-q74m (`<= 0.64.0`) and GHSA-j7h2-66j4-ghjf (`< 0.64.0`).
The manifest pinned `russh = "=0.54.1"`.
The directory `/crates/orblx-ssh` has no lockfile, so Dependabot stopped with "Dependabot can't update vulnerable dependencies for projects without a lockfile or pinned version requirement".
This change updates russh to `=0.65.0`. That version is not in the range of any advisory.
The code changes for the new russh API are:

- `check_server_key` gets `PublicKeyOrCertificate`. The client accepts only a raw Ed25519 key that is equal to the expected key. The client refuses an SSH certificate.
- `channel_open_session` gets a `ChannelOpenHandle`. The server calls `accept`.
- Channel data is `Bytes`.

russh 0.65.0 needs Rust 1.89, so the workspace `rust-version` is now 1.89.
`.github/dependabot.yml` does not change.

[C] `scripts/proof/ssh.sh` with russh 0.65.0. The SSH command from alice to node b prints `alice`. This extract does not show the audit counter lines:

```text
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
revoke_seconds 1
=== [C] audit chain on node b ===
ok
=== [C] audit chain on node c ===
ok
proof_ok
```

## Container proof

| Host | Label | Role |
| --- | --- | --- |
| Linux machine that runs Docker | REAL | Builds the release binary, makes the tarball, writes `SHA256SUMS`, and signs with a throwaway key |
| `orblx-release-http` container | [C] | `python3 -m http.server`. Serves the good files and three changed copies |
| Client containers | [C] | Clean Ubuntu 24.04 with curl and cosign. No orblx. One new container for each install |

The proof script is `scripts/proof/release.sh`.
The script gets cosign v3.1.4 and checks its SHA-256. `COSIGN_BIN` can point to a local copy.
The throwaway keys stay in a temporary directory. The cleanup removes them.
A local key has no Rekor entry, so the proof uses `--cosign-key`, and the check skips the transparency log.
The keyless path runs only in GitHub Actions.

Run this command on the REAL Linux host:

```bash
scripts/proof/release.sh
```

The script does these steps:

1. It builds `orblx` in release mode and makes `orblx-x86_64-unknown-linux-gnu.tar.gz`.
2. It writes `SHA256SUMS` and signs it with the throwaway key `test`.
3. It makes three changed copies: `bad-tarball` (one byte of the tarball), `bad-sums` (byte 0 of `SHA256SUMS`), and `bad-signer` (signed with the other throwaway key).
4. A clean client runs `curl | sh` from `good` with `--service`. The install must pass.
5. A clean client runs the install from each changed copy. Each install must fail, and `/usr/local/bin/orblx` must not exist.
6. A client without cosign must fail.
7. It checks that no served file has private key text, then prints `proof_ok`.

The recorded run output starts after the build:

```text
=== [REAL] package, checksum, and sign ===
packaged orblx-x86_64-unknown-linux-gnu.tar.gz version 0.1.0
468fe676dc0a59a3deca01c7fe37a73c5468b0f7d1c80e56bbcb4f3d741a6dcb  orblx-x86_64-unknown-linux-gnu.tar.gz
test_public_key_sha256 6aeec7503a4832c5b3bcc759f1e690129e88104e81c724ee913bf3a578b4e0b9
104 SHA256SUMS
387 SHA256SUMS.sigstore.json
7371 install.sh
5919791 orblx-x86_64-unknown-linux-gnu.tar.gz
=== [REAL] make the changed copies ===
changed byte 2959895 of orblx-x86_64-unknown-linux-gnu.tar.gz
changed byte 0 of SHA256SUMS
bad-signer: SHA256SUMS is signed with a different throwaway key
=== [C] build the clean client image ===
client has no orblx
=== [C] start the HTTP container ===
=== [C] install from good with curl | sh ===
orblx install: warning: http://orblx-release-http:8000/good is not HTTPS. The signature and the checksum still protect the files.
orblx install: target x86_64-unknown-linux-gnu version latest source http://orblx-release-http:8000/good
orblx install: check the signature of SHA256SUMS
orblx install: signature ok
orblx install: check the SHA-256 of orblx-x86_64-unknown-linux-gnu.tar.gz
orblx install: checksum ok 468fe676dc0a59a3deca01c7fe37a73c5468b0f7d1c80e56bbcb4f3d741a6dcb
orblx install: installed /usr/local/bin/orblx
orblx 0.1.0
orblx install: installed /etc/systemd/system/orblxd.service
orblx install: systemd is not running. The script did not reload systemd.
orblx install: done
-rwxr-xr-x /usr/local/bin/orblx
-rw-r--r-- /etc/systemd/system/orblxd.service
orblx 0.1.0
=== [C] install from bad-tarball must fail ===
orblx install: warning: http://orblx-release-http:8000/bad-tarball is not HTTPS. The signature and the checksum still protect the files.
orblx install: target x86_64-unknown-linux-gnu version latest source http://orblx-release-http:8000/bad-tarball
orblx install: check the signature of SHA256SUMS
orblx install: signature ok
orblx install: check the SHA-256 of orblx-x86_64-unknown-linux-gnu.tar.gz
orblx install: error: The checksum of orblx-x86_64-unknown-linux-gnu.tar.gz is not correct. The script installed nothing.
install_exit 1
=== [C] install from bad-sums must fail ===
orblx install: warning: http://orblx-release-http:8000/bad-sums is not HTTPS. The signature and the checksum still protect the files.
orblx install: target x86_64-unknown-linux-gnu version latest source http://orblx-release-http:8000/bad-sums
orblx install: check the signature of SHA256SUMS
orblx install: error: The signature check of SHA256SUMS failed. The script installed nothing.
install_exit 1
=== [C] install from bad-signer must fail ===
orblx install: warning: http://orblx-release-http:8000/bad-signer is not HTTPS. The signature and the checksum still protect the files.
orblx install: target x86_64-unknown-linux-gnu version latest source http://orblx-release-http:8000/bad-signer
orblx install: check the signature of SHA256SUMS
orblx install: error: The signature check of SHA256SUMS failed. The script installed nothing.
install_exit 1
=== [C] install without cosign must fail ===
orblx install: warning: http://orblx-release-http:8000/good is not HTTPS. The signature and the checksum still protect the files.
orblx install: error: cosign is not installed. The script needs cosign to check the signature. See https://docs.sigstore.dev/cosign/system_config/installation/
=== [REAL] no private key text in the served files ===
private_key_in_www none
proof_ok
```

## Limits

- The proof checks the key path of the installer. The keyless path needs a real tag run in GitHub Actions.
- No release tag exists yet. The first `v0.1.0` tag is the first real run of the workflow.
- The macOS binaries are not signed or notarized by Apple. Gatekeeper can block a binary from a browser download. `curl` downloads do not get the quarantine flag.
- The installer needs cosign on the host.
