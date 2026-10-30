# W25-8 Official Docker image

Gap matrix row 58. This change adds an official Orblx container image.
A container from the image enrolls one time, joins the mesh, and runs as a normal node.
The same image also runs the coordinator (`coord serve`) and the other `orblx` commands.

Labels:

- **REAL**: the Linux host and the Docker engine (29.x, legacy builder) on that host.
- **[C]**: a container. The coordinator and the nodes `a` and `b` are [C].

The change adds no Rust code, no new crypto design, no new dependency, and no new port.
It does not change `node.rs`, `up.rs`, the data path, the coordinator audit files, or the policy sharing files.
CI builds the image. CI does not push the image to a registry.

Files:

- `docker/Dockerfile`: the image.
- `docker/entrypoint.sh`: the node start steps.
- `.dockerignore`: the build context has only `Cargo.toml`, `Cargo.lock`, `crates/`, and `docker/entrypoint.sh`.
  It replaces the old list (`target`, `.git`). The other proof images use their own staged directories, so the change does not affect them.
- `scripts/proof/docker-image.sh`: the proof.
- `scripts/proof/image-secrets-scan.py`: the scan of `docker save` output.
- `.github/workflows/ci.yml`: the job `Docker image build, size, and secrets scan`.

## 1. Image

The Dockerfile has three stages:

1. `rust:1-alpine` builds `orblx` with `cargo build --release --locked -p orblx-cli --bin orblx` (musl), then strips it.
   The crypto is ring only, so the musl build needs no OpenSSL.
2. `alpine:3.22` adds `iproute2` (required, for `ip`) and `iptables` (subnet routes and exit nodes).
   Then it removes the public CA bundle, the apk signing keys, and the apk database.
   The node uses only the coordinator trust bundle in its state directory.
3. `FROM scratch` copies the stage 2 root file system into one flat layer.
   Thus the removed files are not in a lower layer.

The image has `VOLUME /var/lib/orblx`, `ENTRYPOINT ["/usr/local/bin/orblx-entrypoint"]`, and `CMD ["node"]`.
The image has no `systemd-resolved`. The node prints that `resolvectl` is not available and continues.
Thus the `~orblx` DNS domain is not set in the container. Overlay IPs work.

Build from the repository root:

```sh
docker build -f docker/Dockerfile -t orblx:local .
```

## 2. Run a node

The node needs only these items:

- an enroll token: `ORBLX_ENROLL_TOKEN_FILE` (a mounted file) or `ORBLX_ENROLL_TOKEN` (a value, for example from `--env-file`),
- `--cap-add NET_ADMIN` and `--device /dev/net/tun`. Do not use `--privileged`.
- the coordinator address and its public trust bundle,
- a volume for `/var/lib/orblx`.

```sh
docker run -d --name orblx-a \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -e ORBLX_COORD=COORD_IP:443 -e ORBLX_NAME=a \
  -e ORBLX_BUNDLE_FILE=/run/orblx/bundle.pem -v "$PWD/trust-bundle.pem:/run/orblx/bundle.pem:ro" \
  -e ORBLX_ENROLL_TOKEN_FILE=/run/orblx/token -v "$PWD/token-a:/run/orblx/token:ro" \
  -v orblx-a:/var/lib/orblx \
  orblx:local
```

| Variable | Use | Default |
| --- | --- | --- |
| `ORBLX_COORD` | The coordinator address, `IP:PORT`. Required. | none |
| `ORBLX_NAME` | The node name. Required for the first enroll. | none |
| `ORBLX_BUNDLE_FILE` | The coordinator trust bundle (public PEM). Required for the first enroll. | none |
| `ORBLX_ENROLL_TOKEN_FILE` | A file with the enroll token. | none |
| `ORBLX_ENROLL_TOKEN` | The enroll token as a value. The script uses it only when `ORBLX_ENROLL_TOKEN_FILE` is not set. | none |
| `ORBLX_ENDPOINT` | The underlay endpoint for peers. | the container IPv4, port 443 |
| `ORBLX_LISTEN` | The QUIC listen address. | `0.0.0.0:443` |
| `ORBLX_COORD_NAME` | The coordinator TLS name. | `coord` |
| `ORBLX_STATE_DIR` | The state directory. | `/var/lib/orblx` |

The `node` command does these steps:

1. If the state directory has `cert.pem`, `key.pem`, and `bundle.pem`, it prints `orblx-entrypoint: state found, no enroll.`
   It does not read the token.
2. If not, it runs `orblx coord enroll` one time. A token value goes to a `0600` temp file in `/tmp`.
   The script deletes that file after the enroll. Then it prints `orblx-entrypoint: enrolled NAME.`
3. It removes `ORBLX_ENROLL_TOKEN` and `ORBLX_ENROLL_TOKEN_FILE` from the environment.
4. It runs `orblx coord netmap`. When the fetch fails, the node uses the netmap in the state directory.
5. It runs `exec orblx up --coord ...`. `orblx up` renews the SVID from the coordinator at 2/3 of its life.

Each other command goes to `orblx`, for example `docker run orblx:local coord serve --state /var/lib/orblx`.

Limits:

- The node gets the netmap at start. A peer that enrolls later is in the netmap after a restart of the node.
  The proof restarts `b` after `a` enrolls for this reason.
- With `ORBLX_ENROLL_TOKEN`, Docker keeps the value in the container config (`docker inspect`).
  The token is one use, so it is not valid after the enroll. Use `ORBLX_ENROLL_TOKEN_FILE` when you can.
- The image has no package manager keys. To add packages, build your own image from `docker/Dockerfile`.
- Out of scope: a Kubernetes operator, a userspace (no TUN) mode, and a registry push.

## 3. Proof

Script: `scripts/proof/docker-image.sh`. Run it as root, or as a user that can use `sudo -n docker`.
The script uses the names `orblx-w25h-dimg-*` (containers, volumes, one network).
It runs the coordinator from the same image with `ORBLX_SVID_TTL=60`.
It does not print enroll tokens, keys, or certificates.

Log: `/workspace/orblx-w18-proof/w25-h-docker-image-ed4c0a83.log` (branch commit `ed4c0a8`, with main `06e4a0b`).
Earlier branch runs (`ecb00bfa`, `75bf8530`) are `proof_ok` too.

| Gate | Label | Result |
| --- | --- | --- |
| 1. Multi-stage build, slim runtime, at most 60 MB | REAL | `size_bytes 40603039` (40.6 MB), 1 layer. PR CI (BuildKit, run 41055756663, before #80 and #85) reports `size_bytes 27703428` (27.7 MB) for the same Dockerfile. The two engines measure the size differently. Both are below the limit. The stripped release binary is 14964872 bytes (15.0 MB). |
| 2. Only a token, `NET_ADMIN`, and `/dev/net/tun`: enroll, SVID, overlay ping | [C] | `b` used a token file. `a` used a token env var (`--env-file`). `privileged false cap_add [CAP_NET_ADMIN] devices 1` for both. Overlay `a 100.64.0.2`, `b 100.64.0.1`. `ping a->b`: 20/20, 0% loss, avg 0.811 ms, max 1.245 ms. The `orblx up` process has 0 `ORBLX_ENROLL_TOKEN*` variables. 0 temp token files. `resolvectl` missing: 1 line, the node continues. |
| 3. Restart with the state volume: same overlay IP, no new enroll | [C] | `a overlay before 100.64.0.2 after 100.64.0.2 enrolled_lines 1 no_enroll_lines 1`. `ping a->b after restart`: 20/20, 0% loss, avg 0.815 ms. |
| 4. SVID renew in the container, short life | [C] | `ORBLX_SVID_TTL=60`. `svid_expiry before 1793366042 after 1793366082` (+40 s), after the line `The node renewed the SVID`. Ping after renew: 20/20, 0% loss, avg 0.726 ms. |
| 5. No token, key, or PEM in the image | REAL | `docker history --no-trunc`: 6 lines, 0 hits (the two tokens, `BEGIN`, `ORBLX_ENROLL_TOKEN=`). `Config.Env` has only `PATH`. Scan: `layers 1 files 206 needles 2 hits 0`. |
| 5. Control | REAL | An image from this image with a planted fake PEM block and a planted string: `control history hit 1`, scan `hits 3` (the string in the layer and in the config, the PEM block in `etc/planted.pem`). |
| 6. CI builds the image on each PR, no push | REAL | The CI job builds the image, checks the size, checks the history, scans the image, runs the control, and runs `orblx --version`. |
| 7. W23-4 gates | [C] | See section 4. |

The scan (`image-secrets-scan.py`) reads each layer and each config blob of `docker save`.
A hit is a PEM block with a base64 body, a file with a state name (`key.pem`, `cert.pem`, `bundle.pem`, `trust-bundle.pem`, `ticket.bin`, `*.key`), or a needle value.
The `orblx` binary has PEM label strings, but no PEM body. A label alone is not a hit.

## 4. W23-4 gates

Script: `scripts/proof/nat-realism.sh` with `ORBLX_NATR_PROFILE=release`, names `orblx-w25h-natr-*`,
subnets `172.29.127.0/24` and `10.127.21.0/24` to `10.127.24.0/24`. Branch commit `75bf853` (with main `d153c70`, #80 port ACL in the data path).
Main `06e4a0b` (#85) changed the coordinator policy API and the CLI. It did not change the data path or this script.

Log: `/workspace/orblx-w18-proof/w25-h-nat-realism-75bf8530.log`. An earlier run on `05f4be2` (`w25-h-nat-realism.log`) is `proof_ok` too. Result: `proof_ok` [C].

| Check | Result |
| --- | --- |
| Direct RTT | `rtt plain_avg_ms 0.041 direct_avg_ms 0.538`, `rtt limit_ms 5 ok` |
| prc_prc relay gate | relay avg 0.804 ms, direct avg 0.538 ms, slack 1 ms, 0/50 lost, `relay_gate ok` |
| sym_sym relay gate | relay avg 0.841 ms, direct avg 0.538 ms, slack 1 ms, 0/50 lost, `relay_gate ok` |
| Switch direct to relay | prc_prc: detect 416 ms, 0/50 lost, max gap 444 ms. prc_sym: detect 1010 ms, 0/50 lost, max gap 539 ms |
| Switch relay to direct | prc_prc: detect 520 ms, 0/50 lost, max gap 209 ms. prc_sym: detect 1173 ms, 0/50 lost, max gap 208 ms |
| Throughput | prc_prc direct 1296.54 Mbit/s, prc_prc relay 1041.32 Mbit/s |
| SVID renew | direct and relay peers see the new peer expiry |

## 5. CI

The job `Docker image build, size, and secrets scan` runs on `ubuntu-latest` for each PR and each push to main. It does these steps:

1. `docker build -f docker/Dockerfile -t orblx-ci:local .`
2. It fails when the image is more than 60000000 bytes.
3. It fails when `docker history --no-trunc` has `BEGIN` or `ORBLX_ENROLL_TOKEN=`.
4. It runs `image-secrets-scan.py` on `docker save`. A hit fails the job.
5. Control: it builds an image with a planted fake PEM block. The scan must find it (`--expect-hit`).
6. It runs `orblx --version` in the image.

The job has no registry login and no `docker push`.
The `rust` job also checks the shell syntax of `docker/entrypoint.sh` and `scripts/proof/docker-image.sh`.
