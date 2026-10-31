#!/usr/bin/env bash
# Release and install proof.
# The script builds a release tarball on the REAL host, writes SHA256SUMS,
# and signs SHA256SUMS with a throwaway cosign key.
# A [C] HTTP container serves the files.
# A clean [C] container runs scripts/install.sh from the HTTP container.
# The script then changes one byte in each file and checks that the install refuses.
# The script does not print the throwaway private key.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
TARGET="x86_64-unknown-linux-gnu"
IMAGE="orblx-release-proof:w20"
NET="orblx-release-proof"
HTTP="orblx-release-http"
COSIGN_VERSION="v3.1.4"
COSIGN_SHA256="424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa"
WORK="$(mktemp -d)"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

cleanup() {
  as_root docker rm -f "$HTTP" >/dev/null 2>&1 || true
  as_root docker network rm "$NET" >/dev/null 2>&1 || true
  as_root docker image rm "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=12  # reason: the floor (PROOF_DISK_FLOOR_GIB): one build output and one proof image. No bigger measure for this proof.
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "release"

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "The proof needs a Linux x86_64 host." >&2
  exit 1
fi
echo "=== [REAL] host ==="
uname -sm

echo "=== [REAL] get cosign ${COSIGN_VERSION} ==="
if [[ -n "${COSIGN_BIN:-}" ]]; then
  cp "$COSIGN_BIN" "$WORK/cosign"
else
  curl -fsSL -o "$WORK/cosign" \
    "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
fi
echo "${COSIGN_SHA256}  $WORK/cosign" | sha256sum -c --quiet
chmod 0755 "$WORK/cosign"
echo "cosign sha256 ${COSIGN_SHA256}"
cosign() { "$WORK/cosign" "$@"; }

echo "=== [REAL] build the release binary ==="
cargo build --release --locked -p orblx-cli --bin orblx
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)"
echo "version ${version}"

echo "=== [REAL] package, checksum, and sign ==="
good="$WORK/www/good"
mkdir -p "$good" "$WORK/keys"
scripts/release/package.sh "$version" "$TARGET" "$TARGET_DIR/release/orblx" "$good"
(cd "$good" && sha256sum orblx-*.tar.gz > SHA256SUMS && cat SHA256SUMS)
# Throwaway keys. The keys are in WORK only. The cleanup removes them.
(cd "$WORK/keys" && COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix test >/dev/null 2>&1)
(cd "$WORK/keys" && COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix other >/dev/null 2>&1)
chmod 0644 "$WORK/keys/test.pub"
sign() {
  COSIGN_PASSWORD="" cosign sign-blob --yes --key "$1" --tlog-upload=false \
    --use-signing-config=false --bundle "$2/SHA256SUMS.sigstore.json" "$2/SHA256SUMS" >/dev/null 2>&1
}
sign "$WORK/keys/test.key" "$good"
cp "$ROOT/scripts/install.sh" "$good/install.sh"
echo "test_public_key_sha256 $(sha256sum "$WORK/keys/test.pub" | cut -d' ' -f1)"
(cd "$good" && stat -c '%s %n' -- *)

# flip_byte FILE OFFSET: change one byte with XOR 0x01.
flip_byte() {
  python3 - "$1" "$2" <<'PY'
import sys
path, offset = sys.argv[1], int(sys.argv[2])
data = bytearray(open(path, "rb").read())
data[offset] ^= 0x01
open(path, "wb").write(data)
print(f"changed byte {offset} of {path.rsplit('/', 1)[-1]}")
PY
}

echo "=== [REAL] make the changed copies ==="
tar_size="$(stat -c %s "$good/orblx-${TARGET}.tar.gz")"
cp -r "$good" "$WORK/www/bad-tarball"
flip_byte "$WORK/www/bad-tarball/orblx-${TARGET}.tar.gz" "$((tar_size / 2))"
cp -r "$good" "$WORK/www/bad-sums"
flip_byte "$WORK/www/bad-sums/SHA256SUMS" 0
cp -r "$good" "$WORK/www/bad-signer"
sign "$WORK/keys/other.key" "$WORK/www/bad-signer"
echo "bad-signer: SHA256SUMS is signed with a different throwaway key"
chmod -R a+rX "$WORK/www"

echo "=== [C] build the clean client image ==="
mkdir -p "$WORK/img"
cp "$WORK/cosign" "$WORK/img/cosign"
cat > "$WORK/img/Dockerfile" <<'DOCKER'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*
COPY cosign /usr/local/bin/cosign
DOCKER
as_root docker build -q -t "$IMAGE" "$WORK/img" >/dev/null
as_root docker run --rm "$IMAGE" sh -c 'test ! -e /usr/local/bin/orblx && echo "client has no orblx"'

echo "=== [C] start the HTTP container ==="
as_root docker rm -f "$HTTP" >/dev/null 2>&1 || true
as_root docker network rm "$NET" >/dev/null 2>&1 || true
as_root docker network create "$NET" >/dev/null
as_root docker run -d --name "$HTTP" --network "$NET" -v "$WORK/www:/srv:ro" "$IMAGE" \
  python3 -m http.server 8000 --directory /srv >/dev/null
for _ in $(seq 1 30); do
  if as_root docker run --rm --network "$NET" "$IMAGE" curl -fsS -o /dev/null "http://${HTTP}:8000/good/SHA256SUMS" 2>/dev/null; then
    break
  fi
  sleep 1
done

client() {
  as_root docker run --rm --network "$NET" -v "$WORK/keys/test.pub:/keys/cosign.pub:ro" "$IMAGE" sh -c "$1"
}

echo "=== [C] install from good with curl | sh ==="
client "curl -fsSL http://${HTTP}:8000/good/install.sh | sh -s -- --base-url http://${HTTP}:8000/good --cosign-key /keys/cosign.pub --service \
  && ls -l /usr/local/bin/orblx | awk '{print \$1, \$NF}' \
  && ls -l /etc/systemd/system/orblxd.service | awk '{print \$1, \$NF}' \
  && /usr/local/bin/orblx --version"

expect_refuse() {
  local dir="$1" needle="$2" out status
  echo "=== [C] install from ${dir} must fail ==="
  set +e
  out="$(client "sh -c 'curl -fsSL http://${HTTP}:8000/good/install.sh | sh -s -- --base-url http://${HTTP}:8000/${dir} --cosign-key /keys/cosign.pub'; rc=\$?; if [ -e /usr/local/bin/orblx ]; then echo installed_after_failure; exit 99; fi; echo install_exit \$rc; exit \$rc" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$out"
  if [[ "$status" -eq 0 || "$status" -eq 99 ]]; then
    echo "The install did not refuse ${dir}." >&2
    exit 1
  fi
  printf '%s\n' "$out" | read_all grep -qF -- "$needle"
  printf '%s\n' "$out" | read_all grep -q '^install_exit [1-9]'
}

expect_refuse bad-tarball "The checksum of orblx-${TARGET}.tar.gz is not correct."
expect_refuse bad-sums "The signature check of SHA256SUMS failed."
expect_refuse bad-signer "The signature check of SHA256SUMS failed."

echo "=== [C] install without cosign must fail ==="
set +e
out="$(as_root docker run --rm --network "$NET" "$IMAGE" sh -c "rm /usr/local/bin/cosign; curl -fsSL http://${HTTP}:8000/good/install.sh | sh -s -- --base-url http://${HTTP}:8000/good; rc=\$?; test ! -e /usr/local/bin/orblx || exit 99; exit \$rc" 2>&1)"
status=$?
set -e
printf '%s\n' "$out"
if [[ "$status" -eq 0 || "$status" -eq 99 ]]; then
  echo "The install did not refuse without cosign." >&2
  exit 1
fi
printf '%s\n' "$out" | read_all grep -q 'cosign is not installed'

echo "=== [REAL] no private key text in the served files ==="
if grep -rq 'PRIVATE KEY' "$WORK/www"; then
  echo "A served file contains a private key." >&2
  exit 1
fi
echo "private_key_in_www none"

echo "proof_ok"
