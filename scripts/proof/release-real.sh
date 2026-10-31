#!/usr/bin/env bash
# Real release asset proof.
# A clean [C] container runs the install.sh asset of a real GitHub release.
# install.sh gets the real release assets from github.com and checks the keyless
# cosign signature and the checksum.
# The container then checks the signature again with the exact certificate identity
# and prints the identity and the issuer from the Fulcio certificate.
# The script then gets the real assets on the REAL host, changes one byte in the tarball,
# and serves the changed copy from a [C] mirror container. The install must refuse it.
# The release has no private key. The script prints no token and no key.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TAG="${RELEASE_TAG:-v0.1.0-rc.2}"
REPO="KimSeogyu/Orblx"
TARGET="x86_64-unknown-linux-gnu"
TARBALL="orblx-${TARGET}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
ISSUER="https://token.actions.githubusercontent.com"
IMAGE="orblx-release-real-proof:w20"
MIRROR="orblx-release-mirror"
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
  as_root docker rm -f "$MIRROR" >/dev/null 2>&1 || true
  as_root docker image rm "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "release-real"

case "$TAG" in
  v[0-9]*) ;;
  *) echo "RELEASE_TAG must be a tag such as v0.1.0-rc.1." >&2; exit 1 ;;
esac
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "The proof needs a Linux x86_64 host." >&2
  exit 1
fi
echo "=== [REAL] host ==="
uname -sm
echo "tag ${TAG}"
echo "release ${BASE}"

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

echo "=== [C] build the clean client image ==="
mkdir -p "$WORK/img"
cp "$WORK/cosign" "$WORK/img/cosign"
cat > "$WORK/img/Dockerfile" <<'DOCKER'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates python3 openssl \
    && rm -rf /var/lib/apt/lists/*
COPY cosign /usr/local/bin/cosign
DOCKER
as_root docker build -q -t "$IMAGE" "$WORK/img" >/dev/null
as_root docker run --rm "$IMAGE" sh -c 'test ! -e /usr/local/bin/orblx && echo "client has no orblx"'

client() {
  # The containers use the default bridge, because it has egress to github.com and to the Sigstore TUF root.
  as_root docker run --rm -e TAG="$TAG" -e BASE="$BASE" \
    -e IDENTITY="$IDENTITY" -e ISSUER="$ISSUER" -e TARBALL="$TARBALL" "$IMAGE" sh -c "$1"
}

echo "=== [C] install from the real release with curl | sh ==="
client '
set -e
curl -fsSL -o /tmp/install.sh "$BASE/install.sh"
curl -fsSL "$BASE/install.sh" | sh -s -- --version "$TAG"
test -x /usr/local/bin/orblx
ls -l /usr/local/bin/orblx | awk "{print \$1, \$NF}"
echo "--- orblx --version"
/usr/local/bin/orblx --version
echo "--- cosign verify-blob with the exact identity"
mkdir /check && cd /check
for f in SHA256SUMS SHA256SUMS.sigstore.json "$TARBALL"; do curl -fsSL -o "$f" "$BASE/$f"; done
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER" SHA256SUMS
echo "verified_identity $IDENTITY"
echo "verified_issuer $ISSUER"
sha256sum --ignore-missing -c SHA256SUMS
echo "--- the Fulcio certificate in the bundle"
python3 - <<PY
import base64, json
b = json.load(open("SHA256SUMS.sigstore.json"))
m = b["verificationMaterial"]
c = m.get("certificate", {}).get("rawBytes") or m["x509CertificateChain"]["certificates"][0]["rawBytes"]
open("cert.der", "wb").write(base64.b64decode(c))
print("bundle_media_type", b.get("mediaType"))
print("tlog_entries", len(m.get("tlogEntries", [])))
PY
openssl x509 -inform DER -in cert.der -noout -issuer
openssl x509 -inform DER -in cert.der -noout -ext subjectAltName | sed -n "2p" | sed "s/^ *//"
openssl x509 -inform DER -in cert.der -noout -text \
  | grep -A1 -E "1\.3\.6\.1\.4\.1\.57264\.1\.(1|8|9|12|14):" | grep -v "^--" | sed "s/^ *//"
'

echo "=== [REAL] get the real assets and change one byte in the tarball ==="
mkdir -p "$WORK/www"
for f in "$TARBALL" SHA256SUMS SHA256SUMS.sigstore.json install.sh; do
  curl -fsSL -o "$WORK/www/$f" "$BASE/$f"
done
(cd "$WORK/www" && sha256sum --ignore-missing -c SHA256SUMS)
size="$(stat -c %s "$WORK/www/$TARBALL")"
python3 - "$WORK/www/$TARBALL" "$((size / 2))" <<'PY'
import sys
path, offset = sys.argv[1], int(sys.argv[2])
data = bytearray(open(path, "rb").read())
data[offset] ^= 0x01
open(path, "wb").write(data)
print(f"changed byte {offset} of {path.rsplit('/', 1)[-1]}")
PY
(cd "$WORK/www" && sha256sum "$TARBALL")
chmod -R a+rX "$WORK/www"

echo "=== [C] start the mirror container with the changed tarball ==="
as_root docker rm -f "$MIRROR" >/dev/null 2>&1 || true
as_root docker run -d --name "$MIRROR" -v "$WORK/www:/srv:ro" "$IMAGE" \
  python3 -m http.server 8000 --directory /srv >/dev/null
mirror_ip="$(as_root docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$MIRROR")"
[[ -n "$mirror_ip" ]] || { echo "The mirror container has no IP address." >&2; exit 1; }
echo "mirror http://${mirror_ip}:8000 (${MIRROR})"
for _ in $(seq 1 30); do
  if client "curl -fsS -o /dev/null http://${mirror_ip}:8000/SHA256SUMS" 2>/dev/null; then
    break
  fi
  sleep 1
done

echo "=== [C] install from the changed mirror must fail ==="
set +e
out="$(client "curl -fsSL -o /tmp/install.sh \"\$BASE/install.sh\" || exit 98; sh /tmp/install.sh --version \"\$TAG\" --base-url http://${mirror_ip}:8000; rc=\$?; if [ -e /usr/local/bin/orblx ]; then echo installed_after_failure; exit 99; fi; echo orblx_absent; echo install_exit \$rc; exit \$rc" 2>&1)"
status=$?
set -e
printf '%s\n' "$out"
if [[ "$status" -eq 0 || "$status" -eq 98 || "$status" -eq 99 ]]; then
  echo "The install did not refuse the changed tarball." >&2
  exit 1
fi
printf '%s\n' "$out" | read_all grep -q '^signature ok\|signature ok$'
printf '%s\n' "$out" | read_all grep -qF "The checksum of ${TARBALL} is not correct. The script installed nothing."
printf '%s\n' "$out" | read_all grep -q '^install_exit [1-9]'

echo "proof_ok"
