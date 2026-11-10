#!/usr/bin/env bash
# Install one-liner end-to-end test.
#
# The script serves the release files from a local HTTP server on the host.
# A clean Ubuntu 24.04 container runs the install one-liner from that server.
# The container does not use a public GitHub release.
# The container then runs orblx up, orblx status, and orblx down.
# The container has NET_ADMIN and /dev/net/tun.
# orblx up opens a TUN device. This test does not use the sim harness.
# The script does not print a key.
#
# Usage:
#   scripts/release/install-e2e.sh
#   scripts/release/install-e2e.sh --artifacts DIR
#
# With --artifacts, DIR holds orblx-x86_64-unknown-linux-gnu.tar.gz.
# With no --artifacts, the script builds that tarball on this host.
set -euo pipefail

# Poll 20 s after kill. Then send SIGKILL and print the fail reason.
reap_bound() {
  local pid="$1"
  local reason="$2"
  local i
  for ((i = 0; i < 200; i++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      return 0
    fi
    sleep 0.1
  done
  echo "fail_reason ${reason}" >&2
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 0
}
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../proof/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
TARGET="x86_64-unknown-linux-gnu"
COSIGN_VERSION="v3.1.4"
COSIGN_SHA256="424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa"
IMAGE="orblx-install-e2e:local"
NET="orblx-install-e2e"
HTTP_PORT="18080"
artifacts=""
http_pid=""

usage() {
  echo "Usage: $0 [--artifacts DIR]" >&2
  exit 2
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --artifacts)
      [[ "$#" -ge 2 ]] || usage
      artifacts="$2"
      shift 2
      ;;
    -h | --help) usage ;;
    *) usage ;;
  esac
done

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

WORK="$(mktemp -d)"
cleanup() {
  if [[ -n "${http_pid}" ]]; then
    kill "$http_pid" >/dev/null 2>&1 || true
    reap_bound "$http_pid" install_e2e_http_pid
  fi
  as_root docker network rm "$NET" >/dev/null 2>&1 || true
  as_root docker image rm "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "The test needs a Linux x86_64 host." >&2
  exit 1
fi
if [[ ! -e /dev/net/tun ]]; then
  echo "The host has no /dev/net/tun. orblx up cannot open a TUN device." >&2
  exit 1
fi

version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)"
echo "version ${version}"
good="$WORK/www"
mkdir -p "$good" "$WORK/keys"

tarball="orblx-${TARGET}.tar.gz"
if [[ -n "$artifacts" ]]; then
  if [[ ! -f "${artifacts}/${tarball}" ]]; then
    echo "The directory ${artifacts} has no ${tarball}." >&2
    exit 1
  fi
  cp "${artifacts}/${tarball}" "${good}/${tarball}"
  echo "artifact ${artifacts}/${tarball}"
else
  echo "=== build the release binary ==="
  cargo build --release --locked -p orblx-cli --bin orblx
  bin="${CARGO_TARGET_DIR:-$ROOT/target}/release/orblx"
  scripts/release/package.sh "$version" "$TARGET" "$bin" "$good"
fi

(
  cd "$good"
  sha256sum "$tarball" > SHA256SUMS
  cat SHA256SUMS
)
cp "$ROOT/scripts/install.sh" "$good/install.sh"

echo "=== get cosign ${COSIGN_VERSION} ==="
if [[ -n "${COSIGN_BIN:-}" ]]; then
  cp "$COSIGN_BIN" "$WORK/cosign"
else
  curl -fsSL -o "$WORK/cosign" \
    "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
fi
echo "${COSIGN_SHA256}  $WORK/cosign" | sha256sum -c --quiet
chmod 0755 "$WORK/cosign"
cosign() { "$WORK/cosign" "$@"; }

# Throwaway keys. The keys stay in WORK. The cleanup removes them.
# The script does not print the private key.
(cd "$WORK/keys" && COSIGN_PASSWORD="" cosign generate-key-pair --output-key-prefix test >/dev/null 2>&1)
chmod 0644 "$WORK/keys/test.pub"
COSIGN_PASSWORD="" cosign sign-blob --yes --key "$WORK/keys/test.key" --tlog-upload=false \
  --use-signing-config=false --bundle "$good/SHA256SUMS.sigstore.json" "$good/SHA256SUMS" >/dev/null 2>&1 \
  || { echo "The signature step failed. The script installed nothing." >&2; exit 1; }
if grep -q 'PRIVATE KEY' "$good/SHA256SUMS" "$good/SHA256SUMS.sigstore.json" "$good/install.sh"; then
  echo "A served file has a private key marker. The script stops." >&2
  exit 1
fi
chmod -R a+rX "$WORK/www"

echo "=== build the clean client image ==="
mkdir -p "$WORK/img"
cp "$WORK/cosign" "$WORK/img/cosign"
cat > "$WORK/img/Dockerfile" <<'DOCKER'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
COPY cosign /usr/local/bin/cosign
DOCKER
as_root docker build -q -t "$IMAGE" "$WORK/img" >/dev/null
as_root docker run --rm "$IMAGE" sh -c 'test ! -e /usr/local/bin/orblx && echo "client has no orblx"'

tag_version="v${version}"
cat > "$WORK/client.sh" <<'CLIENT'
#!/bin/sh
# Run inside the clean container. Do not print a key.
set -eu
base="${ORBLX_E2E_BASE:?}"
version="${ORBLX_E2E_VERSION:?}"
echo "=== install one-liner ==="
curl -fsSL "${base}/install.sh" | sh -s -- \
  --base-url "$base" \
  --cosign-key /keys/cosign.pub \
  --version "$version"
/usr/local/bin/orblx --version

state=/var/lib/orblx-e2e
/usr/local/bin/orblx node-issue --out "$state" --node a=100.64.0.1
cat > "$state/a/netmap.json" <<'EOF'
{
  "version": 1,
  "self": {"name": "a", "overlay_ip": "100.64.0.1"},
  "peers": []
}
EOF

echo "=== orblx up ==="
/usr/local/bin/orblx up \
  --netmap "$state/a/netmap.json" \
  --state-dir "$state/a" \
  --listen 127.0.0.1:51820 >/tmp/orblx-up.log 2>&1 &
up_pid=$!

ok=0
i=0
while [ "$i" -lt 40 ]; do
  if /usr/local/bin/orblx status --state-dir "$state/a" > /tmp/status-up.txt 2>/tmp/status-up.err; then
    if grep -q '^state up$' /tmp/status-up.txt; then
      ok=1
      break
    fi
  fi
  if ! kill -0 "$up_pid" 2>/dev/null; then
    echo "orblx up stopped before status showed state up." >&2
    cat /tmp/orblx-up.log >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 1
done
if [ "$ok" -ne 1 ]; then
  echo "orblx status did not show state up." >&2
  cat /tmp/status-up.txt /tmp/status-up.err /tmp/orblx-up.log >&2 || true
  exit 1
fi
echo "=== orblx status (up) ==="
cat /tmp/status-up.txt
grep -q '^name a$' /tmp/status-up.txt
grep -q '^overlay_ip 100.64.0.1$' /tmp/status-up.txt
echo "status_up_exit 0"

echo "=== orblx down ==="
/usr/local/bin/orblx down --state-dir "$state/a" > /tmp/down.txt
cat /tmp/down.txt
grep -q 'The node is down.' /tmp/down.txt
echo "down_exit 0"

/usr/local/bin/orblx status --state-dir "$state/a" > /tmp/status-down.txt
echo "=== orblx status (down) ==="
cat /tmp/status-down.txt
grep -q '^state down$' /tmp/status-down.txt
echo "status_down_exit 0"
wait "$up_pid" || true
echo install_e2e_ok
CLIENT
chmod 0755 "$WORK/client.sh"

echo "=== start the local artifact server ==="
as_root docker network rm "$NET" >/dev/null 2>&1 || true
as_root docker network create "$NET" >/dev/null
gateway="$(as_root docker network inspect "$NET" --format '{{(index .IPAM.Config 0).Gateway}}')"
if [[ -z "$gateway" ]]; then
  echo "The Docker network has no gateway." >&2
  exit 1
fi
# The server runs on the host. The container uses the network gateway.
# Container-to-container forwarding is not required.
python3 -m http.server "$HTTP_PORT" --bind "$gateway" --directory "$good" >"$WORK/http.log" 2>&1 &
http_pid=$!
base_url="http://${gateway}:${HTTP_PORT}"
ready=0
for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 -o /dev/null "${base_url}/SHA256SUMS" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" -ne 1 ]]; then
  echo "The artifact server did not start." >&2
  exit 1
fi
echo "artifact_server ${base_url}"

echo "=== run up, status, and down in the clean container ==="
as_root docker run --rm \
  --network "$NET" \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  --sysctl net.ipv4.conf.all.rp_filter=0 \
  --sysctl net.ipv4.conf.default.rp_filter=0 \
  -v "$WORK/keys/test.pub:/keys/cosign.pub:ro" \
  -v "$WORK/client.sh:/client.sh:ro" \
  -e "ORBLX_E2E_BASE=${base_url}" \
  -e "ORBLX_E2E_VERSION=${tag_version}" \
  "$IMAGE" \
  /bin/sh /client.sh
