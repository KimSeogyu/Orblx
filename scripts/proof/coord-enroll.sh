#!/usr/bin/env bash
# Token enrollment proof for the coordinator container.
# The script deletes the orblx-coord-proof volumes at the start.
# The script does not print enroll tokens or private keys.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
# W25-14: this proof needs root. It stops at once without root.
require_root "$@"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.coord.yml"
UP_NAME="orblx-coord-proof-up"

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
}

# W25-14b: on each exit, remove every proof container, so no container keeps port 443.
cleanup() {
  docker rm -f "$UP_NAME" >/dev/null 2>&1 || true
  dc --profile nodes down -v --remove-orphans >/dev/null 2>&1 || true
}
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "coord-enroll" "orblx-coord-proof-"
# The test hook ORBLX_COORD_ENROLL_FAIL_AT=start makes the proof fail on purpose after it
# starts the coordinator. The cleanup test uses it.

resolve_coord() {
  dc --profile nodes run --rm --no-deps --entrypoint getent node-a ahostsv4 coord \
    | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
# That policy drops UDP on a user-defined bridge.
# iptables-nft already accepts the same traffic.
open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  if [[ "$(id -u)" -eq 0 ]]; then
    iptables-legacy -P FORWARD ACCEPT
  else
    sudo -n iptables-legacy -P FORWARD ACCEPT
  fi
}

build_image() {
  local image_dir bin
  bin="$ROOT/target/debug/orblx"
  cargo build -p orblx-cli --bin orblx
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -t orblx-coord:w18 "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord cat /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  dc logs coord >&2 || true
  return 1
}

echo "=== [C] remove old proof volumes ==="
# W25-14b: "--profile nodes" is needed. Without it, "down -v" keeps the node-a and node-b
# volumes, so an old ticket.bin from an earlier run stays in the node state.
cleanup
for vol in orblx-coord-proof_orblx-coord-store orblx-coord-proof_orblx-node-a orblx-coord-proof_orblx-node-b; do
  if docker volume inspect "$vol" >/dev/null 2>&1; then
    echo "The old proof volume ${vol} is still there." >&2
    exit 1
  fi
done
open_legacy_forward

echo "=== [C] build coordinator image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
if [[ "${ORBLX_COORD_ENROLL_FAIL_AT:-}" == start ]]; then
  echo "proof_fail: the test hook ORBLX_COORD_ENROLL_FAIL_AT=start stops the proof." >&2
  exit 1
fi
wait_bundle

echo "=== [C] token server-a ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/server-a
echo "=== [C] token server-b ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/server-b

if dc exec -T coord cat /var/lib/orblx/nodes.json | read_all grep -q 'ge1\.'; then
  echo "The node store contains an enroll token." >&2
  exit 1
fi
if dc exec -T coord cat /var/lib/orblx/nodes.json | read_all grep -q 'PRIVATE KEY'; then
  echo "The node store contains a private key." >&2
  exit 1
fi

echo "=== [C] coordinator address ==="
coord_ip="$(resolve_coord)"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"

echo "=== [C] enroll server-a ==="
dc --profile nodes run --rm node-a \
  coord enroll \
  --name server-a \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/server-a \
  --state /var/lib/orblx \
  --endpoint server-a:443

echo "=== [C] enroll server-b ==="
dc --profile nodes run --rm node-b \
  coord enroll \
  --name server-b \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/server-b \
  --state /var/lib/orblx \
  --endpoint server-b:443

echo "=== [C] netmap before restart ==="
before="$(dc --profile nodes run --rm node-a coord netmap --coord ${coord_ip}:443 --bundle /coord-state/trust-bundle.pem --state /var/lib/orblx)"
printf '%s\n' "$before"

echo "=== [C] restart coordinator ==="
dc restart coord
wait_bundle
sleep 1

echo "=== [C] netmap after restart ==="
after="$(dc --profile nodes run --rm node-a coord netmap --coord ${coord_ip}:443 --bundle /coord-state/trust-bundle.pem --state /var/lib/orblx)"
printf '%s\n' "$after"

ip_before="$(printf '%s\n' "$before" | read_all awk '/^overlay_ip /{print $2; exit}')"
ip_after="$(printf '%s\n' "$after" | read_all awk '/^overlay_ip /{print $2; exit}')"
peer_before="$(printf '%s\n' "$before" | awk '/^peer /{print $2, $3}')"
peer_after="$(printf '%s\n' "$after" | awk '/^peer /{print $2, $3}')"
if [[ "$ip_before" != "$ip_after" || -z "$ip_before" || "$peer_before" != "$peer_after" ]]; then
  echo "The overlay addresses changed." >&2
  exit 1
fi
echo "same_ip server-a ${ip_before}"
echo "same_peer ${peer_before}"

echo "=== [C] reuse token server-a ==="
set +e
reuse="$(dc --profile nodes run --rm node-a coord enroll --name server-c --coord ${coord_ip}:443 --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/server-a --state /tmp/reuse --endpoint server-c:443 2>&1)"
code=$?
set -e
printf '%s\n' "$reuse"
if [[ "$code" -eq 0 ]]; then
  echo "The reused enroll token was accepted." >&2
  exit 1
fi
if ! printf '%s\n' "$reuse" | read_all grep -q 'already used'; then
  echo "The rejection text is missing." >&2
  exit 1
fi
echo "reused_token rejected"

echo "=== [C] netmap json ==="
dc --profile nodes run --rm --entrypoint cat node-a /var/lib/orblx/netmap.json
echo

# W25-14b: since #41 (0c54129) enroll writes ticket.bin, so "orblx up" gets past the ticket
# and opens the TUN device. The node-a container has no TUN device. The proof now runs
# "up" two times on the same state:
#   1. node-a (no TUN device): up must exit non-zero with the TUN message, print no ready
#      line, and change no state file.
#   2. node-a-tun (TUN device, NET_ADMIN): up must accept the netmap and open the TUN
#      device, with no new enroll token.
# A changed netmap must make up stop with 'The netmap is not valid' before the TUN step.
state_sums() {
  dc --profile nodes run --rm --entrypoint sh node-a -c \
    'cd /var/lib/orblx && find . -type f | sort | xargs sha256sum'
}
self_ip="$(dc --profile nodes run --rm --entrypoint cat node-a /var/lib/orblx/netmap.json | jq -r '.self.overlay_ip')"
[[ "$self_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "The netmap has no self overlay IP." >&2; exit 1; }

echo "=== [C] orblx up reads netmap.json (no TUN device) ==="
sums_before="$(state_sums)"
set +e
up_out="$(dc --profile nodes run --rm node-a up --state-dir /var/lib/orblx 2>&1)"
up_code=$?
set -e
printf '%s\n' "$up_out"
if [[ "$up_code" -eq 0 ]]; then
  echo "orblx up reported success without a TUN device." >&2
  exit 1
fi
if printf '%s\n' "$up_out" | read_all grep -q 'The netmap is not valid'; then
  echo "orblx up rejected the coordinator netmap." >&2
  exit 1
fi
if ! printf '%s\n' "$up_out" | read_all grep -q 'The TUN device did not open'; then
  echo "orblx up did not stop with the TUN message." >&2
  exit 1
fi
if printf '%s\n' "$up_out" | read_all grep -q '^The TUN device is '; then
  echo "orblx up reported a TUN device that did not open." >&2
  exit 1
fi
sums_after="$(state_sums)"
if [[ "$sums_before" != "$sums_after" ]]; then
  echo "orblx up changed the node state when the TUN device did not open." >&2
  diff <(printf '%s\n' "$sums_before") <(printf '%s\n' "$sums_after") >&2 || true
  exit 1
fi
echo "up_without_tun exit ${up_code} state_files $(printf '%s\n' "$sums_after" | wc -l) unchanged"

echo "=== [C] negative: orblx up with a changed netmap ==="
set +e
bad_out="$(timeout 120 docker compose --progress quiet -f "$FILE" --profile nodes run --rm --entrypoint sh node-a-tun -c \
  'rm -rf /tmp/bad && cp -a /var/lib/orblx /tmp/bad && printf "{\"version\":1,\"self\":" > /tmp/bad/netmap.json && exec orblx up --state-dir /tmp/bad' 2>&1)"
bad_code=$?
set -e
printf '%s\n' "$bad_out"
if [[ "$bad_code" -eq 0 || "$bad_code" -eq 124 ]]; then
  echo "orblx up did not stop on a changed netmap (exit ${bad_code})." >&2
  exit 1
fi
if ! printf '%s\n' "$bad_out" | read_all grep -q 'The netmap is not valid'; then
  echo "orblx up did not reject the changed netmap." >&2
  exit 1
fi
if printf '%s\n' "$bad_out" | read_all grep -q '^The TUN device is '; then
  echo "orblx up opened the TUN device with a changed netmap." >&2
  exit 1
fi
echo "bad_netmap rejected exit ${bad_code}"

echo "=== [C] orblx up reads netmap.json (TUN device, same state, no new enroll token) ==="
dc --profile nodes run -d --name "$UP_NAME" node-a-tun up --state-dir /var/lib/orblx >/dev/null
# The awk reader stops at the ready line. The result comes from the awk output only.
# pipe-ok: the ready line in the awk output decides, not the pipe status.
ready_out="$( { timeout 120 docker logs -f "$UP_NAME" 2>&1 || true; } \
  | awk '{print} /^The TUN device is /{found = 1; exit} END {exit !found}' )" || true
printf '%s\n' "$ready_out"
if printf '%s\n' "$ready_out" | read_all grep -q 'The netmap is not valid'; then
  echo "orblx up rejected the coordinator netmap." >&2
  exit 1
fi
if ! printf '%s\n' "$ready_out" | read_all grep -qx "The overlay IP is ${self_ip}."; then
  echo "orblx up did not accept the netmap." >&2
  exit 1
fi
if ! printf '%s\n' "$ready_out" | read_all grep -q '^The TUN device is '; then
  echo "orblx up did not accept the netmap." >&2
  exit 1
fi
[[ "$(docker inspect -f '{{.State.Running}}' "$UP_NAME")" == true ]] || { echo "orblx up stopped after the ready line." >&2; exit 1; }
docker rm -f "$UP_NAME" >/dev/null
echo "orblx_up_read_netmap true"
echo
echo "proof_ok"
