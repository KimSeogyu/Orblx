#!/usr/bin/env bash
# Receiver ACL proof for the coordinator and two node containers.
# The script deletes the orblx-policy-proof volumes at the start.
# The script does not print enroll tokens or private keys.
# The Mac steps stay in docs/w18-policy.md. This script does not run them.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.policy.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "policy"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-policy-proof" || exit 1

dc() {
  docker compose --progress quiet -f "$FILE" "$@"
}

resolve_coord() {
  dc --profile nodes run --rm --no-deps --entrypoint getent mac ahostsv4 coord \
    | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

# Docker on this host can leave iptables-legacy FORWARD policy DROP.
# That policy drops UDP on a user-defined bridge.
# iptables-nft already accepts the same traffic.
as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
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

cp "$ROOT/scripts/proof/policy.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build coordinator image ==="
build_image

echo "=== [C] start coordinator ==="
dc up -d coord
wait_bundle

echo "=== [C] policy test ==="
dc exec -T coord orblx policy test --file /var/lib/orblx/policy.hujson

echo "=== [C] token box ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/box
echo "=== [C] token mac ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 --out /var/lib/orblx/tokens/mac

echo "=== [C] coordinator address ==="
coord_ip="$(resolve_coord)"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"

echo "=== [C] enroll box ==="
box_enroll="$(dc --profile nodes run --rm box \
  coord enroll \
  --name box \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/box \
  --state /var/lib/orblx \
  --endpoint box:443)"
printf '%s\n' "$box_enroll"
box_ip="$(printf '%s\n' "$box_enroll" | read_all awk '/^overlay_ip /{print $2; exit}')"
if [[ -z "$box_ip" ]]; then
  echo "The box overlay address is missing." >&2
  exit 1
fi

echo "=== [C] enroll mac ==="
dc --profile nodes run --rm mac \
  coord enroll \
  --name mac \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/mac \
  --state /var/lib/orblx \
  --endpoint mac:443

echo "=== [C] netmap on box ==="
dc --profile nodes run --rm box \
  coord netmap \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --state /var/lib/orblx

echo "=== [C] grants on box ==="
grants_before="$(dc --profile nodes run --rm --entrypoint cat box /var/lib/orblx/grants.json)"
printf '%s\n' "$grants_before"
printf '%s\n' "$grants_before" | read_all grep -q 'spiffe://orblx.local/node/mac'
printf '%s\n' "$grants_before" | read_all grep -q '"port_start":22'
if printf '%s\n' "$grants_before" | read_all grep -q '5432'; then
  echo "The grants allow TCP 5432." >&2
  exit 1
fi

echo "=== [C] enforce on box ==="
dc --profile nodes run --rm box \
  policy enforce \
  --state /var/lib/orblx \
  --src mac \
  --dst-ip "$box_ip" \
  --port 22 \
  --port 5432 \
  --audit /var/lib/orblx/audit.jsonl

echo "=== [C] audit verify ==="
verify="$(dc --profile nodes run --rm box audit verify --file /var/lib/orblx/audit.jsonl)"
printf '%s\n' "$verify"
printf '%s\n' "$verify" | read_all grep -qx 'deny 1'
printf '%s\n' "$verify" | read_all grep -qx 'ok'

echo "=== [C] failing policy ==="
cat >"$POLICY_FILE" <<'EOF'
{
  "groups": { "group:humans": ["spiffe://orblx.local/node/mac"] },
  "tags": { "tag:box": ["spiffe://orblx.local/node/box"] },
  "tagOwners": { "tag:box": ["group:humans"] },
  "acls": [
    {
      "action": "accept",
      "src": ["group:humans"],
      "proto": "tcp",
      "dst": ["tag:box:22"]
    }
  ],
  "tests": [
    {
      "src": "spiffe://orblx.local/node/mac",
      "proto": "tcp",
      "accept": ["spiffe://orblx.local/node/box:5432"]
    }
  ]
}
EOF
if dc exec -T coord orblx policy check --file /var/lib/orblx/policy.hujson; then
  echo "A failing policy loaded." >&2
  exit 1
fi
dc --profile nodes run --rm box \
  coord netmap \
  --coord "${coord_ip}:443" \
  --bundle /coord-state/trust-bundle.pem \
  --state /var/lib/orblx >/dev/null
grants_after="$(dc --profile nodes run --rm --entrypoint cat box /var/lib/orblx/grants.json)"
if [[ "$grants_before" != "$grants_after" ]]; then
  echo "The failing policy replaced the grants." >&2
  exit 1
fi
fail_count="$(dc logs coord | grep -c 'policy load failed:' || true)"
if [[ "$fail_count" != "1" ]]; then
  echo "The coordinator logged ${fail_count} policy errors." >&2
  dc logs coord >&2 || true
  exit 1
fi
echo "failing_policy kept_grants"
echo "policy_errors 1"

echo "proof_ok"
