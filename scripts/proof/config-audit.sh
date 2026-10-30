#!/usr/bin/env bash
# Config audit proof.
# The script makes each control-plane change, prints the audit records,
# checks the chain, changes one byte, and checks that the chain check fails.
# The script deletes the orblx-audit-proof volumes at the start and at the end.
# The script does not print enroll tokens or private keys.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.audit.yml"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

dc() {
  docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

resolve_name() {
  local name="$1"
  dc run --rm --no-deps --entrypoint getent a ahostsv4 "$name" \
    | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

build_image() {
  local image_dir bin
  bin="${CARGO_TARGET_DIR:-$ROOT/target}/debug/orblx"
  cargo build -p orblx-cli --bin orblx --locked
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -q -t orblx-audit:w20 "$image_dir"
  rm -rf "$image_dir"
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  dc logs coord >&2 || true
  return 1
}

run_node() {
  local service="$1"
  shift
  dc run --rm --no-deps --entrypoint orblx "$service" "$@"
}

admin() {
  run_node owner admin "$@" \
    --coord "${coord_ip}:443" \
    --state /var/lib/orblx \
    --bundle /var/lib/orblx/bundle.pem
}

enroll_node() {
  local name="$1"
  echo "=== [C] enroll ${name} ==="
  run_node "$name" \
    coord enroll \
    --name "$name" \
    --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state /var/lib/orblx \
    --endpoint "${name}:443"
}

advertise_b() {
  run_node b coord advertise \
    --coord "${coord_ip}:443" \
    --bundle /var/lib/orblx/bundle.pem \
    --state /var/lib/orblx \
    "$@"
}

expect_action() {
  local text="$1"
  local action="$2"
  local actor="$3"
  if ! printf '%s\n' "$text" | grep -E "^record [0-9]+ [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z ${action} .* actor ${actor} before [0-9a-f]{16} after [0-9a-f]{16}" >/dev/null; then
    echo "The audit has no ${action} record for ${actor}." >&2
    exit 1
  fi
}

cp "$ROOT/scripts/proof/audit.hujson" "$POLICY_FILE"

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true

echo "=== [C] build coordinator image ==="
build_image

echo "=== [C] start coordinator ==="
start_unix="$(date -u +%s)"
dc up -d coord
wait_bundle

for name in owner a b; do
  echo "=== [C] token ${name} ==="
  dc exec -T coord orblx coord token create \
    --state /var/lib/orblx \
    --ttl 3600 \
    --out "/var/lib/orblx/tokens/${name}"
done

coord_ip="$(resolve_name coord)"
if [[ -z "$coord_ip" ]]; then
  echo "The coordinator address did not resolve." >&2
  exit 1
fi
echo "coord_ip ${coord_ip}"

enroll_node owner
enroll_node a
enroll_node b

echo "=== [C] admin approve a and b ==="
admin approve a
admin approve b

echo "=== [C] route change on b ==="
advertise_b --route 10.77.0.0/24

echo "=== [C] exit-node change on b ==="
advertise_b --exit-node on

echo "=== [C] admin expire a ==="
admin expire a

echo "=== [C] admin approve a ==="
admin approve a

echo "=== [C] admin revoke a ==="
admin revoke a

echo "=== [C] policy replace ==="
cat "$ROOT/scripts/proof/audit-v2.hujson" > "$POLICY_FILE"
admin nodes

echo "=== [C] policy reject ==="
printf '%s\n' '{ "acls": [ this is not hujson' > "$POLICY_FILE"
admin nodes

echo "=== [C] coordinator log lines for the config audit ==="
dc logs --no-log-prefix coord | grep -E '^(config audit|policy load failed)' || true

echo "=== [C] admin audit ==="
audit_text="$(admin audit)"
printf '%s\n' "$audit_text"
owner_id="spiffe://orblx.local/node/owner"
coord_id="spiffe://orblx.local/coord/coord"
b_id="spiffe://orblx.local/node/b"
expect_action "$audit_text" policy-load "$coord_id"
expect_action "$audit_text" enroll "token:[0-9a-f]{16}"
expect_action "$audit_text" approve "$owner_id"
expect_action "$audit_text" routes "$b_id"
expect_action "$audit_text" exit-node "$b_id"
expect_action "$audit_text" expire "$owner_id"
expect_action "$audit_text" revoke "$owner_id"
expect_action "$audit_text" policy-replace "$coord_id"
expect_action "$audit_text" policy-reject "$coord_id"
enroll_count="$(printf '%s\n' "$audit_text" | grep -c ' enroll ')"
if [[ "$enroll_count" -ne 3 ]]; then
  echo "The audit has ${enroll_count} enroll records. The proof expects 3." >&2
  exit 1
fi
printf '%s\n' "$audit_text" | grep -q '^verify ok records 13 tip [0-9a-f]\{64\}$'

echo "=== [C] admin audit --json --since ${start_unix} ==="
audit_json="$(admin audit --json --since "$start_unix" 2>"$WORK/json.err")"
printf '%s\n' "$audit_json"
cat "$WORK/json.err"
printf '%s\n' "$audit_json" | jq -e -s 'length == 13' >/dev/null
printf '%s\n' "$audit_json" | jq -e -s 'map(.action) | index("revoke") != null' >/dev/null
printf '%s\n' "$audit_json" \
  | jq -e -s 'all(.[]; (.at_utc | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")))' >/dev/null

echo "=== [C] admin audit --since 1h ==="
admin audit --since 1h --verify

echo "=== [C] audit verify-config in the coordinator ==="
dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl

echo "=== [C] change one byte in the chain ==="
dc exec -T coord python3 - <<'PY'
import pathlib
path = pathlib.Path("/var/lib/orblx/config-audit.jsonl")
data = bytearray(path.read_bytes())
needle = b'"action":"approve","target":"a"'
at = data.index(needle) + len(needle) - 2
old = data[at]
data[at] = ord("x")
path.write_bytes(bytes(data))
print(f"changed byte offset {at} from {chr(old)!r} to 'x'")
PY

echo "=== [C] admin audit --verify after the change ==="
set +e
tamper_out="$(admin audit --verify 2>&1)"
tamper_status=$?
set -e
printf '%s\n' "$tamper_out"
echo "exit ${tamper_status}"
if [[ "$tamper_status" -eq 0 ]]; then
  echo "The chain check passed after the change." >&2
  exit 1
fi
printf '%s\n' "$tamper_out" | grep -q '^verify failed: The hash check failed at index'

echo "=== [C] audit verify-config after the change ==="
set +e
file_out="$(dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl 2>&1)"
file_status=$?
set -e
printf '%s\n' "$file_out"
echo "exit ${file_status}"
if [[ "$file_status" -eq 0 ]]; then
  echo "The file check passed after the change." >&2
  exit 1
fi
printf '%s\n' "$file_out" | grep -q 'The hash check failed at index'

echo "proof_ok"
