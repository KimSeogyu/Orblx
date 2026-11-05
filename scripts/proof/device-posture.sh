#!/usr/bin/env bash
# Device posture proof for grants and tickets.
# The host is REAL. coord, a, b, and c are [C] containers.
# Gates:
#   1. orblx policy test prints the three posture lines and policy ok.
#   2. a and b enroll in posture: deny 0, revoke 0, restore 0, grants on b 1, ticket nonces 0.
#   3. a reports windows: revoke 1, grants on b 0, ticket nonces 1. A second report stays at 1.
#   4. a reports linux and renews: restore 1, revoke stays 1, grants on b 1, ticket nonces stay 1.
#   5. a reports windows again: revoke 2, restore stays 1, grants on b 0, ticket nonces 2.
#   6. c enrolls with an unknown OS: deny 1, no ticket file. A second report stays at 1.
#   7. The audit chain verifies. Logs and the audit file have 0 secret hits.
# The script prints proof_ok. It does not print a token, a key, or a ticket nonce.
# Environment:
#   DPPROOF_PROJECT  Compose project name (default orblx-device-posture-proof).
#   DPPROOF_IMAGE    Image tag (default orblx-device-posture:local).
#   DPPROOF_BIN      An orblx binary to use. Without it, the script builds target/debug/orblx.
#   ORBLX_NET_HOOK   A root script that the script runs after the network starts.
#   PROOF_LOG        The log file of this run. The secret check also reads this file.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.device-posture.yml"
DPPROOF_PROJECT="${DPPROOF_PROJECT:-orblx-device-posture-proof}"
DPPROOF_IMAGE="${DPPROOF_IMAGE:-orblx-device-posture:local}"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/env"
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15
trap proof_lock_end EXIT
proof_lock_take "device-posture" "$DPPROOF_PROJECT"
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "$DPPROOF_PROJECT" || exit 1
printf 'DPPROOF_IMAGE=%s\n' "$DPPROOF_IMAGE" > "$ENV_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose -p "$DPPROOF_PROJECT" --env-file "$ENV_FILE" --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap 'cleanup; proof_lock_end' EXIT

fail() {
  echo "proof_fail: $*" >&2
  echo "---- coord log (last 40 lines) ----" >&2
  dc logs --no-log-prefix coord 2>&1 | tail -n 40 >&2 || true
  exit 1
}

node_run() {
  local name="$1"
  shift
  dc run --rm --no-deps -T "$name" "$@"
}

enroll_node() {
  local name="$1"
  echo "=== [C] enroll ${name} ==="
  node_run "$name" coord enroll \
    --name "$name" \
    --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state /var/lib/orblx \
    --endpoint "${name}:443"
}

renew_node() {
  local name="$1"
  node_run "$name" coord renew \
    --coord "$COORD" \
    --bundle /var/lib/orblx/bundle.pem \
    --state /var/lib/orblx
}

grant_count() {
  local out
  out="$(node_run b coord netmap \
    --coord "$COORD" \
    --bundle /var/lib/orblx/bundle.pem \
    --state /var/lib/orblx)"
  printf '%s\n' "$out" | awk '/^grants /{print $2; exit}'
}

audit_counts() {
  dc exec -T coord python3 -c 'import json
deny=revoke=restore=0
for line in open("/var/lib/orblx/config-audit.jsonl"):
    row=json.loads(line)
    if row.get("action")=="posture-deny":
        deny+=1
    elif row.get("action")=="posture-revoke":
        revoke+=1
    elif row.get("action")=="posture-restore":
        restore+=1
print(deny)
print(revoke)
print(restore)'
}

nonce_count() {
  dc exec -T coord python3 -c 'import json, pathlib
path=pathlib.Path("/var/lib/orblx/deny.json")
if not path.exists():
    print(0)
    print(0)
    raise SystemExit
data=json.loads(path.read_text())
print(len(data.get("revoked_ticket_nonces", [])))
print(len(data.get("revoked_uris", [])))'
}

expect_pair() {
  local label="$1" got1="$2" want1="$3" got2="$4" want2="$5"
  echo "${label} ${got1} ${got2} want ${want1} ${want2}"
  [[ "$got1" == "$want1" && "$got2" == "$want2" ]] || fail "${label}"
}

expect_counts() {
  local label="$1" got_deny="$2" want_deny="$3" got_revoke="$4" want_revoke="$5" got_restore="$6" want_restore="$7"
  echo "${label} deny ${got_deny} revoke ${got_revoke} restore ${got_restore} want ${want_deny} ${want_revoke} ${want_restore}"
  [[ "$got_deny" == "$want_deny" && "$got_revoke" == "$want_revoke" && "$got_restore" == "$want_restore" ]] || fail "${label}"
}

echo "=== [REAL] host ==="
uname -sm

echo "=== [C] policy test ==="
bin="${DPPROOF_BIN:-}"
if [[ -z "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --locked
  bin="$ROOT/target/debug/orblx"
fi
[[ -x "$bin" ]] || fail "the orblx binary $bin is missing"
policy_out="$("$bin" policy test "$ROOT/scripts/proof/device-posture.hujson")"
printf '%s\n' "$policy_out"
[[ "$policy_out" == $'allow posture desk\ndeny posture desk\ndeny posture desk\npolicy ok' ]] \
  || fail "policy test output"

echo "=== [C] build image ${DPPROOF_IMAGE} (project ${DPPROOF_PROJECT}) ==="
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$bin")"
as_root docker build -q -t "$DPPROOF_IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] start coordinator ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
dc run --rm --no-deps -T --entrypoint sh coord -c 'mkdir -p /var/lib/orblx && cat > /var/lib/orblx/policy.hujson' \
  < "$ROOT/scripts/proof/device-posture.hujson"
dc up -d coord
if [[ -n "${ORBLX_NET_HOOK:-}" ]]; then
  as_root "$ORBLX_NET_HOOK" >/dev/null 2>&1 || true
fi
for _ in $(seq 1 60); do
  dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem && break
  sleep 1
done
dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem || fail "no trust bundle"
coord_ip="$(dc run --rm --no-deps -T --entrypoint getent a ahostsv4 coord | awk '{print $1; exit}')"
COORD="${coord_ip}:443"
echo "coord ${COORD}"

for name in a b c; do
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 600 \
    --out "/var/lib/orblx/tokens/${name}" | grep -E '^(wrote|token_id|expires_unix|out)'
done

enroll_node a
enroll_node b
mapfile -t counts < <(audit_counts)
expect_counts "after enroll" "${counts[0]}" 0 "${counts[1]}" 0 "${counts[2]}" 0
grants="$(grant_count)"
echo "grants_b ${grants} want 1"
[[ "$grants" == 1 ]] || fail "grants after enroll"
mapfile -t nonces < <(nonce_count)
expect_pair "nonces after enroll" "${nonces[0]}" 0 "${nonces[1]}" 0

echo "=== [C] a reports windows ==="
dc run --rm --no-deps -T -e ORBLX_CLIENT_OS=windows a coord renew \
  --coord "$COORD" --bundle /var/lib/orblx/bundle.pem --state /var/lib/orblx \
  | grep -E '^(enrolled|name|ticket)'
mapfile -t counts < <(audit_counts)
expect_counts "after windows" "${counts[0]}" 0 "${counts[1]}" 1 "${counts[2]}" 0
grants="$(grant_count)"
echo "grants_b ${grants} want 0"
[[ "$grants" == 0 ]] || fail "grants after windows"
mapfile -t nonces < <(nonce_count)
expect_pair "nonces after windows" "${nonces[0]}" 1 "${nonces[1]}" 0

echo "=== [C] a reports windows again ==="
dc run --rm --no-deps -T -e ORBLX_CLIENT_OS=windows a coord renew \
  --coord "$COORD" --bundle /var/lib/orblx/bundle.pem --state /var/lib/orblx \
  | grep -E '^(enrolled|name|ticket)'
mapfile -t counts < <(audit_counts)
expect_counts "windows again" "${counts[0]}" 0 "${counts[1]}" 1 "${counts[2]}" 0
mapfile -t nonces < <(nonce_count)
expect_pair "nonces windows again" "${nonces[0]}" 1 "${nonces[1]}" 0

echo "=== [C] a reports linux and renews ==="
dc run --rm --no-deps -T -e ORBLX_CLIENT_OS=linux a coord renew \
  --coord "$COORD" --bundle /var/lib/orblx/bundle.pem --state /var/lib/orblx \
  | grep -E '^(enrolled|name|ticket)'
mapfile -t counts < <(audit_counts)
expect_counts "after recovery" "${counts[0]}" 0 "${counts[1]}" 1 "${counts[2]}" 1
grants="$(grant_count)"
echo "grants_b ${grants} want 1"
[[ "$grants" == 1 ]] || fail "grants after recovery"
mapfile -t nonces < <(nonce_count)
expect_pair "nonces after recovery" "${nonces[0]}" 1 "${nonces[1]}" 0

echo "=== [C] a reports windows a second time ==="
dc run --rm --no-deps -T -e ORBLX_CLIENT_OS=windows a coord renew \
  --coord "$COORD" --bundle /var/lib/orblx/bundle.pem --state /var/lib/orblx \
  | grep -E '^(enrolled|name|ticket)'
mapfile -t counts < <(audit_counts)
expect_counts "second fall" "${counts[0]}" 0 "${counts[1]}" 2 "${counts[2]}" 1
grants="$(grant_count)"
echo "grants_b ${grants} want 0"
[[ "$grants" == 0 ]] || fail "grants after second fall"
mapfile -t nonces < <(nonce_count)
expect_pair "nonces second fall" "${nonces[0]}" 2 "${nonces[1]}" 0

echo "=== [C] c enrolls with an unknown OS ==="
dc run --rm --no-deps -T -e ORBLX_CLIENT_OS=unknown c coord enroll \
  --name c \
  --coord "$COORD" \
  --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/c \
  --state /var/lib/orblx \
  --endpoint c:443 | grep -E '^(enrolled|name|ticket)'
dc run --rm --no-deps -T c test ! -f /var/lib/orblx/ticket.bin
mapfile -t counts < <(audit_counts)
expect_counts "unknown enroll" "${counts[0]}" 1 "${counts[1]}" 2 "${counts[2]}" 1
echo "=== [C] c reports again while still out ==="
dc run --rm --no-deps -T -e ORBLX_CLIENT_OS=unknown c coord renew \
  --coord "$COORD" --bundle /var/lib/orblx/bundle.pem --state /var/lib/orblx \
  | grep -E '^(enrolled|name|ticket)'
mapfile -t counts < <(audit_counts)
expect_counts "unknown again" "${counts[0]}" 1 "${counts[1]}" 2 "${counts[2]}" 1
mapfile -t nonces < <(nonce_count)
expect_pair "nonces after unknown" "${nonces[0]}" 2 "${nonces[1]}" 0

echo "=== [C] audit chain ==="
verify_out="$(dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl)" \
  || fail "audit verify-config failed"
[[ "${verify_out%%$'\n'*}" == ok ]] || fail "audit verify-config did not print ok"
echo "audit verify-config ok"

echo "=== [C] secret check ==="
dc exec -T coord python3 -c 'import json, pathlib
root=pathlib.Path("/var/lib/orblx")
needles=["PRIVATE KEY", "ge1.", "orblx-at1."]
deny=root/"deny.json"
if deny.exists():
    needles += json.loads(deny.read_text()).get("revoked_ticket_nonces", [])
path=pathlib.Path("/tmp/needles")
path.write_text("\n".join(needles)+"\n")
print(len(needles))' > "$WORK/needle_count"
[[ "$(tr -d "[:space:]" < "$WORK/needle_count")" == 5 ]] || fail "needle count"
hits_audit="$(dc exec -T coord sh -c 'grep -cF -f /tmp/needles /var/lib/orblx/config-audit.jsonl || true')"
echo "secret_hits audit ${hits_audit}"
[[ "$hits_audit" == 0 ]] || fail "audit has a secret"
hits_posture="$(dc exec -T coord sh -c 'grep -cF -f /tmp/needles /var/lib/orblx/posture.json || true')"
echo "secret_hits posture ${hits_posture}"
[[ "$hits_posture" == 0 ]] || fail "posture file has a revoked nonce or a key"
dc logs --no-log-prefix > "$WORK/logs.txt" 2>&1 || true
dc exec -T coord cat /tmp/needles > "$WORK/needles"
hits_logs="$(grep -cF -f "$WORK/needles" "$WORK/logs.txt" || true)"
echo "secret_hits container_logs ${hits_logs}"
[[ "$hits_logs" == 0 ]] || fail "logs have a secret"
if [[ -n "${PROOF_LOG:-}" && -f "$PROOF_LOG" ]]; then
  hits_proof="$(grep -cF -f "$WORK/needles" "$PROOF_LOG" || true)"
  echo "secret_hits proof_log ${hits_proof}"
  [[ "$hits_proof" == 0 ]] || fail "proof log has a secret"
fi

echo "proof_ok"
