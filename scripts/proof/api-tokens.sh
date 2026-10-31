#!/usr/bin/env bash
# W25-3 scoped API token proof for the coordinator admin API.
# The host is REAL. coord, owner, a, and client are [C] containers.
# Gates:
#   1. A nodes:read token gets 200 for nodes, users, and routes, and 403 for every other admin operation.
#   2. An expired token gets 401 at most EXPIRY_LIMIT_MS after its expiry time.
#   3. A revoked token gets 401 at most REVOKE_LIMIT_MS after the revoke.
#   4. Each token has exactly one token-create and one token-revoke record. Each call with a token
#      has exactly one token-use (allowed) or token-deny (refused) record. The chain check prints ok.
#   5. No token text is in a log, an audit record, or a coordinator state file.
#   6. The owner SVID (mTLS) still works. A node that is not an owner is still refused.
# The script never prints a token. It prints proof_ok.
# Environment:
#   ATPROOF_PROJECT  Compose project name (default orblx-api-tokens-proof).
#   ATPROOF_IMAGE    Image tag (default orblx-api-tokens:local).
#   ATPROOF_BIN      An orblx binary to use. Without it, the script builds target/debug/orblx.
#   ORBLX_NET_HOOK  A root script that the script runs after the network starts.
#   PROOF_LOG       The log file of this run. The secret check also reads this file.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.api-tokens.yml"
ATPROOF_PROJECT="${ATPROOF_PROJECT:-orblx-api-tokens-proof}"
ATPROOF_IMAGE="${ATPROOF_IMAGE:-orblx-api-tokens:local}"
EXPIRY_LIMIT_MS=1000
REVOKE_LIMIT_MS=1000
WORK="$(mktemp -d)"
ENV_FILE="$WORK/env"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=12  # reason: the floor (PROOF_DISK_FLOOR_GIB): one build output and one proof image. No bigger measure for this proof.
trap proof_lock_end EXIT
proof_lock_take "api-tokens" "$ATPROOF_PROJECT"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "$ATPROOF_PROJECT" || exit 1
printf 'ATPROOF_IMAGE=%s\n' "$ATPROOF_IMAGE" > "$ENV_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose -p "$ATPROOF_PROJECT" --env-file "$ENV_FILE" --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the cleanup runs first, then the lock is released.
trap 'cleanup; proof_lock_end' EXIT

# A pipe into head or grep -q can stop the writer early (SIGPIPE). With pipefail, the
# pipe then fails at random. So the script keeps each output in a variable first.
first_line() {
  local text="$1"
  printf '%s\n' "${text%%$'\n'*}"
}

fail() {
  echo "proof_fail: $*" >&2
  echo "---- coord log (last 40 lines) ----" >&2
  dc logs --no-log-prefix coord 2>&1 | tail -n 40 >&2 || true
  exit 1
}

owner() {
  dc run --rm --no-deps -T owner "$@"
}

# Run one admin call from the client host with a token file. Print "op OP status N".
client_call() {
  local token="$1" op="$2" arg="${3:-}"
  local out status
  set +e
  if [[ -n "$arg" ]]; then
    out="$(dc exec -T client orblx admin call "$op" "$arg" --token-file "/tokens/$token" \
      --coord "$COORD" --bundle /coord-state/trust-bundle.pem 2>&1)"
  else
    out="$(dc exec -T client orblx admin call "$op" --token-file "/tokens/$token" \
      --coord "$COORD" --bundle /coord-state/trust-bundle.pem 2>&1)"
  fi
  set -e
  status="$(printf '%s\n' "$out" | read_all awk '/^status /{print $2; exit}')"
  printf '%s\n' "${status:-none}"
}

echo "=== [REAL] host ==="
uname -sm

echo "=== [C] build image ${ATPROOF_IMAGE} (project ${ATPROOF_PROJECT}) ==="
bin="${ATPROOF_BIN:-}"
if [[ -z "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --locked
  bin="$ROOT/target/debug/orblx"
fi
[[ -x "$bin" ]] || fail "the orblx binary $bin is missing"
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$bin")"
as_root docker build -q -t "$ATPROOF_IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] start coordinator ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
dc run --rm --no-deps -T --entrypoint sh coord -c 'mkdir -p /var/lib/orblx && cat > /var/lib/orblx/policy.hujson' \
  < "$ROOT/scripts/proof/api-tokens.hujson"
dc up -d coord client
if [[ -n "${ORBLX_NET_HOOK:-}" ]]; then
  as_root "$ORBLX_NET_HOOK" >/dev/null 2>&1 || true
fi
for _ in $(seq 1 60); do
  dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem && break
  sleep 1
done
dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem || fail "no trust bundle"
coord_ip="$(dc exec -T client getent ahostsv4 coord | read_all awk '{print $1; exit}')"
COORD="${coord_ip}:443"
echo "coord ${COORD}"

echo "=== [C] enroll owner and a ==="
for name in owner a; do
  dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 600 \
    --out "/var/lib/orblx/tokens/${name}" | grep -E '^(wrote|token_id)'
  dc run --rm --no-deps -T "$name" coord enroll --name "$name" --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem --token-file "/coord-state/tokens/${name}" \
    --state /var/lib/orblx --endpoint "${name}:443" | grep -E '^(enrolled|overlay|svid)' || true
done

ADMIN=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)

echo "=== [C] gate 6: owner SVID (mTLS) still works ==="
owner admin nodes "${ADMIN[@]}"
policy_out="$(owner admin policy "${ADMIN[@]}")"
first_line "$policy_out"
set +e
a_out="$(dc run --rm --no-deps -T a admin nodes "${ADMIN[@]}" 2>&1)"
a_rc=$?
set -e
printf '%s\n' "$a_out" | tail -n 1
[[ "$a_rc" -ne 0 ]] && grep -q "not an owner" <<< "$a_out" || fail "node a was not refused"
echo "node_a_admin refused (not an owner)"

echo "=== [C] owner creates tokens ==="
# create_token NAME SCOPE TTL prints the create lines. The token goes only to /tokens/NAME.
create_token() {
  owner admin token-create --scope "$2" --ttl "$3" --out "/tokens/$1" "${ADMIN[@]}"
}
id_from() {
  printf '%s\n' "$1" | awk '/^token_id /{print $2}'
}
out="$(create_token read nodes:read 10m)"; printf '%s\n' "$out"; READ_ID="$(id_from "$out")"
out="$(create_token policy policy:write 10m)"; printf '%s\n' "$out"; POLICY_ID="$(id_from "$out")"
out="$(create_token revoke nodes:read 10m)"; printf '%s\n' "$out"; REVOKE_ID="$(id_from "$out")"
owner admin token-list "${ADMIN[@]}"
dc exec -T client sh -c 'stat -c "%a %n" /tokens/read /tokens/policy /tokens/revoke'

echo "=== [C] gate 1: nodes:read token on every admin operation ==="
ops=(admin-nodes admin-users admin-routes admin-approve admin-revoke admin-revoke-all admin-expire
  admin-grants admin-grant-approve admin-grant-revoke admin-audit admin-lock admin-lock-init
  admin-lock-sign admin-lock-update admin-policy admin-policy-set admin-token-create
  admin-token-list admin-token-revoke)
allowed=0
refused=0
for op in "${ops[@]}"; do
  arg=""
  case "$op" in
    admin-approve|admin-revoke|admin-expire) arg="a" ;;
    admin-revoke-all) arg="spiffe://orblx.local/node/a" ;;
    admin-token-revoke) arg="$READ_ID" ;;
    admin-token-create) arg='{"scopes":["nodes:write"],"ttl_secs":60}' ;;
    admin-policy-set) arg='{"owners":["spiffe://orblx.local/node/a"]}' ;;
  esac
  status="$(client_call read "$op" "$arg")"
  case "$op" in
    admin-nodes|admin-users|admin-routes) want=200 ;;
    *) want=403 ;;
  esac
  echo "op ${op} status ${status} want ${want}"
  if [[ "$status" != "$want" ]]; then
    fail "KILL: op ${op} gave status ${status}, not ${want}"
  fi
  if [[ "$want" == 200 ]]; then allowed=$((allowed + 1)); else refused=$((refused + 1)); fi
done
echo "gate1 ops ${#ops[@]} allowed ${allowed} refused_403 ${refused}"
nodes_out="$(owner admin nodes "${ADMIN[@]}")"
grep -q '^node a ' <<< "$nodes_out" || fail "node a is gone after the 403 calls"
policy_out="$(owner admin policy "${ADMIN[@]}")"
grep -q 'node/owner' <<< "$policy_out" || fail "the policy changed after the 403 calls"
echo "after_403 node a still enrolled, policy owners unchanged"

echo "=== [C] policy:write token: policy-set 200, nodes 403 ==="
policy_text="$(cat "$ROOT/scripts/proof/api-tokens.hujson")"
s1="$(client_call policy admin-policy-set "$policy_text")"
s2="$(client_call policy admin-nodes)"
s3="$(client_call policy admin-grant-approve x)"
echo "policy_token policy-set ${s1} nodes ${s2} grant-approve ${s3}"
[[ "$s1" == 200 && "$s2" == 403 && "$s3" == 403 ]] || fail "policy token statuses"
POLICY_USE=1
POLICY_DENY=2

echo "=== [C] gate 2: expired token ==="
# The token is made just before the loop, so the loop sees it work and then expire.
expire_out="$(create_token expire nodes:read 3s)"
printf '%s\n' "$expire_out"
EXPIRE_ID="$(id_from "$expire_out")"
expire_at="$(printf '%s\n' "$expire_out" | awk '/^expires_unix_ms /{print $2}')"
loop='end=$(( $(date +%s%3N) + 20000 )); ok=0
while [ "$(date +%s%3N)" -lt "$end" ]; do
  out="$(orblx admin call admin-nodes --token-file /tokens/$1 --coord $2 --bundle /coord-state/trust-bundle.pem 2>&1)"
  line="$(printf "%s\n" "$out" | grep "^status ")"
  case "$line" in
    "status 200 "*) ok=$((ok + 1)); last="$line" ;;
    *) echo "allowed $ok"; echo "last_ok $last"; echo "first_deny $line"; printf "%s\n" "$out" | tail -n 1; exit 0 ;;
  esac
done
echo "allowed $ok"; echo "no_deny"'
exp_out="$(dc exec -T client bash -c "$loop" loop expire "$COORD")"
printf '%s\n' "$exp_out"
exp_allowed="$(printf '%s\n' "$exp_out" | awk '/^allowed /{print $2}')"
deny_ms="$(printf '%s\n' "$exp_out" | awk '/^first_deny /{print $5}')"
deny_status="$(printf '%s\n' "$exp_out" | awk '/^first_deny /{print $3}')"
[[ "$deny_status" == 401 ]] || fail "the expired token did not get 401"
grep -q "The API token is expired." <<< "$exp_out" || fail "the deny reason is not expired"
last_ok_ms="$(printf '%s\n' "$exp_out" | awk '/^last_ok /{print $5}')"
expiry_delta=$((deny_ms - expire_at))
echo "expire expires_unix_ms ${expire_at} last_ok_done_ms ${last_ok_ms} first_401_done_ms ${deny_ms} expiry_to_401_ms ${expiry_delta}"
(( expiry_delta >= 0 && expiry_delta <= EXPIRY_LIMIT_MS )) || fail "expiry_to_401_ms ${expiry_delta}"
(( exp_allowed >= 1 )) || fail "the expire token never worked"

echo "=== [C] gate 3: revoked token ==="
dc exec -T -d client bash -c "{ ${loop}
} > /tmp/revoke-loop.txt 2>&1" loop revoke "$COORD"
sleep 2
rev_out="$(owner admin token-revoke "$REVOKE_ID" "${ADMIN[@]}")"
printf '%s\n' "$rev_out"
revoked_at="$(printf '%s\n' "$rev_out" | awk '/^revoked_unix_ms /{print $2}')"
for _ in $(seq 1 40); do
  dc exec -T client grep -q -E '^(first_deny|no_deny)' /tmp/revoke-loop.txt 2>/dev/null && break
  sleep 0.5
done
rl="$(dc exec -T client cat /tmp/revoke-loop.txt)"
printf '%s\n' "$rl"
rev_allowed="$(printf '%s\n' "$rl" | awk '/^allowed /{print $2}')"
rdeny_ms="$(printf '%s\n' "$rl" | awk '/^first_deny /{print $5}')"
rdeny_status="$(printf '%s\n' "$rl" | awk '/^first_deny /{print $3}')"
[[ "$rdeny_status" == 401 ]] || fail "the revoked token did not get 401"
grep -q "The API token is revoked." <<< "$rl" || fail "the deny reason is not revoked"
revoke_delta=$((rdeny_ms - revoked_at))
echo "revoke revoked_unix_ms ${revoked_at} first_401_done_ms ${rdeny_ms} revoke_to_401_ms ${revoke_delta}"
(( revoke_delta >= 0 && revoke_delta <= REVOKE_LIMIT_MS )) || fail "revoke_to_401_ms ${revoke_delta}"
(( rev_allowed >= 1 )) || fail "the revoke token never worked"
s4="$(client_call revoke admin-nodes)"
echo "revoked_token later status ${s4}"
[[ "$s4" == 401 ]] || fail "the revoked token works again"

echo "=== [C] owner revokes the other tokens ==="
for id in "$READ_ID" "$POLICY_ID" "$EXPIRE_ID"; do
  owner admin token-revoke "$id" "${ADMIN[@]}" | grep '^revoked_token'
done
owner admin token-list "${ADMIN[@]}"

echo "=== [C] gate 4: audit records ==="
audit_json="$(owner admin audit --json "${ADMIN[@]}" 2>/dev/null)"
count() {
  printf '%s\n' "$audit_json" | jq -c "select(.action == \"$1\" and .target == \"$2\")" | wc -l
}
check_count() {
  local action="$1" id="$2" want="$3" got
  got="$(count "$action" "$id")"
  echo "audit ${action} ${id} ${got} want ${want}"
  [[ "$got" == "$want" ]] || fail "audit ${action} ${id} ${got} not ${want}"
}
# read: the gate 1 calls only. policy: 1 allowed and 2 refused. expire and revoke: the loops, then 1 more refused call for revoke.
check_count token-create "$READ_ID" 1
check_count token-use "$READ_ID" "$allowed"
check_count token-deny "$READ_ID" "$refused"
check_count token-revoke "$READ_ID" 1
check_count token-create "$POLICY_ID" 1
check_count token-use "$POLICY_ID" "$POLICY_USE"
check_count token-deny "$POLICY_ID" "$POLICY_DENY"
check_count token-revoke "$POLICY_ID" 1
check_count token-create "$EXPIRE_ID" 1
check_count token-use "$EXPIRE_ID" "$exp_allowed"
check_count token-deny "$EXPIRE_ID" 1
check_count token-revoke "$EXPIRE_ID" 1
check_count token-create "$REVOKE_ID" 1
check_count token-use "$REVOKE_ID" "$rev_allowed"
check_count token-deny "$REVOKE_ID" 2
check_count token-revoke "$REVOKE_ID" 1
printf '%s\n' "$audit_json" | jq -r 'select(.action | startswith("token-")) | "\(.action) \(.target) \(.actor) \(.detail)"' \
  | sort | uniq -c | sort -k2
owner admin audit --verify "${ADMIN[@]}"
verify_out="$(dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl)" \
  || fail "audit verify-config failed"
[[ "$(first_line "$verify_out")" == ok ]] || fail "audit verify-config did not print ok"
echo "audit verify-config ok $(grep '^records ' <<< "$verify_out")"

echo "=== [C] gate 5: no token text in logs, audit records, or state files ==="
# The check reads the 4 token files inside [C] and does not print them.
dc exec -T client sh -c 'for f in /tokens/read /tokens/policy /tokens/revoke /tokens/expire; do cut -d. -f2 "$f"; done' > "$WORK/needles"
[[ "$(wc -l < "$WORK/needles")" -eq 4 ]] || fail "the token files are not readable"
# Positive control: the same check finds each token in its own file.
hits_control="$(dc exec -T client sh -c 'cat > /tmp/needles; grep -lF -f /tmp/needles /tokens/read /tokens/policy /tokens/revoke /tokens/expire | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
echo "secret_check control_token_files ${hits_control} want 4"
[[ "$hits_control" == 4 ]] || fail "the secret check does not find the token files"
hits_state="$(dc exec -T coord sh -c 'cat > /tmp/needles; grep -rlF -f /tmp/needles /var/lib/orblx | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
echo "secret_hits coord_state_files ${hits_state}"
dc logs --no-log-prefix > "$WORK/logs.txt" 2>&1 || true
hits_logs="$(grep -cF -f "$WORK/needles" "$WORK/logs.txt" || true)"
echo "secret_hits container_logs ${hits_logs} lines $(wc -l < "$WORK/logs.txt")"
hits_audit="$(printf '%s\n' "$audit_json" | grep -cF -f "$WORK/needles" || true)"
echo "secret_hits audit_records ${hits_audit}"
hits_proof=0
if [[ -n "${PROOF_LOG:-}" && -f "$PROOF_LOG" ]]; then
  hits_proof="$(grep -cF -f "$WORK/needles" "$PROOF_LOG" || true)"
  echo "secret_hits proof_log ${hits_proof}"
fi
dc exec -T coord sh -c 'stat -c "%a %n" /var/lib/orblx/api-tokens.json; grep -c hash_hex /var/lib/orblx/api-tokens.json'
rm -f "$WORK/needles"
[[ "$hits_state" == 0 && "$hits_logs" == 0 && "$hits_audit" == 0 && "$hits_proof" == 0 ]] || fail "a token text was found"

echo "=== [C] gate 6: owner SVID after the token steps ==="
owner admin nodes "${ADMIN[@]}" | tail -n 1

echo "proof_ok"
