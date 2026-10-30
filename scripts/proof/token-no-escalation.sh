#!/usr/bin/env bash
# W25-3b proof: a scoped API token cannot escalate past its scope.
# The host is REAL. coord, owner, a, and client are [C] containers (compose.api-tokens.yml).
# Gates:
#   1. A policy:write token that adds, removes, or changes the owners gets 403. The owners do not change.
#   2. The same token gets 200 for a policy-set that keeps the owners.
#   3. The same token gets 403 for the node lock signer calls and the token calls. The lock store
#      and the token store do not change.
#   4. The owner SVID (mTLS) can change the owners.
#   5. Each refusal has exactly 1 token-deny record. The chain check prints ok.
#   7. No token text is in a log, an audit record, or a coordinator state file.
# Gate 6 (the W25-3 proof and the W23-4 gates) uses api-tokens.sh and nat-realism.sh.
# The script never prints a token or a key. It prints proof_ok.
# Environment:
#   ESC_PROJECT     Compose project name (default orblx-w25e-escalation).
#   ESC_IMAGE       Image tag (default orblx-w25e-escalation:local).
#   ESC_BIN         An orblx binary to use. Without it, the script builds target/debug/orblx.
#   ORBLX_NET_HOOK  A root script that the script runs after the network starts.
#   PROOF_LOG       The log file of this run. The secret check also reads this file.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.api-tokens.yml"
ESC_PROJECT="${ESC_PROJECT:-orblx-w25e-escalation}"
ESC_IMAGE="${ESC_IMAGE:-orblx-w25e-escalation:local}"
OWNER_ID="spiffe://orblx.local/node/owner"
A_ID="spiffe://orblx.local/node/a"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/env"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take "token-no-escalation" "$ESC_PROJECT"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "$ESC_PROJECT" || exit 1
printf 'TOKENS_IMAGE=%s\n' "$ESC_IMAGE" > "$ENV_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose -p "$ESC_PROJECT" --env-file "$ENV_FILE" --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the cleanup runs first, then the lock is released.
trap 'cleanup; proof_lock_end' EXIT

# No pipe into head or grep -q: with pipefail, an early reader can fail the pipe (SIGPIPE).
# The script keeps each output in a variable, then checks the variable.
has_line() {
  local pattern="$1" text="$2"
  [[ -n "$(awk -v re="$pattern" '$0 ~ re {print; exit}' <<< "$text")" ]]
}

field() {
  local key="$1" text="$2"
  awk -v k="$key" '$1 == k {print $2; exit}' <<< "$text"
}

fail() {
  echo "proof_fail: $*" >&2
  local logs
  logs="$(dc logs --no-log-prefix coord 2>&1 || true)"
  echo "---- coord log (last 40 lines) ----" >&2
  tail -n 40 <<< "$logs" >&2
  exit 1
}

owner() {
  dc run --rm --no-deps -T owner "$@"
}

owner_sh() {
  dc run --rm --no-deps -T --entrypoint sh owner -c "$1"
}

# Run one admin call from the client host with a token file. Print the status, or none.
client_call() {
  local token="$1" op="$2" arg="${3:-}"
  local out
  set +e
  if [[ -n "$arg" ]]; then
    out="$(dc exec -T client orblx admin call "$op" "$arg" --token-file "/tokens/$token" \
      --coord "$COORD" --bundle /coord-state/trust-bundle.pem 2>&1)"
  else
    out="$(dc exec -T client orblx admin call "$op" --token-file "/tokens/$token" \
      --coord "$COORD" --bundle /coord-state/trust-bundle.pem 2>&1)"
  fi
  set -e
  # The call runs in a command substitution, so it keeps the reply in a file, not a variable.
  printf '%s\n' "$out" > "$WORK/last.txt"
  local status
  status="$(field status "$out")"
  printf '%s\n' "${status:-none}"
}

# policy_json OWNER... prints a policy with these owners and the proof ACL.
policy_json() {
  local list="" id
  for id in "$@"; do
    list="${list:+$list, }\"$id\""
  done
  printf '{"nodeApproval": false, "owners": [%s], "acls": [{"action": "accept", "src": ["%s"], "proto": "udp", "dst": ["%s:*"]}]}\n' \
    "$list" "$A_ID" "$OWNER_ID"
}

coord_sha() {
  dc exec -T coord sh -c "if [ -f '$1' ]; then sha256sum '$1' | cut -c1-64; else echo missing; fi"
}

policy_sha() {
  local out
  out="$(owner admin policy "${ADMIN[@]}")"
  field policy_sha256 "$out"
}

a_is_refused() {
  local out rc
  set +e
  out="$(dc run --rm --no-deps -T a admin nodes "${ADMIN[@]}" 2>&1)"
  rc=$?
  set -e
  [[ "$rc" -ne 0 ]] && has_line "not an owner" "$out"
}

echo "=== [REAL] host ==="
uname -sm
echo "commit $(git rev-parse HEAD)"

echo "=== [C] build image ${ESC_IMAGE} (project ${ESC_PROJECT}) ==="
bin="${ESC_BIN:-}"
if [[ -z "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --locked
  bin="$ROOT/target/debug/orblx"
fi
[[ -x "$bin" ]] || fail "the orblx binary $bin is missing"
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$bin")"
as_root docker build -q -t "$ESC_IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] start coordinator ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
policy_json "$OWNER_ID" | dc run --rm --no-deps -T --entrypoint sh coord -c \
  'mkdir -p /var/lib/orblx && cat > /var/lib/orblx/policy.hujson'
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
  out="$(dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 600 \
    --out "/var/lib/orblx/tokens/${name}")"
  grep -E '^(wrote|token_id)' <<< "$out" || true
  out="$(dc run --rm --no-deps -T "$name" coord enroll --name "$name" --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem --token-file "/coord-state/tokens/${name}" \
    --state /var/lib/orblx --endpoint "${name}:443")"
  grep -E '^(enrolled|overlay|svid)' <<< "$out" || true
done
ADMIN=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)
LOCK=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)

echo "=== [C] owner sets up node lock (mTLS) ==="
out="$(owner lock keygen --out /var/lib/orblx/lock-owner.key)"
grep '^owner_key_fp' <<< "$out"
out="$(owner lock init --pub-file /var/lib/orblx/lock-owner.key.pub "${LOCK[@]}")"
printf '%s\n' "$out"
has_line '^coord_lock on version' "$out" || fail "the owner could not set up node lock"
out="$(owner lock sign a --key-file /var/lib/orblx/lock-owner.key "${LOCK[@]}")"
printf '%s\n' "$out"
# A second key that the token tries to add as a signer. The script does not print it.
out="$(owner lock keygen --out /var/lib/orblx/lock-other.key)"
grep '^owner_key_fp' <<< "$out"
OTHER_PUB="$(owner_sh 'tr -d "\n" < /var/lib/orblx/lock-other.key.pub')"
[[ ${#OTHER_PUB} -eq 64 ]] || fail "the second lock public key is not 64 characters"

echo "=== [C] owner creates tokens ==="
create_token() {
  owner admin token-create --scope "$2" --ttl "$3" --out "/tokens/$1" "${ADMIN[@]}"
}
ALL_SCOPES="nodes:read,nodes:write,grants:read,grants:write,audit:read,lock:read,lock:write,policy:read,policy:write"
out="$(create_token policy policy:write 10m)"; printf '%s\n' "$out"; POLICY_ID="$(field token_id "$out")"
out="$(create_token all "$ALL_SCOPES" 10m)"; printf '%s\n' "$out"; ALL_ID="$(field token_id "$out")"
[[ -n "$POLICY_ID" && -n "$ALL_ID" ]] || fail "no token id"

policy_before="$(policy_sha)"
echo "policy_sha256 before ${policy_before}"
a_is_refused || fail "node a is an owner before the token calls"

echo "=== [C] gate 1: token policy-set that touches the owners ==="
declare -A DENY_OWNERS=([policy]=0 [all]=0)
gate1_403=0
for token in policy all; do
  for kind in add remove change; do
    case "$kind" in
      add) text="$(policy_json "$OWNER_ID" "$A_ID")" ;;
      remove) text="$(policy_json)" ;;
      change) text="$(policy_json "$A_ID")" ;;
    esac
    status="$(client_call "$token" admin-policy-set "$text")"
    reason="$(awk '!/^status / {line = $0} END {print line}' "$WORK/last.txt")"
    echo "token ${token} owners_${kind} status ${status} want 403 (${reason})"
    [[ "$status" == 403 ]] || fail "KILL: token ${token} owners_${kind} gave ${status}"
    DENY_OWNERS[$token]=$((DENY_OWNERS[$token] + 1))
    gate1_403=$((gate1_403 + 1))
  done
done
policy_after="$(policy_sha)"
echo "policy_sha256 after ${policy_after}"
[[ "$policy_after" == "$policy_before" ]] || fail "KILL: the policy changed after the 403 calls"
a_is_refused || fail "KILL: node a became an owner"
out="$(owner admin nodes "${ADMIN[@]}")"
has_line '^node owner ' "$out" || fail "the owner lost admin access"
echo "gate1 refused_403 ${gate1_403} policy unchanged, owner still owner, a still not owner"

echo "=== [C] gate 2: token policy-set that keeps the owners ==="
keep_text="$(policy_json "$OWNER_ID" | sed 's/"proto": "udp"/"proto": "tcp"/')"
status="$(client_call policy admin-policy-set "$keep_text")"
echo "token policy keep_owners status ${status} want 200"
[[ "$status" == 200 ]] || fail "the keep-owners policy-set gave ${status}"
policy_keep="$(policy_sha)"
echo "policy_sha256 after_keep ${policy_keep}"
[[ "$policy_keep" != "$policy_before" ]] || fail "the keep-owners policy-set did not change the file"
out="$(owner admin policy "${ADMIN[@]}")"
has_line '"proto": "tcp"' "$out" || fail "the new policy text is not on the coordinator"
a_is_refused || fail "node a became an owner after the keep-owners set"
# The first policy again (same owners) is also 200.
status="$(client_call policy admin-policy-set "$(policy_json "$OWNER_ID")")"
echo "token policy same_owners_again status ${status} want 200"
[[ "$status" == 200 ]] || fail "the same-owners policy-set gave ${status}"
POLICY_USE=2

echo "=== [C] gate 3: node lock signers and token rules ==="
lock_before="$(coord_sha /var/lib/orblx/node-lock-store.json)"
tokens_before="$(coord_sha /var/lib/orblx/api-tokens.json)"
lock_show_before="$(owner lock show "${LOCK[@]}")"
list_before="$(owner admin token-list "${ADMIN[@]}")"
gate3_403=0
for op in admin-lock-init admin-lock-update admin-lock-sign admin-token-create admin-token-list admin-token-revoke; do
  case "$op" in
    admin-lock-init) arg="{\"keys\":[\"${OTHER_PUB}\"]}" ;;
    admin-lock-update) arg="{\"version\":2,\"action\":\"rotate\",\"keys\":[\"${OTHER_PUB}\"],\"prev\":\"\",\"sigs\":[]}" ;;
    admin-lock-sign) arg="{\"name\":\"a\",\"key_id\":\"${OTHER_PUB}\",\"sig\":\"00\"}" ;;
    admin-token-create) arg='{"scopes":["nodes:write","lock:write","policy:write"],"ttl_secs":600}' ;;
    admin-token-list) arg="" ;;
    admin-token-revoke) arg="$ALL_ID" ;;
  esac
  status="$(client_call policy "$op" "$arg")"
  echo "token policy op ${op} status ${status} want 403"
  [[ "$status" == 403 ]] || fail "KILL: op ${op} gave ${status}"
  gate3_403=$((gate3_403 + 1))
done
lock_after="$(coord_sha /var/lib/orblx/node-lock-store.json)"
tokens_after="$(coord_sha /var/lib/orblx/api-tokens.json)"
lock_show_after="$(owner lock show "${LOCK[@]}")"
list_after="$(owner admin token-list "${ADMIN[@]}")"
echo "lock_store_sha before ${lock_before:0:16} after ${lock_after:0:16}"
echo "token_store_sha before ${tokens_before:0:16} after ${tokens_after:0:16}"
printf '%s\n' "$lock_show_after"
[[ "$lock_before" == "$lock_after" && "$lock_show_before" == "$lock_show_after" ]] || fail "KILL: the node lock changed"
[[ "$tokens_before" == "$tokens_after" && "$list_before" == "$list_after" ]] || fail "KILL: the token store changed"
echo "gate3 refused_403 ${gate3_403} lock store unchanged, token store unchanged"

echo "=== [C] gate 4: owner SVID (mTLS) changes the owners ==="
policy_json "$OWNER_ID" "$A_ID" | owner_sh 'cat > /var/lib/orblx/owners-add.hujson'
out="$(owner admin policy-set /var/lib/orblx/owners-add.hujson "${ADMIN[@]}")"
printf '%s\n' "$out"
has_line '^policy_set ' "$out" || fail "the owner could not change the owners"
out="$(dc run --rm --no-deps -T a admin nodes "${ADMIN[@]}" 2>&1)" || fail "node a is not an owner after the owner change"
has_line '^node a ' "$out" || fail "node a admin nodes output"
echo "owner_mtls owners_add ok (mTLS reply ok, the 200 of this path), node a admin nodes ok"
policy_json "$OWNER_ID" | owner_sh 'cat > /var/lib/orblx/owners-back.hujson'
out="$(owner admin policy-set /var/lib/orblx/owners-back.hujson "${ADMIN[@]}")"
printf '%s\n' "$out"
a_is_refused || fail "node a is still an owner after the owner restore"
echo "owner_mtls owners_restore ok, node a refused again"

echo "=== [C] gate 5: audit records ==="
audit_json="$(owner admin audit --json "${ADMIN[@]}" 2>/dev/null)"
count() {
  local action="$1" id="$2" reason="${3:-}"
  jq -c --arg a "$action" --arg t "$id" --arg r "$reason" \
    'select(.action == $a and .target == $t and ($r == "" or (.detail | test("reason " + $r + " status 403$"))))' \
    <<< "$audit_json" | wc -l
}
check_count() {
  local got
  got="$(count "$1" "$2" "${4:-}")"
  echo "audit $1 $2 ${4:-any} ${got} want $3"
  [[ "$got" == "$3" ]] || fail "audit $1 $2 ${4:-} ${got} not $3"
}
check_count token-deny "$POLICY_ID" "${DENY_OWNERS[policy]}" owners
check_count token-deny "$ALL_ID" "${DENY_OWNERS[all]}" owners
check_count token-deny "$POLICY_ID" "$gate3_403" scope
check_count token-deny "$POLICY_ID" $((DENY_OWNERS[policy] + gate3_403))
check_count token-deny "$ALL_ID" "${DENY_OWNERS[all]}"
check_count token-use "$POLICY_ID" "$POLICY_USE"
check_count token-use "$ALL_ID" 0
jq -r 'select(.action | startswith("token-")) | "\(.action) \(.target) \(.detail)"' <<< "$audit_json" \
  | sort | uniq -c | sort -k2
out="$(owner admin audit --verify "${ADMIN[@]}")"
printf '%s\n' "$out"
has_line '^verify ok' "$out" || fail "audit --verify did not print ok"
verify_out="$(dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl)" \
  || fail "audit verify-config failed"
[[ "${verify_out%%$'\n'*}" == ok ]] || fail "audit verify-config did not print ok"
echo "audit verify-config ok $(grep '^records ' <<< "$verify_out" || true)"

echo "=== [C] revoke tokens ==="
for id in "$POLICY_ID" "$ALL_ID"; do
  out="$(owner admin token-revoke "$id" "${ADMIN[@]}")"
  grep '^revoked_token' <<< "$out"
done

echo "=== [C] gate 7: no token text in logs, audit records, or state files ==="
dc exec -T client sh -c 'for f in /tokens/policy /tokens/all; do cut -d. -f2 "$f"; done' > "$WORK/needles"
[[ "$(wc -l < "$WORK/needles")" -eq 2 ]] || fail "the token files are not readable"
hits_control="$(dc exec -T client sh -c 'cat > /tmp/needles; grep -lF -f /tmp/needles /tokens/policy /tokens/all | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
echo "secret_check control_token_files ${hits_control} want 2"
[[ "$hits_control" == 2 ]] || fail "the secret check does not find the token files"
hits_state="$(dc exec -T coord sh -c 'cat > /tmp/needles; grep -rlF -f /tmp/needles /var/lib/orblx | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
echo "secret_hits coord_state_files ${hits_state}"
dc logs --no-log-prefix > "$WORK/logs.txt" 2>&1 || true
hits_logs="$(grep -cF -f "$WORK/needles" "$WORK/logs.txt" || true)"
echo "secret_hits container_logs ${hits_logs} lines $(wc -l < "$WORK/logs.txt")"
hits_audit="$(grep -cF -f "$WORK/needles" <<< "$audit_json" || true)"
echo "secret_hits audit_records ${hits_audit}"
hits_proof=0
if [[ -n "${PROOF_LOG:-}" && -f "$PROOF_LOG" ]]; then
  hits_proof="$(grep -cF -f "$WORK/needles" "$PROOF_LOG" || true)"
  echo "secret_hits proof_log ${hits_proof}"
fi
rm -f "$WORK/needles"
[[ "$hits_state" == 0 && "$hits_logs" == 0 && "$hits_audit" == 0 && "$hits_proof" == 0 ]] || fail "a token text was found"

echo "proof_ok"
