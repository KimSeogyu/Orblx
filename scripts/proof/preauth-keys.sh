#!/usr/bin/env bash
# Pre-auth key proof.
# The host is REAL. The containers are [C].
# The OIDC issuer is the test issuer (orblx-test-idp). The script uses no real secret.
# Gates:
#   1. An owner user enrolls with an ID token and is approved.
#   2. A pre-auth key is one use. A second enroll is refused.
#   3. A reusable key stops at its max use count.
#   4. An expired key, a revoked key, and an unknown key are refused.
#   5. A tag or a grant outside the caller rights is refused.
#      A token cannot set a tag. A token needs grants:write to set a grant.
#   6. A life outside 1 second to 1 hour is refused.
#   7. A pre-auth node is approved while node approval is on.
#      A token node stays pending until the owner approves it.
#   8. A grant inside the key ceiling is approved with no human approve.
#      A wider grant is refused.
#   9. An ephemeral node is removed at key expiry.
#      An ephemeral node is removed after 15 seconds offline.
#      The removal uses the existing deny path.
#  10. The key file and the key store are mode 0600.
#      The list, the audit, and the logs do not contain the key text.
#      Each create, use, deny, revoke, and removal has one audit record.
# The script does not print a pre-auth key, an enroll token, an ID token, or a private key.
# This proof was not run in the change that added it. Do not treat a missing proof_ok as a pass.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.preauth-keys.yml"
PROJECT="${PAK_PROJECT:-orblx-preauth-keys}"
IMAGE="${PAK_IMAGE:-orblx-preauth-keys:local}"
WORK="$(mktemp -d)"
export POLICY_DIR="$WORK/policy"
export CONFIG_FILE="$WORK/coord.toml"
export IDP_CA_FILE="$WORK/idp-ca.pem"
ISSUER="https://idp:8443"
CLIENT="orblx-proof"
STATE=/var/lib/orblx
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15 # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
trap proof_lock_end EXIT
proof_lock_take "preauth-keys" "$PROJECT"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "$PROJECT" || exit 1

mkdir -p "$POLICY_DIR"
cp "$ROOT/scripts/proof/preauth-keys.hujson" "$POLICY_DIR/policy.hujson"
: >"$IDP_CA_FILE"
cat >"$CONFIG_FILE" <<CONF
# [C] coordinator config for the pre-auth key proof.
[oidc]
issuer = "${ISSUER}"
client_id = "${CLIENT}"
allowed_domains = ["example.test"]
allowed_emails = []
ca_file = "/etc/orblx/idp-ca.pem"
CONF

dc() {
  as_root env POLICY_DIR="$POLICY_DIR" CONFIG_FILE="$CONFIG_FILE" IDP_CA_FILE="$IDP_CA_FILE" \
    PAK_IMAGE="$IMAGE" \
    docker compose -p "$PROJECT" --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs (tail, secrets removed) ----" >&2
    dc logs --tail 40 --no-log-prefix 2>&1 | grep -v -E 'orblx-pak1\.|ge1\.|PRIVATE KEY' >&2 || true
  fi
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap 'cleanup; proof_lock_end' EXIT

fail() {
  echo "proof_fail: $*" >&2
  exit 1
}

# Print text only when it has no key prefix and no private key.
show_safe() {
  local text="$1"
  if printf '%s\n' "$text" | read_all grep -q -E 'orblx-pak1\.|ge1\.|PRIVATE KEY'; then
    fail "the command output contains a secret"
  fi
  printf '%s\n' "$text"
}

coord_file() {
  dc exec -T coord cat "$STATE/$1"
}

owner() {
  dc run --rm --no-deps -T --entrypoint orblx owner "$@"
}

# enroll_id SERVICE NAME ID_TOKEN_FILE STATE
# An OIDC ID token uses --id-token-file. A pre-auth key uses --token-file.
enroll_id() {
  local service="$1" name="$2" token_file="$3" state="$4"
  owner_ip_enroll "$service" coord enroll --name "$name" --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem --id-token-file "$token_file" \
    --state "$state" --endpoint "${name}:443"
}

# enroll_node SERVICE NAME TOKEN_FILE STATE
enroll_node() {
  local service="$1" name="$2" token_file="$3" state="$4"
  owner_ip_enroll "$service" coord enroll --name "$name" --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem --token-file "$token_file" \
    --state "$state" --endpoint "${name}:443"
}

owner_ip_enroll() {
  dc run --rm --no-deps -T --entrypoint orblx "$@"
}

node_state() {
  local name="$1" out
  out="$(owner admin nodes --coord "$COORD" --state "$STATE" --bundle "$STATE/bundle.pem")"
  printf '%s\n' "$out" | read_all awk -v name="$name" '$1 == "node" && $2 == name { print $4 }'
}

wait_state() {
  local name="$1" want="$2" i state
  for i in $(seq 1 40); do
    state="$(node_state "$name")"
    if [[ "$state" == "$want" ]]; then
      echo "node ${name} ${want}"
      return 0
    fi
    sleep 1
  done
  echo "node ${name} is ${state:-missing}, not ${want}" >&2
  return 1
}

echo "=== [REAL] host ==="
uname -sm

echo "=== [C] build release image ${IMAGE} ==="
# W25-35: this proof has a time limit, so the binary is a release build.
cargo build --release -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp --locked
# shellcheck source=scripts/proof/stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$ROOT/target/release/orblx")"
cp "$ROOT/target/release/orblx-test-idp" "$image_dir/orblx-test-idp"
printf '%s\n' 'COPY orblx-test-idp /usr/local/bin/orblx-test-idp' >>"$image_dir/Dockerfile"
as_root docker build -q -t "$IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] start the test issuer ==="
dc run --rm --no-deps --entrypoint orblx-test-idp idp init --dir /idp --host idp >/dev/null
dc run --rm --no-deps --entrypoint cat idp /idp/ca.pem >"$IDP_CA_FILE"
grep -q 'BEGIN CERTIFICATE' "$IDP_CA_FILE"
dc up -d idp
for _ in $(seq 1 30); do
  if dc logs idp 2>&1 | read_all grep -q 'idp serve'; then
    break
  fi
  sleep 1
done
dc logs idp 2>&1 | read_all grep -q 'idp serve' || fail "the test issuer did not start"
dc run --rm --no-deps --entrypoint orblx-test-idp idp mint --dir /idp --kid rs1 \
  --issuer "$ISSUER" --aud "$CLIENT" --out /tokens/owner \
  --sub owner --email owner@example.test >/dev/null

echo "=== [C] start the coordinator ==="
dc up -d coord
for _ in $(seq 1 60); do
  if dc exec -T coord test -s "$STATE/trust-bundle.pem"; then
    break
  fi
  sleep 1
done
dc exec -T coord test -s "$STATE/trust-bundle.pem" || fail "no trust bundle"
COORD="$(dc run --rm --no-deps -T --entrypoint getent owner ahostsv4 coord | read_all awk '{print $1; exit}')"
COORD="${COORD}:443"
echo "coord ${COORD}"

echo "=== [C] gate 1: owner user enrolls ==="
show_safe "$(enroll_id owner owner /tokens/owner "$STATE")"
[[ "$(node_state owner)" == "approved" ]] || fail "the owner user is not approved"

ADMIN=(--coord "$COORD" --state "$STATE" --bundle "$STATE/bundle.pem")

echo "=== [C] gate 7: a token node waits; a pre-auth node does not ==="
dc exec -T coord mkdir -p "$STATE/tokens"
dc exec -T coord orblx coord token create --state "$STATE" --ttl 600 \
  --out "$STATE/tokens/srv" | read_all grep -E '^(wrote|token_id)'
show_safe "$(dc run --rm --no-deps -T --entrypoint orblx srv coord enroll --name srv \
  --coord "$COORD" --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/srv --state "$STATE" --endpoint srv:443)"
[[ "$(node_state srv)" == "pending" ]] || fail "the token node did not wait"
owner admin approve srv "${ADMIN[@]}"
[[ "$(node_state srv)" == "approved" ]] || fail "the owner did not approve srv"

create_key() {
  owner admin preauth-create "$@" "${ADMIN[@]}"
}

echo "=== [C] gate 2: one use ==="
show_safe "$(create_key --ttl 10m --out /keys/one)"
mode="$(dc run --rm --no-deps -T --entrypoint stat owner -c %a /keys/one)"
[[ "$mode" == "600" ]] || fail "the key file mode is ${mode}"
show_safe "$(enroll_node agent bot /keys/one /work/bot)"
[[ "$(node_state bot)" == "approved" ]] || fail "the pre-auth node is not approved"
set +e
second="$(enroll_node agent bot2 /keys/one /work/bot2 2>&1)"
second_rc=$?
set -e
[[ "$second_rc" -ne 0 ]] || fail "the one-use key enrolled a second node"
printf '%s\n' "$second" | read_all grep -q 'used up' || fail "the second enroll was not used up"
echo "one-use second enroll refused"

echo "=== [C] gate 3: reusable key ==="
show_safe "$(create_key --ttl 10m --uses 2 --out /keys/two)"
show_safe "$(enroll_node agent r1 /keys/two /work/r1)"
show_safe "$(enroll_node agent r2 /keys/two /work/r2)"
set +e
third="$(enroll_node agent r3 /keys/two /work/r3 2>&1)"
third_rc=$?
set -e
[[ "$third_rc" -ne 0 ]] || fail "the reusable key enrolled a third node"
printf '%s\n' "$third" | read_all grep -q 'used up' || fail "the third enroll was not used up"
echo "reusable key stopped at 2 uses"

echo "=== [C] gate 4: expired, revoked, unknown ==="
show_safe "$(create_key --ttl 3s --out /keys/short)"
sleep 4
set +e
late="$(enroll_node agent late /keys/short /work/late 2>&1)"
late_rc=$?
set -e
[[ "$late_rc" -ne 0 ]] || fail "the expired key enrolled a node"
printf '%s\n' "$late" | read_all grep -q 'expired' || fail "the late enroll was not expired"
echo "expired key refused"
stop_made="$(create_key --ttl 10m --out /keys/stop)"
show_safe "$stop_made"
stop_id="$(printf '%s\n' "$stop_made" | read_all awk '/^preauth_id /{print $2}')"
show_safe "$(owner admin preauth-revoke "$stop_id" "${ADMIN[@]}")"
set +e
rev="$(enroll_node agent revoked /keys/stop /work/revoked 2>&1)"
rev_rc=$?
set -e
[[ "$rev_rc" -ne 0 ]] || fail "the revoked key enrolled a node"
printf '%s\n' "$rev" | read_all grep -q 'revoked' || fail "the revoked enroll was not revoked"
echo "revoked key refused"
dc run --rm --no-deps -T --entrypoint sh agent -c \
  'umask 077; printf "%s\n" "orblx-pak1.not-a-real-key" > /work/unknown-key'
set +e
bad="$(enroll_node agent nope /work/unknown-key /work/nope 2>&1)"
bad_rc=$?
set -e
[[ "$bad_rc" -ne 0 ]] || fail "the unknown key enrolled a node"
printf '%s\n' "$bad" | read_all grep -q 'not valid' || fail "the unknown key was not refused"
echo "unknown key refused"

echo "=== [C] gate 5 and 6: tag, grant, and life bounds ==="
set +e
tag_out="$(create_key --ttl 10m --tag tag:other --out /keys/bad-tag 2>&1)"
tag_rc=$?
set -e
[[ "$tag_rc" -ne 0 ]] || fail "a tag outside the caller was accepted"
printf '%s\n' "$tag_out" | read_all grep -q 'outside the caller rights' || fail "the tag deny text is wrong"
echo "foreign tag refused"
set +e
life_out="$(owner admin call admin-preauth-create '{"ttl_secs":7200}' "${ADMIN[@]}" 2>&1)"
life_rc=$?
set -e
[[ "$life_rc" -ne 0 ]] || fail "a 2 hour key was accepted"
printf '%s\n' "$life_out" | read_all grep -q 'not valid' || fail "the life deny text is wrong"
echo "long life refused"
show_safe "$(owner admin token-create --scope nodes:write --ttl 10m --out /keys/write-only "${ADMIN[@]}")"
show_safe "$(owner admin token-create --scope nodes:write,grants:write --ttl 10m --out /keys/grants "${ADMIN[@]}")"
set +e
tok_tag="$(owner admin preauth-create --ttl 10m --tag tag:bot --out /keys/tok-tag \
  --token-file /keys/grants --coord "$COORD" --bundle /coord-state/trust-bundle.pem 2>&1)"
tok_tag_rc=$?
set -e
[[ "$tok_tag_rc" -ne 0 ]] || fail "a token set a tag"
echo "token tag refused"
set +e
tok_grant="$(owner admin preauth-create --ttl 10m --grant srv,web,8080,30 --out /keys/tok-grant \
  --token-file /keys/write-only --coord "$COORD" --bundle /coord-state/trust-bundle.pem 2>&1)"
tok_grant_rc=$?
set -e
[[ "$tok_grant_rc" -ne 0 ]] || fail "a token without grants:write set a grant"
echo "token grant without grants:write refused"
show_safe "$(owner admin preauth-create --ttl 10m --grant srv,web,8080,30 --out /keys/tok-ok \
  --token-file /keys/grants --coord "$COORD" --bundle /coord-state/trust-bundle.pem)"
echo "token with grants:write set a grant ceiling"

echo "=== [C] gate 8: grant ceiling ==="
show_safe "$(create_key --ttl 10m --grant srv,web,8080,30 --out /keys/ceil)"
show_safe "$(enroll_node agent grantbot /keys/ceil /work/grantbot)"
set +e
wide="$(dc run --rm --no-deps -T --entrypoint orblx agent agent grant request \
  --agent grantbot --node srv --service web --port 8080 --ttl 31 \
  --coord "$COORD" --state /work/grantbot --bundle /work/grantbot/bundle.pem 2>&1)"
wide_rc=$?
set -e
[[ "$wide_rc" -ne 0 ]] || fail "a wider grant was accepted"
printf '%s\n' "$wide" | read_all grep -q 'outside the pre-auth key' || fail "the wide grant text is wrong"
echo "wider grant refused"
fit="$(dc run --rm --no-deps -T --entrypoint orblx agent agent grant request \
  --agent grantbot --node srv --service web --port 8080 --ttl 30 \
  --coord "$COORD" --state /work/grantbot --bundle /work/grantbot/bundle.pem)"
show_safe "$fit"
grant_id="$(printf '%s\n' "$fit" | read_all awk '/^grant_id /{print $2}')"
printf '%s\n' "$fit" | read_all grep -q 'grant_state approved' || fail "the grant was not approved"
fetch="$(dc run --rm --no-deps -T --entrypoint orblx agent agent grant fetch \
  --id "$grant_id" --out /work/grantbot/out \
  --coord "$COORD" --state /work/grantbot --bundle /work/grantbot/bundle.pem)"
show_safe "$fetch"
printf '%s\n' "$fetch" | read_all grep -q 'grant_state issued' || fail "the grant was not issued"
key_mode="$(dc run --rm --no-deps -T --entrypoint stat agent -c %a /work/grantbot/out/agent.key.pem)"
[[ "$key_mode" == "600" ]] || fail "the agent key mode is ${key_mode}"

echo "=== [C] gate 9: ephemeral removal ==="
show_safe "$(create_key --ttl 4s --ephemeral --out /keys/ending)"
show_safe "$(enroll_node agent ending /keys/ending /work/ending)"
wait_state ending removed
show_safe "$(create_key --ttl 30m --ephemeral --out /keys/quiet)"
show_safe "$(enroll_node agent quiet /keys/quiet /work/quiet)"
sleep 20
wait_state quiet removed
svid="$(coord_file nodes.json | jq -r '.nodes[] | select(.name == "quiet") | .svid')"
[[ -n "$svid" && "$svid" != null ]] || fail "the removed node has no SVID"
coord_file deny.json | read_all grep -q -F -- "$svid" || fail "the deny list has no SVID for quiet"
echo "ephemeral nodes removed and the SVID is denied"

echo "=== [C] gate 10: store, list, and audit ==="
store_mode="$(dc exec -T coord stat -c %a "$STATE/preauth-keys.json")"
[[ "$store_mode" == "600" ]] || fail "the key store mode is ${store_mode}"
list_out="$(owner admin preauth-list "${ADMIN[@]}")"
show_safe "$list_out"
printf '%s\n' "$list_out" | read_all grep -q '^preauth ' || fail "the list is empty"
uses="$(coord_file config-audit.jsonl | jq -r 'select(.action == "preauth-use") | .action' | wc -l)"
creates="$(coord_file config-audit.jsonl | jq -r 'select(.action == "preauth-create") | .action' | wc -l)"
revokes="$(coord_file config-audit.jsonl | jq -r 'select(.action == "preauth-revoke") | .action' | wc -l)"
removes="$(coord_file config-audit.jsonl | jq -r 'select(.action == "node-remove") | .target' )"
echo "audit preauth-create ${creates} preauth-use ${uses} preauth-revoke ${revokes}"
# Successful enrolls: bot, r1, r2, grantbot, ending, quiet. The token ceiling key is not enrolled.
[[ "$uses" -eq 6 ]] || fail "preauth-use count is ${uses}"
[[ "$creates" -eq 8 ]] || fail "preauth-create count is ${creates}"
[[ "$revokes" -eq 1 ]] || fail "preauth-revoke count is ${revokes}"
remove_eq() {
  local target="$1" want="$2" got
  got="$(coord_file config-audit.jsonl | jq -r --arg target "$target" \
    'select(.action == "node-remove" and .target == $target) | .target' | wc -l)"
  [[ "$got" -eq "$want" ]] || fail "node-remove ${target} count is ${got}, want ${want}"
}
deny_eq() {
  local reason="$1" want="$2" got
  got="$(coord_file config-audit.jsonl | jq -r --arg reason "$reason" \
    'select(.action == "preauth-deny" and .detail == ("reason " + $reason)) | .action' | wc -l)"
  [[ "$got" -eq "$want" ]] || fail "preauth-deny ${reason} count is ${got}, want ${want}"
}
remove_eq ending 1
remove_eq quiet 1
[[ "$(printf '%s\n' "$removes" | wc -l)" -eq 2 ]] || fail "node-remove count is not 2"
coord_file config-audit.jsonl | jq -r 'select(.action == "node-remove" and .target == "ending") | .detail' \
  | read_all grep -q 'reason expiry' || fail "ending removal is not expiry"
coord_file config-audit.jsonl | jq -r 'select(.action == "node-remove" and .target == "quiet") | .detail' \
  | read_all grep -q 'reason grace' || fail "quiet removal is not grace"
# One record for each single gate. Two records where the script refuses twice.
deny_eq used 2
deny_eq expired 1
deny_eq revoked 1
deny_eq unknown 1
deny_eq tag 2
deny_eq grant 2
deny_eq life 1
owner admin audit --verify "${ADMIN[@]}" | read_all grep -q '^verify ok ' || fail "the audit chain check failed"
scan="$(
  dc logs --no-log-prefix 2>&1 || true
  coord_file config-audit.jsonl
  coord_file preauth-keys.json
  coord_file nodes.json
  coord_file deny.json
)"
if printf '%s\n' "$scan" | read_all grep -q -E 'orblx-pak1\.|PRIVATE KEY'; then
  fail "a log or a state file contains a key or a private key"
fi
if [[ -n "${PROOF_LOG:-}" ]] && read_all grep -q -E 'orblx-pak1\.|PRIVATE KEY' <"$PROOF_LOG"; then
  fail "the proof log contains a key or a private key"
fi
echo "secret scan clean"
echo "proof_ok"
