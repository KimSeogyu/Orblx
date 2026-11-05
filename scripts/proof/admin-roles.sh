#!/usr/bin/env bash
# Admin role proof.
# The host is REAL. idp, coord, and tool are [C].
# The issuer is orblx-test-idp. The script does not read a real OAuth secret.
# The script does not print an enroll token, an ID token, an API token, or a private key.
# Gates are in docs/w25-admin-roles.md.
# Environment:
#   RBAC_PROJECT  Compose project (default orblx-admin-roles).
#   RBAC_IMAGE    Image tag (default orblx-admin-roles:local).
#   RBAC_BIN      An orblx binary. Without it, the script builds target/debug/orblx.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.admin-roles.yml"
RBAC_PROJECT="${RBAC_PROJECT:-orblx-admin-roles}"
RBAC_IMAGE="${RBAC_IMAGE:-orblx-admin-roles:local}"
WORK="$(mktemp -d)"
export POLICY_DIR="$WORK/policy"
export CONFIG_FILE="$WORK/coord.toml"
export IDP_CA_FILE="$WORK/idp-ca.pem"
STATE=/var/lib/orblx
ISSUER="https://idp:8443"
CLIENT="orblx-proof"
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
trap proof_lock_end EXIT
proof_lock_take "admin-roles" "$RBAC_PROJECT"
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "$RBAC_PROJECT" || exit 1
mkdir -p "$POLICY_DIR"
cp "$ROOT/scripts/proof/admin-roles.hujson" "$POLICY_DIR/policy.hujson"
cp "$ROOT/scripts/proof/admin-roles-next.hujson" "$POLICY_DIR/policy-next.hujson"
: >"$IDP_CA_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root env RBAC_IMAGE="$RBAC_IMAGE" POLICY_DIR="$POLICY_DIR" CONFIG_FILE="$CONFIG_FILE" \
    IDP_CA_FILE="$IDP_CA_FILE" \
    docker compose -p "$RBAC_PROJECT" --progress quiet --profile nodes -f "$FILE" "$@"
}

fail() {
  echo "proof_fail: $*" >&2
  dc logs --tail 40 coord 2>&1 | grep -v -e 'PRIVATE KEY' -e 'orblx-at1.' -e 'eyJ' >&2 || true
  exit 1
}

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap 'cleanup; proof_lock_end' EXIT

tool() {
  dc run --rm --no-deps --entrypoint orblx tool "$@"
}

idp() {
  dc run --rm --no-deps --entrypoint orblx-test-idp idp "$@"
}

mint() {
  idp mint --dir /idp --kid rs1 --issuer "$ISSUER" --aud "$CLIENT" --out "/tokens/$1" \
    --sub "$1" --email "$1@example.test" >/dev/null
}

wait_log() {
  local service="$1" needle="$2" i
  for i in $(seq 1 60); do
    if dc logs "$service" 2>&1 | read_all grep -q -- "$needle"; then
      return 0
    fi
    sleep 1
  done
  echo "The service ${service} did not print: ${needle}" >&2
  return 1
}

wait_bundle() {
  local i
  for i in $(seq 1 90); do
    if dc exec -T coord test -s "$STATE/trust-bundle.pem"; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  return 1
}

coord_ip() {
  dc run --rm --no-deps --entrypoint getent tool ahostsv4 coord \
    | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

# admin_as NAME ARGS... : one admin call from the node state /homes/NAME.
admin_as() {
  local name="$1"
  shift
  tool admin "$@" --coord "${COORD}:443" --state "/homes/${name}" --bundle "/homes/${name}/bundle.pem"
}

enroll_token() {
  local name="$1"
  tool coord enroll --name "$name" --coord "${COORD}:443" \
    --bundle /coord-state/trust-bundle.pem --token-file "/coord-state/tokens/${name}" \
    --state "/homes/${name}" --endpoint "${name}:443" >/dev/null
}

enroll_user() {
  local name="$1"
  tool coord enroll --name "${name}-pc" --coord "${COORD}:443" \
    --bundle /coord-state/trust-bundle.pem --id-token-file "/tokens/${name}" \
    --state "/homes/${name}" --endpoint "${name}-pc:443"
}

audit_count() {
  dc exec -T coord cat "$STATE/config-audit.jsonl" \
    | jq -c --arg action "$1" --arg target "$2" \
      'select(.action == $action and .target == $target)' \
    | wc -l
}

node_state() {
  local name="$1"
  admin_as owner nodes | read_all awk -v n="$name" '$1 == "node" && $2 == n {print $4; exit}'
}

echo "=== [REAL] host ==="
uname -sm

echo "=== [C] build image ${RBAC_IMAGE} ==="
bin="${RBAC_BIN:-}"
if [[ -z "$bin" ]]; then
  cargo build --release -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp --locked
  bin="$ROOT/target/release/orblx"
else
  cargo build --release -p orblx-test-idp --bin orblx-test-idp --locked
fi
[[ -x "$bin" ]] || fail "the orblx binary is missing"
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$bin")"
cp "$ROOT/target/release/orblx-test-idp" "$image_dir/orblx-test-idp"
printf '%s\n' 'COPY orblx-test-idp /usr/local/bin/orblx-test-idp' >>"$image_dir/Dockerfile"
as_root docker build -q -t "$RBAC_IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

cat >"$CONFIG_FILE" <<CONF
# [C] coordinator config for the admin role proof.
[oidc]
issuer = "${ISSUER}"
client_id = "${CLIENT}"
allowed_domains = ["example.test"]
allowed_emails = []
ca_file = "/etc/orblx/idp-ca.pem"
CONF

echo "=== [C] init test issuer ==="
idp init --dir /idp --host idp >/dev/null
dc run --rm --no-deps --entrypoint cat idp /idp/ca.pem >"$IDP_CA_FILE"
grep -q 'BEGIN CERTIFICATE' "$IDP_CA_FILE"
dc up -d idp
wait_log idp "idp serve"

echo "=== [C] start coordinator ==="
dc run --rm --no-deps --entrypoint sh coord -c 'mkdir -p /var/lib/orblx && cat > /var/lib/orblx/policy.hujson' \
  < "$POLICY_DIR/policy.hujson"
dc up -d coord
wait_bundle
wait_log coord "oidc issuer"
COORD="$(coord_ip)"
[[ -n "$COORD" ]] || fail "no coord address"
echo "coord_ip ${COORD}"

for name in owner pend pend2 pend3; do
  dc exec -T coord orblx coord token create --state "$STATE" --ttl 3600 \
    --out "$STATE/tokens/${name}" >/dev/null
  echo "token ${name} written"
done
enroll_token owner
echo "enrolled owner"
for name in ada ned ita aud mem olivia; do
  mint "$name"
done

echo "=== [C] enroll users ==="
# olivia is an owner user. She enrolls with no approval.
enroll_user olivia >/dev/null
echo "enrolled olivia"
for name in ada ned ita aud mem; do
  set +e
  out="$(enroll_user "$name" 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail "${name} enrolled while pending"
  printf '%s\n' "$out" | read_all grep -q 'waits for owner approval' || fail "${name} was not pending"
  echo "pending ${name}"
  admin_as owner user-approve "oidc:${name}" >/dev/null
  enroll_user "$name" >/dev/null
  echo "enrolled ${name}"
done
for name in pend pend2 pend3; do
  enroll_token "$name"
  echo "enrolled ${name}"
done

echo "=== [C] gate 1: member ==="
denies="$(audit_count role-deny nodes)"
set +e
mem_out="$(admin_as mem nodes 2>&1)"
mem_rc=$?
set -e
[[ "$mem_rc" -ne 0 ]] || fail "member admin nodes passed"
printf '%s\n' "$mem_out" | read_all grep -q 'The caller is not an owner.' || fail "member sentence"
[[ "$(audit_count role-deny nodes)" -eq $((denies + 1)) ]] || fail "member role-deny count"

echo "=== [C] gate 2: role-set ==="
admin_as owner role-set oidc:ada admin
admin_as owner role-set oidc:ned network-admin
admin_as owner role-set oidc:ita it-admin
admin_as owner role-set oidc:aud auditor
[[ "$(audit_count role-set oidc:ada)" -eq 1 ]] || fail "ada role-set count"
[[ "$(audit_count role-set oidc:ned)" -eq 1 ]] || fail "ned role-set count"
[[ "$(audit_count role-set oidc:ita)" -eq 1 ]] || fail "ita role-set count"
[[ "$(audit_count role-set oidc:aud)" -eq 1 ]] || fail "aud role-set count"
roles_out="$(admin_as owner roles)"
printf '%s\n' "$roles_out"
printf '%s\n' "$roles_out" | read_all grep -qx 'role ada approved admin' || fail "ada role"
printf '%s\n' "$roles_out" | read_all grep -qx 'role ned approved network-admin' || fail "ned role"
printf '%s\n' "$roles_out" | read_all grep -qx 'role ita approved it-admin' || fail "ita role"
printf '%s\n' "$roles_out" | read_all grep -qx 'role aud approved auditor' || fail "aud role"
printf '%s\n' "$roles_out" | read_all grep -qx 'role mem approved member' || fail "mem role"
printf '%s\n' "$roles_out" | read_all grep -qx 'role olivia approved owner' || fail "olivia role"

echo "=== [C] gate 3: auditor ==="
admin_as aud audit --verify | read_all grep -q '^verify ok ' || fail "auditor audit"
admin_as aud nodes >/dev/null
[[ "$(node_state pend)" == "pending" ]] || fail "pend was not pending"
set +e
aud_out="$(admin_as aud approve pend 2>&1)"
aud_rc=$?
set -e
[[ "$aud_rc" -ne 0 ]] || fail "auditor approve passed"
printf '%s\n' "$aud_out" | read_all grep -q 'role auditor' || fail "auditor sentence"
[[ "$(audit_count role-deny approve)" -eq 1 ]] || fail "auditor role-deny count"
[[ "$(node_state pend)" == "pending" ]] || fail "auditor approve changed pend"

echo "=== [C] gate 4: it admin and network admin ==="
admin_as ita approve pend >/dev/null
[[ "$(node_state pend)" == "approved" ]] || fail "it admin did not approve pend"
sha1="$(admin_as owner policy | read_all awk '/^policy_sha256 /{print $2; exit}')"
set +e
ita_pol="$(admin_as ita policy-set /policy/policy-next.hujson 2>&1)"
ita_pol_rc=$?
set -e
[[ "$ita_pol_rc" -ne 0 ]] || fail "it admin policy-set passed"
printf '%s\n' "$ita_pol" | read_all grep -q 'role it-admin' || fail "it admin policy sentence"
sha2="$(admin_as owner policy | read_all awk '/^policy_sha256 /{print $2; exit}')"
[[ "$sha1" == "$sha2" && -n "$sha1" ]] || fail "policy sha changed after it admin"
admin_as ned policy-set /policy/policy-next.hujson >/dev/null
sha3="$(admin_as owner policy | read_all awk '/^policy_sha256 /{print $2; exit}')"
[[ "$sha3" != "$sha1" && -n "$sha3" ]] || fail "network admin policy-set did not change the sha"
tokens_before="$(admin_as owner token-list | read_all awk '/^tokens /{print $2; exit}')"
set +e
ned_tok="$(admin_as ned token-create --scope nodes:write --ttl 10m --out /tokens/ned-bad 2>&1)"
ned_tok_rc=$?
set -e
[[ "$ned_tok_rc" -ne 0 ]] || fail "network admin created nodes:write"
printf '%s\n' "$ned_tok" | read_all grep -q 'cannot hold the scope nodes:write' || fail "network admin scope sentence"
set +e
ita_tok="$(admin_as ita token-create --scope policy:write --ttl 10m --out /tokens/ita-bad 2>&1)"
ita_tok_rc=$?
set -e
[[ "$ita_tok_rc" -ne 0 ]] || fail "it admin created policy:write"
printf '%s\n' "$ita_tok" | read_all grep -q 'cannot hold the scope policy:write' || fail "it admin scope sentence"
tokens_after="$(admin_as owner token-list | read_all awk '/^tokens /{print $2; exit}')"
[[ "$tokens_before" == "$tokens_after" ]] || fail "a refused create stored a token"

echo "=== [C] gate 5: token cap after demotion ==="
admin_as ita token-create --scope nodes:write --ttl 10m --out /tokens/ita-nodes >/dev/null
use_before="$(audit_count token-use "$(admin_as owner token-list | read_all awk '/^token /{id=$2} END{print id}')")"
# The new token is the last active token. Approve pend2 with it.
set +e
tok_out="$(tool admin approve pend2 --coord "${COORD}:443" --token-file /tokens/ita-nodes \
  --bundle /coord-state/trust-bundle.pem 2>&1)"
tok_rc=$?
set -e
printf '%s\n' "$tok_out" | read_all grep -q '^status 200 ' || fail "token approve before demotion: ${tok_rc}"
[[ "$(node_state pend2)" == "approved" ]] || fail "token did not approve pend2"
token_id="$(admin_as owner token-list | read_all awk '/^token /{id=$2} END{print id}')"
[[ -n "$token_id" ]] || fail "no token id"
admin_as owner role-set oidc:ita member
[[ "$(audit_count role-set oidc:ita)" -eq 2 ]] || fail "ita demotion count"
deny_before="$(audit_count role-deny approve)"
tdeny_before="$(audit_count token-deny "$token_id")"
set +e
late="$(tool admin approve pend3 --coord "${COORD}:443" --token-file /tokens/ita-nodes \
  --bundle /coord-state/trust-bundle.pem 2>&1)"
late_rc=$?
set -e
[[ "$late_rc" -ne 0 ]] || fail "demoted token approve passed"
printf '%s\n' "$late" | read_all grep -q '^status 403 ' || fail "demoted token status"
printf '%s\n' "$late" | read_all grep -q 'The caller is not an owner.' || fail "demoted token sentence"
[[ "$(audit_count role-deny approve)" -eq $((deny_before + 1)) ]] || fail "demotion role-deny count"
[[ "$(audit_count token-deny "$token_id")" -eq "$tdeny_before" ]] || fail "demotion wrote token-deny"
[[ "$(node_state pend3)" == "pending" ]] || fail "demoted token changed pend3"
# use_before is only a sanity read. The gate is the counts above.
echo "token_use_sample ${use_before}"

echo "=== [C] gate 5b: current role after demotion ==="
# ada is admin. The token holds nodes:read and nodes:write.
ada_out="$(admin_as ada token-create --scope nodes:read,nodes:write --ttl 10m --out /tokens/ada-nodes)"
ada_id="$(printf '%s\n' "$ada_out" | read_all awk '/^token_id /{print $2; exit}')"
[[ -n "$ada_id" ]] || fail "no ada token id"
echo "ada_token ${ada_id}"
ada_token() {
  local op="$1"
  shift
  tool admin "$op" "$@" --coord "${COORD}:443" --token-file /tokens/ada-nodes \
    --bundle /coord-state/trust-bundle.pem
}
admin_as owner role-set oidc:ada auditor
set +e
aud_read="$(ada_token nodes 2>&1)"
aud_read_rc=$?
set -e
printf '%s\n' "$aud_read" | read_all grep -q '^status 200 ' || fail "auditor token read: ${aud_read_rc}"
deny_approve="$(audit_count role-deny approve)"
set +e
aud_write="$(ada_token approve pend3 2>&1)"
aud_write_rc=$?
set -e
[[ "$aud_write_rc" -ne 0 ]] || fail "auditor token approve passed"
printf '%s\n' "$aud_write" | read_all grep -q '^status 403 ' || fail "auditor token status"
printf '%s\n' "$aud_write" | read_all grep -q 'role auditor' || fail "auditor token sentence"
[[ "$(audit_count role-deny approve)" -eq $((deny_approve + 1)) ]] || fail "auditor token role-deny"
[[ "$(node_state pend3)" == "pending" ]] || fail "auditor token changed pend3"
admin_as owner role-set oidc:ada member
deny_nodes="$(audit_count role-deny nodes)"
set +e
mem_read="$(ada_token nodes 2>&1)"
mem_read_rc=$?
set -e
[[ "$mem_read_rc" -ne 0 ]] || fail "member token read passed"
printf '%s\n' "$mem_read" | read_all grep -q '^status 403 ' || fail "member token status"
printf '%s\n' "$mem_read" | read_all grep -q 'The caller is not an owner.' || fail "member token sentence"
[[ "$(audit_count role-deny nodes)" -eq $((deny_nodes + 1)) ]] || fail "member token role-deny"
admin_as owner role-set oidc:ada admin
set +e
back="$(ada_token approve pend3 2>&1)"
back_rc=$?
set -e
printf '%s\n' "$back" | read_all grep -q '^status 200 ' || fail "promoted token approve: ${back_rc}"
[[ "$(node_state pend3)" == "approved" ]] || fail "promoted token did not approve pend3"
sha_pol="$(admin_as owner policy | read_all awk '/^policy_sha256 /{print $2; exit}')"
deny_pol="$(audit_count role-deny policy-set)"
tdeny_pol="$(audit_count token-deny "$ada_id")"
set +e
pol="$(ada_token policy-set /policy/policy-next.hujson 2>&1)"
pol_rc=$?
set -e
[[ "$pol_rc" -ne 0 ]] || fail "promoted token policy-set passed"
printf '%s\n' "$pol" | read_all grep -q '^status 403 ' || fail "promoted token policy status"
printf '%s\n' "$pol" | read_all grep -q 'does not have the scope' || fail "promoted token scope sentence"
sha_pol2="$(admin_as owner policy | read_all awk '/^policy_sha256 /{print $2; exit}')"
[[ "$sha_pol" == "$sha_pol2" && -n "$sha_pol" ]] || fail "promoted token changed the policy"
[[ "$(audit_count role-deny policy-set)" -eq "$deny_pol" ]] || fail "promoted token wrote role-deny"
[[ "$(audit_count token-deny "$ada_id")" -eq $((tdeny_pol + 1)) ]] || fail "promoted token scope record"

echo "=== [C] gate 6: owner user and a second owner ==="
set +e
olv="$(admin_as owner role-set oidc:olivia admin 2>&1)"
olv_rc=$?
set -e
[[ "$olv_rc" -ne 0 ]] || fail "olivia was demoted"
printf '%s\n' "$olv" | read_all grep -q 'owner user' || fail "olivia sentence"
admin_as owner roles | read_all grep -qx 'role olivia approved owner' || fail "olivia role changed"
# ada is admin. Move ada to owner, then back to admin. olivia stays owner, so ada is not the last owner.
admin_as owner role-set oidc:ada owner
admin_as owner role-set oidc:ada admin
[[ "$(audit_count role-set oidc:ada)" -eq 6 ]] || fail "ada second change count"
admin_as owner roles | read_all grep -qx 'role ada approved admin' || fail "ada did not return to admin"
set +e
ada_set="$(admin_as ada role-set oidc:mem admin 2>&1)"
ada_rc=$?
set -e
[[ "$ada_rc" -ne 0 ]] || fail "admin changed a role"
printf '%s\n' "$ada_set" | read_all grep -q 'role admin' || fail "admin role sentence"
[[ "$(audit_count role-deny role-set)" -eq 1 ]] || fail "admin role-deny count"

echo "=== [C] gate 7: secrets ==="
secret_hits=0
scan_file() {
  local label="$1"
  if printf '%s\n' "$2" | read_all grep -q -e 'orblx-at1.' -e 'PRIVATE KEY' -e 'eyJ'; then
    echo "secret hit ${label}" >&2
    secret_hits=$((secret_hits + 1))
  fi
}
scan_file audit "$(dc exec -T coord cat "$STATE/config-audit.jsonl")"
scan_file nodes "$(dc exec -T coord cat "$STATE/nodes.json")"
scan_file tokens "$(dc exec -T coord cat "$STATE/api-tokens.json" 2>/dev/null || true)"
scan_file coordlog "$(dc logs coord 2>&1 || true)"
if [[ -n "${PROOF_LOG:-}" && -f "${PROOF_LOG}" ]]; then
  scan_file prooflog "$(cat "$PROOF_LOG")"
fi
[[ "$secret_hits" -eq 0 ]] || fail "secret hits ${secret_hits}"
echo "secret_hits 0"

echo "=== [C] gate 8: chain ==="
admin_as owner audit --verify | read_all grep -q '^verify ok ' || fail "chain check"
echo "proof_ok"
