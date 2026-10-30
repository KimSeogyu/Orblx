#!/usr/bin/env bash
# W25-9 policy GitOps proof. The host is REAL. coord, owner, and ci are [C] containers.
# The ci container has no SVID. It runs ../steps.sh, the same steps as the example workflow.
# Gates:
#   1. `orblx policy diff` exits 0 when the file is the live policy and 1 when it differs.
#   2. A file with a failing policy test fails `steps.sh test`. `steps.sh apply` sends nothing.
#   3. `steps.sh apply` with a policy:write token gets 200. The live sha256 is the file sha256.
#   4. The same file again: changed false, the same policy file, no new policy-replace record.
#   5. A file that changes the owners gets 403. The live policy does not change.
#   6. A stale apply (the live policy changed after the diff) gets 409 and writes nothing.
#   7. No token text is in the proof log, the step output, GITHUB_OUTPUT, container logs,
#      the audit records, or the coordinator state. A control check finds a planted copy.
# The script never prints a token. It prints proof_ok.
# Environment:
#   GITOPS_PROJECT  Compose project name (default orblx-w25i-gitops-proof).
#   GITOPS_IMAGE    Image tag (default orblx-w25i-gitops:local).
#   GITOPS_BIN      An orblx binary. Without it, the script builds target/debug/orblx.
#   PROOF_LOG       The log file of this run. The secret check also reads this file.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../../scripts/proof/pipe-lib.sh"

HERE="$(cd "$(dirname "$0")" && pwd)"
EXAMPLE="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$EXAMPLE/../.." && pwd)"
cd "$ROOT"
FILE="$HERE/compose.yml"
GITOPS_PROJECT="${GITOPS_PROJECT:-orblx-w25i-gitops-proof}"
GITOPS_IMAGE="${GITOPS_IMAGE:-orblx-w25i-gitops:local}"
WORK="$(mktemp -d)"
ENV_FILE="$WORK/env"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take "policy-gitops" "$GITOPS_PROJECT"
printf 'GITOPS_IMAGE=%s\nGITOPS_EXAMPLE=%s\n' "$GITOPS_IMAGE" "$EXAMPLE" > "$ENV_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose -p "$GITOPS_PROJECT" --env-file "$ENV_FILE" --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the cleanup runs first, then the lock is released.
trap 'cleanup; proof_lock_end' EXIT

fail() {
  echo "proof_fail: $*" >&2
  echo "---- coord log (last 30 lines) ----" >&2
  dc logs --no-log-prefix coord 2>&1 | tail -n 30 >&2 || true
  exit 1
}

owner() {
  dc run --rm --no-deps -T owner "$@"
}

sha_of() {
  sha256sum "$1" | awk '{print $1}'
}

# live_sha: the live policy sha256 that the owner SVID reads.
live_sha() {
  local out
  out="$(owner admin policy "${ADMIN[@]}")"
  awk '/^policy_sha256 /{print $2; exit}' <<< "$out"
}

audit_json() {
  owner admin audit --json "${ADMIN[@]}" 2>/dev/null
}

# count_action ACTION [DETAIL_PREFIX]
count_action() {
  local text
  text="$(audit_json)"
  printf '%s\n' "$text" | jq -c --arg a "$1" --arg d "${2:-}" \
    'select(.action == $a and ((.detail // "") | startswith($d)))' | wc -l | tr -d ' '
}

# count_prefix PREFIX: records whose action starts with PREFIX.
count_prefix() {
  local text
  text="$(audit_json)"
  printf '%s\n' "$text" | jq -c --arg p "$1" 'select(.action | startswith($p))' | wc -l | tr -d ' '
}

policy_file_stat() {
  dc exec -T coord stat -c '%Y.%i %s' /var/lib/orblx/policy.hujson
}

# put NAME: copy $WORK/NAME into the ci container at /tmp/work/NAME.
put() {
  dc exec -T ci sh -c "mkdir -p /tmp/work && cat > /tmp/work/$1" < "$WORK/$1"
}

# ci_steps MODE NAME [ENV...]: run steps.sh in ci. Set CI_OUT and CI_RC.
ci_steps() {
  local mode="$1" name="$2"
  shift 2
  local envs=(-e "ORBLX_COORD=$COORD" -e ORBLX_BUNDLE=/coord-state/trust-bundle.pem
    -e ORBLX_READ_TOKEN_FILE=/tokens/read -e ORBLX_WRITE_TOKEN_FILE=/tokens/write
    -e GITHUB_OUTPUT=/tmp/work/github_output)
  for kv in "$@"; do envs+=(-e "$kv"); done
  set +e
  CI_OUT="$(dc exec -T "${envs[@]}" ci bash /example/steps.sh "$mode" "/tmp/work/$name" 2>&1)"
  CI_RC=$?
  set -e
  printf '%s\n' "$CI_OUT" >> "$WORK/step-output.txt"
  printf '%s\n' "$CI_OUT" | sed 's/^/  | /'
  echo "steps ${mode} ${name} exit ${CI_RC}"
}

# ci_diff NAME: run `orblx policy diff` in ci. Set CI_OUT and CI_RC.
ci_diff() {
  set +e
  CI_OUT="$(dc exec -T ci orblx policy diff --file "/tmp/work/$1" --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem --token-file /tokens/read 2>&1)"
  CI_RC=$?
  set -e
  printf '%s\n' "$CI_OUT" >> "$WORK/step-output.txt"
  printf '%s\n' "$CI_OUT" | sed 's/^/  | /'
  echo "diff ${1} exit ${CI_RC}"
}

status_of() {
  awk '/^status /{s=$2} END{print s ? s : "none"}' <<< "$1"
}

echo "=== [REAL] host ==="
uname -sm
other="$(as_root docker ps --format '{{.Names}}' | grep -c '^orblx' || true)"
echo "other_orblx_containers_at_start ${other}"

echo "=== [C] build image ${GITOPS_IMAGE} (project ${GITOPS_PROJECT}) ==="
bin="${GITOPS_BIN:-}"
if [[ -z "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --locked
  bin="$ROOT/target/debug/orblx"
fi
[[ -x "$bin" ]] || fail "the orblx binary $bin is missing"
# shellcheck source=../../../scripts/proof/stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$bin")"
as_root docker build -q -t "$GITOPS_IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] start coordinator with the example policy ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
dc run --rm --no-deps -T --entrypoint sh coord -c 'mkdir -p /var/lib/orblx && cat > /var/lib/orblx/policy.hujson' \
  < "$EXAMPLE/policy.hujson"
dc up -d coord ci
for _ in $(seq 1 60); do
  dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem && break
  sleep 1
done
dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem || fail "no trust bundle"
coord_ip="$(dc exec -T ci getent ahostsv4 coord | read_all awk '{print $1; exit}')"
COORD="${coord_ip}:443"
echo "coord ${COORD}"

echo "=== [C] enroll owner, make the CI tokens ==="
dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 600 \
  --out /var/lib/orblx/tokens/owner | grep -E '^(wrote|token_id)'
owner coord enroll --name owner --coord "$COORD" --bundle /coord-state/trust-bundle.pem \
  --token-file /coord-state/tokens/owner --state /var/lib/orblx --endpoint owner:443 \
  | grep -E '^(enrolled|overlay|svid)' || true
ADMIN=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)
owner admin token-create --scope policy:read --ttl 10m --out /tokens/read "${ADMIN[@]}"
owner admin token-create --scope policy:write --ttl 10m --out /tokens/write "${ADMIN[@]}"
dc exec -T ci sh -c 'stat -c "%a %n" /tokens/read /tokens/write; ls -A /var/lib/orblx 2>/dev/null | wc -l | sed "s/^/ci_node_state_files /"'

# The policy files of the proof. Each one is the example with one change.
cp "$EXAMPLE/policy.hujson" "$WORK/same.hujson"
sed 's|"dst": \["spiffe://orblx.local/node/owner:22"\]|"dst": ["spiffe://orblx.local/node/owner:22", "spiffe://orblx.local/node/owner:443"]|' \
  "$EXAMPLE/policy.hujson" > "$WORK/next.hujson"
sed 's|"deny": \["spiffe://orblx.local/node/owner:5432"\]|"deny": ["spiffe://orblx.local/node/owner:22"]|' \
  "$WORK/next.hujson" > "$WORK/bad.hujson"
sed 's|"owners": \["spiffe://orblx.local/node/owner"\]|"owners": ["spiffe://orblx.local/node/owner", "spiffe://orblx.local/node/a"]|' \
  "$WORK/next.hujson" > "$WORK/owners.hujson"
sed 's|owner:443"\]|owner:443", "spiffe://orblx.local/node/owner:8443"]|' "$WORK/next.hujson" > "$WORK/review.hujson"
sed 's|owner:443"\]|owner:443", "spiffe://orblx.local/node/owner:9000"]|' "$WORK/next.hujson" > "$WORK/hotfix.hujson"
for name in same next bad owners review hotfix; do
  echo "file ${name}.hujson sha256 $(sha_of "$WORK/$name.hujson")"
  put "$name.hujson"
done
[[ "$(sha_of "$WORK/next.hujson")" != "$(sha_of "$WORK/same.hujson")" ]] || fail "next.hujson is not changed"
[[ "$(sha_of "$WORK/review.hujson")" != "$(sha_of "$WORK/next.hujson")" ]] || fail "review.hujson is not changed"
[[ "$(sha_of "$WORK/hotfix.hujson")" != "$(sha_of "$WORK/next.hujson")" ]] || fail "hotfix.hujson is not changed"
grep -q 'node/a"\]' "$WORK/owners.hujson" || fail "owners.hujson is not changed"

live0="$(live_sha)"
echo "live_sha256 start ${live0}"
[[ "$live0" == "$(sha_of "$WORK/same.hujson")" ]] || fail "the start policy is not the example"

echo "=== [C] gate 1: policy diff exit codes ==="
ci_diff same.hujson
g1_same=$CI_RC
grep -q '^policy same$' <<< "$CI_OUT" || fail "diff same did not print policy same"
ci_diff next.hujson
g1_diff=$CI_RC
g1_line="$(grep '^policy differs' <<< "$CI_OUT" || true)"
grep -q '^+.*owner:443' <<< "$CI_OUT" || fail "diff did not show the added line"
echo "gate1 same_exit ${g1_same} want 0 differ_exit ${g1_diff} want 1 (${g1_line})"
[[ "$g1_same" == 0 && "$g1_diff" == 1 ]] || fail "gate 1"

echo "=== [C] gate 2: a failing policy test fails the check and applies nothing ==="
use_before="$(count_action token-use)"
replace_before="$(count_action policy-replace)"
ci_steps test bad.hujson
g2_test=$CI_RC
ci_steps apply bad.hujson
g2_apply=$CI_RC
grep -q '== step: policy diff' <<< "$CI_OUT" && fail "apply ran the diff after a failed test"
use_after="$(count_action token-use)"
replace_after="$(count_action policy-replace)"
live2="$(live_sha)"
echo "gate2 test_exit ${g2_test} apply_exit ${g2_apply} token_use ${use_before}->${use_after}" \
  "policy_replace ${replace_before}->${replace_after} live_unchanged $([[ "$live2" == "$live0" ]] && echo yes || echo no)"
[[ "$g2_test" == 1 && "$g2_apply" == 1 && "$use_after" == "$use_before" \
  && "$replace_after" == "$replace_before" && "$live2" == "$live0" ]] || fail "gate 2"

echo "=== [C] gate 3: merge apply with the policy:write token ==="
ci_steps apply next.hujson
g3_rc=$CI_RC
g3_status="$(status_of "$CI_OUT")"
live3="$(live_sha)"
next_sha="$(sha_of "$WORK/next.hujson")"
echo "gate3 exit ${g3_rc} status ${g3_status} live_sha256 ${live3} file_sha256 ${next_sha}"
[[ "$g3_rc" == 0 && "$g3_status" == 200 && "$live3" == "$next_sha" ]] || fail "gate 3"
grep -q 'changed true' <<< "$CI_OUT" || fail "gate 3 did not print changed true"
ci_diff next.hujson
[[ "$CI_RC" == 0 ]] || fail "gate 3: diff after apply is not 0"

echo "=== [C] gate 4: the same file again changes nothing ==="
stat_before="$(policy_file_stat)"
replace_before="$(count_action policy-replace)"
records_before="$(count_prefix policy-)"
sleep 1.1
ci_steps apply next.hujson
g4_rc=$CI_RC
g4_status="$(status_of "$CI_OUT")"
stat_after="$(policy_file_stat)"
replace_after="$(count_action policy-replace)"
records_after="$(count_prefix policy-)"
live4="$(live_sha)"
g4_changed="$(grep -o 'changed [a-z]*' <<< "$CI_OUT" | tail -n 1)"
echo "gate4 exit ${g4_rc} status ${g4_status} ${g4_changed} policy_file ${stat_before} -> ${stat_after}" \
  "policy_replace ${replace_before}->${replace_after} policy_records ${records_before}->${records_after}"
[[ "$g4_rc" == 0 && "$g4_status" == 200 && "$g4_changed" == "changed false" && "$stat_after" == "$stat_before" \
  && "$replace_after" == "$replace_before" && "$records_after" == "$records_before" && "$live4" == "$next_sha" ]] \
  || fail "gate 4"

echo "=== [C] gate 5: a token cannot change the owners ==="
replace_before="$(count_action policy-replace)"
ci_steps apply owners.hujson
g5_rc=$CI_RC
g5_status="$(status_of "$CI_OUT")"
live5="$(live_sha)"
replace_after="$(count_action policy-replace)"
deny_owners="$(count_action token-deny 'op policy-set scope policy:write reason owners')"
echo "gate5 exit ${g5_rc} status ${g5_status} live_unchanged $([[ "$live5" == "$next_sha" ]] && echo yes || echo no)" \
  "policy_replace ${replace_before}->${replace_after} token_deny_owners ${deny_owners}"
[[ "$g5_rc" == 1 && "$g5_status" == 403 && "$live5" == "$next_sha" && "$replace_after" == "$replace_before" \
  && "$deny_owners" == 1 ]] || fail "gate 5"

echo "=== [C] gate 6: a stale apply gets 409 ==="
ci_steps plan review.hujson
seen="$(awk '/^plan live_sha256 /{print $3}' <<< "$CI_OUT")"
echo "plan saw live_sha256 ${seen}"
[[ "$seen" == "$next_sha" ]] || fail "gate 6: the plan did not see the live sha"
# An owner changes the live policy after the review (owner SVID, mTLS).
hot_out="$(dc run --rm --no-deps -T --entrypoint sh owner -c \
  "cat > /tmp/hotfix.hujson && orblx admin policy-set /tmp/hotfix.hujson --coord $COORD --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem" \
  < "$WORK/hotfix.hujson")"
printf '%s\n' "$hot_out"
hot_sha="$(sha_of "$WORK/hotfix.hujson")"
[[ "$(live_sha)" == "$hot_sha" ]] || fail "gate 6: the owner change is not live"
replace_before="$(count_action policy-replace)"
ci_steps apply review.hujson "ORBLX_EXPECT_SHA=$seen"
g6_rc=$CI_RC
g6_status="$(status_of "$CI_OUT")"
live6="$(live_sha)"
replace_after="$(count_action policy-replace)"
echo "gate6 exit ${g6_rc} status ${g6_status} expect ${seen} live_sha256 ${live6} hotfix_sha256 ${hot_sha}" \
  "policy_replace ${replace_before}->${replace_after}"
[[ "$g6_rc" == 1 && "$g6_status" == 409 && "$live6" == "$hot_sha" && "$replace_after" == "$replace_before" ]] \
  || fail "gate 6"
grep -q 'live policy changed' <<< "$CI_OUT" || fail "gate 6: no conflict text"
# A new diff sees the owner change. Then the apply works.
ci_steps apply review.hujson
[[ "$CI_RC" == 0 && "$(live_sha)" == "$(sha_of "$WORK/review.hujson")" ]] || fail "gate 6: the apply after a new diff"
echo "gate6 after_new_diff status $(status_of "$CI_OUT") live_sha256 $(live_sha)"

echo "=== [C] audit chain ==="
verify_out="$(dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl)" \
  || fail "audit verify-config failed"
echo "audit verify-config $(head -n 1 <<< "$verify_out") $(grep '^records ' <<< "$verify_out" || true)"
echo "audit token-use policy-set $(count_action token-use 'op policy-set') policy $(count_action token-use 'op policy ')" \
  "token-deny $(count_action token-deny) policy-replace $(count_action policy-replace)"

echo "=== [C] gate 7: no token text anywhere ==="
# The full token text of both CI tokens. The script does not print it.
dc exec -T ci sh -c 'cat /tokens/read; echo; cat /tokens/write; echo' | grep -v '^$' > "$WORK/needles"
[[ "$(wc -l < "$WORK/needles")" -eq 2 ]] || fail "the token files are not readable"
dc exec -T ci sh -c 'cat /tmp/work/github_output' > "$WORK/github_output.txt"
dc logs --no-log-prefix > "$WORK/logs.txt" 2>&1 || true
audit_json > "$WORK/audit.txt"
hits() {
  grep -cF -f "$WORK/needles" "$1" || true
}
# Control: the same check finds a planted copy of each token.
cp "$WORK/step-output.txt" "$WORK/control.txt"
cat "$WORK/needles" >> "$WORK/control.txt"
h_control="$(hits "$WORK/control.txt")"
h_files="$(dc exec -T ci sh -c 'cat > /tmp/needles; grep -lF -f /tmp/needles /tokens/read /tokens/write | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
h_steps="$(hits "$WORK/step-output.txt")"
h_output="$(hits "$WORK/github_output.txt")"
h_logs="$(hits "$WORK/logs.txt")"
h_audit="$(hits "$WORK/audit.txt")"
h_state="$(dc exec -T coord sh -c 'cat > /tmp/needles; grep -rlF -f /tmp/needles /var/lib/orblx | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
h_proof=0
if [[ -n "${PROOF_LOG:-}" && -f "$PROOF_LOG" ]]; then
  h_proof="$(hits "$PROOF_LOG")"
fi
echo "gate7 control_planted ${h_control} want 2 control_token_files ${h_files} want 2"
echo "gate7 hits step_output ${h_steps} github_output ${h_output} container_logs ${h_logs}" \
  "audit_records ${h_audit} coord_state_files ${h_state} proof_log ${h_proof}"
echo "gate7 sizes step_output_lines $(wc -l < "$WORK/step-output.txt") log_lines $(wc -l < "$WORK/logs.txt")" \
  "audit_lines $(wc -l < "$WORK/audit.txt")"
rm -f "$WORK/needles" "$WORK/control.txt"
[[ "$h_control" == 2 && "$h_files" == 2 ]] || fail "gate 7: the control check did not find the tokens"
[[ "$h_steps" == 0 && "$h_output" == 0 && "$h_logs" == 0 && "$h_audit" == 0 && "$h_state" == 0 \
  && "$h_proof" == 0 ]] || fail "gate 7: a token text was found"

other_end="$(as_root docker ps --format '{{.Names}}' | grep '^orblx' | grep -vc "^${GITOPS_PROJECT}" || true)"
echo "other_orblx_containers_at_end ${other_end}"
echo "proof_ok"
