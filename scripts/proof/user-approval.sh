#!/usr/bin/env bash
# User approval proof (W25-15).
# Phase M (migration): a coordinator from before W25-15 (OLD_ORBLX, [C] a main build with no
#   user approval) enrolls owner and srv with tokens and mia-pc with an ID token of user mia.
#   Then the script starts the new coordinator on the same store. mia is approved with no action
#   and 1 user-approve record (detail "store migration"): mia-pc works and mia enrolls a second node.
# Gate 1: user nina (verified email in an allowed domain) enrolls. The coordinator refuses:
#   no SVID, no node, and node srv counts 0 bytes from her container.
# Gate 2: orblx admin users shows nina pending. user-reject rex keeps rex blocked.
#   user-approve nina: the nina-pc container waits with --wait-approval, enrolls, and starts.
#   The script measures the time from the approve command to the first HTTP 200 from srv.
#   Each action writes 1 audit record. The chain verifies.
# Gate 4: owner user olivia never waits and cannot be rejected. Auto-approve is off by
#   default. A policy with autoApproveDomains approves a verified email in that domain.
# Gate 5: the logs hold no enroll token, ID token, or private key.
# The script does not print enroll tokens, ID tokens, private keys, or tickets.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.user-approval.yml"
WORK="$(mktemp -d)"
export POLICY_DIR="$WORK/policy"
export CONFIG_FILE="$WORK/coord.toml"
export IDP_CA_FILE="$WORK/idp-ca.pem"
export COORD_ADDR="127.0.0.1:443"
export COORD_IMAGE="orblx-w25o-users:old"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
OLD_ORBLX="${OLD_ORBLX:?set OLD_ORBLX to an orblx binary from before W25-15}"
ISSUER="https://idp:8443"
CLIENT="orblx-proof"
REACH_LIMIT_MS="${ORBLX_UA_REACH_LIMIT_MS:-2000}"
STATE=/var/lib/orblx
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=12  # reason: the floor (PROOF_DISK_FLOOR_GIB): one build output and one proof image. No bigger measure for this proof.
trap proof_lock_end EXIT
proof_lock_take "user-approval"
mkdir -p "$POLICY_DIR"
: >"$IDP_CA_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root env POLICY_DIR="$POLICY_DIR" CONFIG_FILE="$CONFIG_FILE" IDP_CA_FILE="$IDP_CA_FILE" \
    COORD_ADDR="$COORD_ADDR" COORD_IMAGE="$COORD_IMAGE" \
    docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-w25o-users" || exit 1

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs (tail) ----"
    dc logs --tail 40 2>&1 | grep -v 'PRIVATE KEY' || true
  fi
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the stack for debug."
    return
  fi
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap 'cleanup; proof_lock_end' EXIT

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
  local tag="$1" bin="$2" image_dir
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  cp "$TARGET_DIR/debug/orblx-test-idp" "$image_dir/orblx-test-idp"
  printf '%s\n' 'COPY orblx-test-idp /usr/local/bin/orblx-test-idp' >>"$image_dir/Dockerfile"
  as_root docker build -q -t "$tag" "$image_dir" >/dev/null
  rm -rf "$image_dir"
}

now_ms() {
  date +%s%3N
}

put_policy() {
  cp "$1" "$POLICY_DIR/.next.hujson"
  mv -f "$POLICY_DIR/.next.hujson" "$POLICY_DIR/policy.hujson"
}

idp() {
  dc run --rm --no-deps --entrypoint orblx-test-idp idp "$@"
}

# mint USER: one ID token for USER@example.test (email_verified true) at /tokens/USER.
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
    if dc exec -T coord cat "$STATE/trust-bundle.pem" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "The coordinator did not write the trust bundle." >&2
  return 1
}

run_node() {
  local service="$1"
  shift
  dc run --rm --no-deps --entrypoint orblx "$service" "$@"
}

owner() {
  run_node owner admin "$@" --coord "${coord_ip}:443" --state "$STATE" --bundle "$STATE/bundle.pem"
}

# enroll_user SERVICE NODE USER STATE_DIR: one OIDC enroll. Prints the output. Keeps the exit code.
enroll_user() {
  run_node "$1" coord enroll --name "$2" --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem --id-token-file "/tokens/$3" \
    --state "$4" --endpoint "$2:443"
}

# expect_refused LABEL TEXT SERVICE NODE USER STATE_DIR
expect_refused() {
  local label="$1" text="$2" out status
  shift 2
  set +e
  out="$(enroll_user "$@" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$out" | grep -v -i 'token' | sed "s/^/  ${label}: /"
  if [[ "$status" -eq 0 ]]; then
    echo "The coordinator enrolled ${label}." >&2
    exit 1
  fi
  printf '%s\n' "$out" | read_all grep -qF -- "$text"
  echo "check ${label} refused exit ${status}"
}

coord_file() {
  dc exec -T coord cat "$STATE/$1"
}

audit_count() {
  # audit_count ACTION TARGET: the config-audit records with this action and target.
  coord_file config-audit.jsonl \
    | jq -s --arg a "$1" --arg t "$2" '[.[] | select(.action == $a and .target == $t)] | length'
}

records() {
  owner audit --verify | awk '$1 == "verify" && $2 == "ok" {print $4}'
}

has_node() {
  coord_file nodes.json | jq -e --arg n "$1" '[.nodes[] | select(.name == $n)] | length > 0' >/dev/null
}

user_line() {
  printf '%s\n' "$users_out" | read_all awk -v u="$1" '$1 == "user" && $2 == u'
}

get() {
  dc exec -T "$1" python3 /tmp/share-get.py "$2" "$3" 0.8
}

wait_path() {
  local from="$1" to="$2" i
  for i in $(seq 1 60); do
    if dc exec -T "$from" orblx status --state-dir "$STATE" 2>/dev/null \
      | read_all grep -q "^peer ${to} .* path direct "; then
      echo "path ${from} ${to} direct"
      return 0
    fi
    sleep 1
  done
  echo "The path from ${from} to ${to} did not come up." >&2
  return 1
}

copy_tools() {
  dc exec -T "$1" sh -c "cat > /tmp/share-get.py" <"$ROOT/scripts/proof/share-get.py"
  dc exec -T "$1" sh -c "cat > /tmp/share-sink.py" <"$ROOT/scripts/proof/share-sink.py"
}

# Policies. old.hujson has no userApproval key: the old coordinator does not know it.
grep -v 'userApproval\|ownerUsers\|^  },$' "$ROOT/scripts/proof/user-approval.hujson" >"$WORK/old.hujson"
cp "$ROOT/scripts/proof/user-approval.hujson" "$WORK/new.hujson"
sed 's/"ownerUsers": \["oidc:olivia"\],/"ownerUsers": ["oidc:olivia"], "autoApproveDomains": ["example.test"],/' \
  "$WORK/new.hujson" >"$WORK/auto.hujson"
cmp -s "$WORK/new.hujson" "$WORK/auto.hujson" && { echo "The auto policy did not change." >&2; exit 1; }
grep -q userApproval "$WORK/old.hujson" && { echo "The old policy has userApproval." >&2; exit 1; }
put_policy "$WORK/old.hujson"
cat >"$CONFIG_FILE" <<CONF
# [C] coordinator config for the user approval proof.
[oidc]
issuer = "${ISSUER}"
client_id = "${CLIENT}"
allowed_domains = ["example.test"]
allowed_emails = []
ca_file = "/etc/orblx/idp-ca.pem"
CONF

echo "=== [C] remove old proof volumes ==="
dc down -v --remove-orphans || true
open_legacy_forward

echo "=== [C] build images ==="
cargo build -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp --locked
build_image orblx-w25o-users:new "$TARGET_DIR/debug/orblx"
build_image orblx-w25o-users:old "$OLD_ORBLX"
old_has="$(as_root docker run --rm --entrypoint orblx orblx-w25o-users:old admin --help 2>&1 | grep -c 'user-approve' || true)"
new_has="$(as_root docker run --rm --entrypoint orblx orblx-w25o-users:new admin --help 2>&1 | grep -c 'user-approve' || true)"
echo "image old user_approve_help ${old_has} new user_approve_help ${new_has}"
[[ "$old_has" -eq 0 && "$new_has" -ge 1 ]]

echo "=== [C] init test issuer ==="
idp init --dir /idp --host idp >/dev/null
dc run --rm --no-deps --entrypoint cat idp /idp/ca.pem >"$IDP_CA_FILE"
grep -q 'BEGIN CERTIFICATE' "$IDP_CA_FILE"
dc up -d idp
wait_log idp "idp serve"

echo "=== [C] phase M: old coordinator (no user approval) ==="
dc up -d coord
wait_bundle
wait_log coord "oidc issuer"
for name in owner srv; do
  dc exec -T coord orblx coord token create --state "$STATE" --ttl 3600 \
    --out "$STATE/tokens/${name}" >/dev/null
  echo "token ${name} written"
done
coord_ip="$(dc run --rm --no-deps --entrypoint getent owner ahostsv4 coord \
  | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}')"
[[ -n "$coord_ip" ]]
echo "coord_ip ${coord_ip}"
export COORD_ADDR="${coord_ip}:443"
for name in owner srv; do
  run_node "$name" coord enroll --name "$name" --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" --endpoint "${name}:443" >/dev/null
  echo "enrolled ${name} with a token"
done
mint mia
enroll_user mia-pc mia-pc mia "$STATE" >/dev/null
echo "enrolled mia-pc as oidc:mia (old coordinator, no approval)"
old_users_key="$(coord_file nodes.json | jq 'has("users")')"
echo "old_store has_users_key ${old_users_key}"
[[ "$old_users_key" == false ]]

echo "=== [C] phase M: new coordinator on the same store ==="
dc stop coord >/dev/null
put_policy "$WORK/new.hujson"
export COORD_IMAGE="orblx-w25o-users:new"
dc up -d coord
wait_bundle
wait_log coord "user migration approved"
dc logs coord 2>&1 | grep "user migration" | sed 's/^[^|]*| //'
dc logs coord 2>&1 | read_all grep -q "user migration approved 1"
coord_file nodes.json | jq -c '.users'
mig_state="$(coord_file nodes.json | jq -r '.users[] | select(.user == "oidc:mia") | .state')"
[[ "$mig_state" == approved ]]
# The migration approval writes 1 user-approve record when the chain opens.
coord_file config-audit.jsonl | jq -c 'select(.action == "user-approve" and .target == "oidc:mia") | {action, actor, target, detail}'
[[ "$(audit_count user-approve oidc:mia)" -eq 1 ]]
coord_file nodes.json | jq -e '[.users[] | select(has("migration_unrecorded"))] | length == 0' >/dev/null
# mia-tab uses a new ID token of the same subject mia.
idp mint --dir /idp --kid rs1 --issuer "$ISSUER" --aud "$CLIENT" --out /tokens/mia-tab \
  --sub mia --email mia@example.test >/dev/null
enroll_user mia-pc mia-tab mia-tab "$STATE/tab" >/dev/null
echo "check migrated mia enrolls mia-tab with no action ok"
has_node mia-tab
users_out="$(owner users)"
printf '%s\n' "$users_out"
user_line mia | read_all grep -q ' approved nodes 2$'

for name in srv mia-pc; do
  run_node "$name" coord netmap --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" \
    --state "$STATE" >/dev/null
done
echo "=== [C] start srv and mia-pc ==="
dc up -d srv mia-pc
for name in srv mia-pc; do
  wait_log "$name" 'The TUN device'
done
nodes="$(owner nodes)"
ip_of() {
  printf '%s\n' "$nodes" | read_all awk -v name="$1" '$1 == "node" && $2 == name {print $3; exit}'
}
srv_ip="$(ip_of srv)"
echo "overlay srv ${srv_ip} mia-pc $(ip_of mia-pc)"
for name in srv mia-pc; do
  copy_tools "$name"
done
dc exec -d srv python3 -m http.server 8080 --bind 0.0.0.0
dc exec -d srv python3 /tmp/share-sink.py serve 7070 /tmp/sink-7070.txt
sleep 1
wait_path mia-pc srv
out="$(get mia-pc "$srv_ip" 8080)"
echo "check migrated mia-pc -> srv:8080 ok: ${out}"

echo "=== [C] gate 1: a new user waits ==="
mint nina
expect_refused "nina-pc pending" "The user waits for owner approval." nina-pc nina-pc nina "$STATE"
expect_refused "nina-pc pending again" "The user waits for owner approval." nina-pc nina-pc nina "$STATE"
nina_files="$(dc run --rm --no-deps --entrypoint sh nina-pc -c "ls -A $STATE | tr '\n' ' '")"
echo "nina-pc state files: [${nina_files}]"
if printf '%s' "$nina_files" | read_all grep -q 'svid\|bundle.pem\|netmap'; then
  echo "The pending user has an SVID, a bundle, or a netmap." >&2
  exit 1
fi
if has_node nina-pc; then
  echo "The store has node nina-pc." >&2
  exit 1
fi
echo "check store has no node nina-pc"
dc logs coord 2>&1 | grep -E "user (pending|refused) oidc:nina" | sed 's/^[^|]*| //'
users_out="$(owner users)"
printf '%s\n' "$users_out"
user_line nina | read_all grep -q ' pending nodes 0$'
printf '%s\n' "$users_out" | read_all grep -qx 'users_pending 1'
[[ "$(audit_count user-approve oidc:nina)" -eq 0 ]]
# The nina-pc container starts and waits for approval. It has no SVID, so it has no TUN.
dc up -d nina-pc
wait_log nina-pc "enroll pending:"
dc logs nina-pc 2>&1 | grep "enroll pending" | awk 'NR == 1' | sed 's/^[^|]*| //' || true
copy_tools nina-pc
dc exec -T nina-pc python3 /tmp/share-sink.py send "$srv_ip" 7070 65536 0.8 || true
sleep 1
pending_bytes="$(dc exec -T srv cat /tmp/sink-7070.txt | awk '{n += $2} END {print n + 0}')"
echo "gate1_bytes srv_sink_all_sources ${pending_bytes} (nina-pc sent 65536 tcp + 65536 udp to ${srv_ip}:7070)"
[[ "$pending_bytes" -eq 0 ]]

echo "=== [C] gate 4: owner user olivia never waits ==="
mint olivia
enroll_user rex-pc olivia-pc olivia "$STATE/olivia" >/dev/null
echo "check owner user olivia enrolls olivia-pc with no approval ok"
olivia_rec="$(coord_file config-audit.jsonl | jq -c 'select(.action == "user-approve" and .target == "oidc:olivia") | {action, target, detail}')"
echo "$olivia_rec"
[[ "$(audit_count user-approve oidc:olivia)" -eq 1 ]]
set +e
olivia_rej="$(owner user-reject oidc:olivia 2>&1)"
olivia_rej_status=$?
set -e
echo "owner user-reject oidc:olivia exit ${olivia_rej_status}: ${olivia_rej}"
[[ "$olivia_rej_status" -ne 0 ]]
[[ "$(audit_count user-reject oidc:olivia)" -eq 0 ]]

echo "=== [C] gate 2: reject ==="
mint rex
expect_refused "rex-pc pending" "The user waits for owner approval." rex-pc rex-pc rex "$STATE"
before="$(records)"
owner user-reject oidc:rex
after="$(records)"
echo "coord_records reject before ${before} after ${after} new $(( after - before ))"
[[ "$(( after - before ))" -eq 1 ]]
expect_refused "rex-pc rejected" "The owner rejected this user." rex-pc rex-pc rex "$STATE"
has_node rex-pc && { echo "The store has node rex-pc." >&2; exit 1; }
[[ "$(audit_count user-reject oidc:rex)" -eq 1 ]]

echo "=== [C] gate 2: approve ==="
users_out="$(owner users)"
printf '%s\n' "$users_out"
user_line nina | read_all grep -q ' pending nodes 0$'
user_line rex | read_all grep -q ' rejected nodes 0$'
# The reach probe runs in the nina-pc container (no docker exec in the loop).
# It tries one HTTP GET to srv:8080 each 50 ms and writes the Unix ms of the first HTTP 200.
dc exec -T nina-pc sh -c "cat > /tmp/reach.py" <<'PY'
import socket, sys, time
host, port, secs, out = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
end = time.time() + secs
tries = 0
while time.time() < end:
    tries += 1
    try:
        with socket.create_connection((host, port), timeout=0.3) as s:
            s.settimeout(0.5)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            if s.recv(64).startswith(b"HTTP/1.0 200"):
                open(out, "w").write(f"first_ok_unix_ms {int(time.time() * 1000)} tries {tries}\n")
                sys.exit(0)
    except OSError:
        pass
    time.sleep(0.05)
open(out, "w").write(f"first_ok_unix_ms none tries {tries}\n")
PY
dc exec -d nina-pc python3 /tmp/reach.py "$srv_ip" 8080 60 /tmp/reach.out
sleep 1
before="$(records)"
approve_ms="$(now_ms)"
owner user-approve oidc:nina
approve_done_ms="$(now_ms)"
reach_line=""
for _ in $(seq 1 150); do
  reach_line="$(dc exec -T nina-pc sh -c 'cat /tmp/reach.out 2>/dev/null || true')"
  [[ -n "$reach_line" ]] && break
  sleep 0.5
done
echo "reach_probe ${reach_line:-none}"
first_ok="$(awk '{print $2}' <<<"$reach_line")"
# The coordinator prints "admin user-approve" when it takes the request. Docker gives the log time.
coord_ts="$(dc logs -t coord 2>&1 | grep 'admin user-approve' | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z' | tail -n 1 || true)"
coord_approve_ms="none"
[[ -n "$coord_ts" ]] && coord_approve_ms="$(date -d "$coord_ts" +%s%3N)"
reach_ms=""
reach_cmd_ms="none"
if [[ "$first_ok" =~ ^[0-9]+$ ]]; then
  reach_cmd_ms="$(( first_ok - approve_ms ))"
  if [[ "$coord_approve_ms" =~ ^[0-9]+$ ]]; then
    reach_ms="$(( first_ok - coord_approve_ms ))"
  fi
fi
echo "coord_approve_after_cmd_start_ms $([[ "$coord_approve_ms" =~ ^[0-9]+$ ]] && echo $(( coord_approve_ms - approve_ms )) || echo none)"
echo "approve_cmd_start_to_reach_ms ${reach_cmd_ms} (includes the docker run start of the admin CLI)"
echo "approve_cmd_ms $(( approve_done_ms - approve_ms ))"
dc logs nina-pc 2>&1 | grep -E "approval_wait_ms|enrolled|The TUN device" | sed 's/^[^|]*| //' || true
wait_ms="$(dc logs nina-pc 2>&1 | awk '{for (i = 1; i < NF; i++) if ($i == "approval_wait_ms") print $(i + 1)}' | tail -n 1)"
# approval_wait_ms counts from the start of the container. The Docker log time of that line
# gives the time from the approve command to the end of the enroll (SVID written).
svid_ts="$(dc logs -t nina-pc 2>&1 | grep 'approval_wait_ms' | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z' | awk 'NR == 1' || true)"
svid_ms="none"
if [[ -n "$svid_ts" ]]; then
  svid_ms="$(( $(date -d "$svid_ts" +%s%3N) - ${coord_approve_ms/none/$approve_ms} ))"
fi
echo "approve_to_svid_ms ${svid_ms} (coordinator approve log time to the Docker log time of the enroll result line)"
echo "approve_to_reach_ms ${reach_ms:-none} limit_ms ${REACH_LIMIT_MS} (coordinator approve log time to the first HTTP 200 nina-pc -> srv:8080; srv did not restart)"
[[ "$(audit_count user-approve oidc:nina)" -eq 1 ]]
has_node nina-pc
users_out="$(owner users)"
user_line nina | read_all grep -q ' approved nodes 1$'
dc exec -T nina-pc python3 /tmp/share-sink.py send "$srv_ip" 7070 65536 0.8 >/dev/null || true
sleep 1
nina_ip="$(owner nodes | read_all awk '$1 == "node" && $2 == "nina-pc" {print $3; exit}')"
after_bytes="$(dc exec -T srv cat /tmp/sink-7070.txt | awk -v s="$nina_ip" '$1 == s {n += $2} END {print n + 0}')"
echo "control srv_sink_from_nina_after_approve ${after_bytes}"

echo "=== [C] gate 4: auto-approve on (policy option, off by default) ==="
put_policy "$WORK/auto.hujson"
mint ivy
enroll_user rex-pc ivy-pc ivy "$STATE/ivy" >/dev/null
coord_file config-audit.jsonl | jq -c 'select(.action == "user-approve" and .target == "oidc:ivy") | {action, target, detail}'
[[ "$(audit_count user-approve oidc:ivy)" -eq 1 ]]
expect_refused "rex-pc rejected with auto on" "The owner rejected this user." rex-pc rex-pc rex "$STATE"
put_policy "$WORK/new.hujson"

echo "=== [C] audit ==="
coord_file config-audit.jsonl >"$WORK/config-audit.jsonl"
jq -c 'select(.action == "user-approve" or .action == "user-reject") | {action, actor, target, detail}' "$WORK/config-audit.jsonl"
n_approve="$(jq -s '[.[] | select(.action == "user-approve")] | length' "$WORK/config-audit.jsonl")"
n_reject="$(jq -s '[.[] | select(.action == "user-reject")] | length' "$WORK/config-audit.jsonl")"
echo "audit user_approve ${n_approve} user_reject ${n_reject}"
[[ "$n_approve" -eq 4 && "$n_reject" -eq 1 ]]
audit_after="$(owner audit --verify)"
printf '%s\n' "$audit_after" | grep '^verify '
grep -q '^verify ok ' <<<"$audit_after"

echo "=== [C] gate 5: logs hold no key, ID token, or enroll token ==="
{
  dc logs 2>&1
  cat "$WORK/config-audit.jsonl"
  dc exec -T coord cat "$STATE/nodes.json"
} >"$WORK/all-logs.log"
for name in owner srv; do
  token="$(dc exec -T coord cat "$STATE/tokens/${name}" 2>/dev/null | tr -d ' \n' || true)"
  if [[ -n "$token" ]] && grep -qF "$token" "$WORK/all-logs.log"; then
    echo "A log holds the ${name} enroll token." >&2
    exit 1
  fi
done
id_tokens=0
for name in mia mia-tab nina olivia rex ivy; do
  sig="$(dc run --rm --no-deps --entrypoint cut idp -d. -f3 "/tokens/${name}")"
  if [[ -n "$sig" ]] && grep -qF -- "$sig" "$WORK/all-logs.log"; then
    id_tokens=$(( id_tokens + 1 ))
  fi
done
hits="$(grep -cF 'PRIVATE KEY' "$WORK/all-logs.log" || true)"
echo "secret_grep tokens 0 id_tokens ${id_tokens} 'PRIVATE KEY' ${hits}"
[[ "$id_tokens" -eq 0 && "$hits" -eq 0 ]]

echo "summary migration mia approved_with_no_action pending_bytes ${pending_bytes} approve_records 1 reject_records 1 owner_user_never_pending ok auto_default off approval_wait_ms ${wait_ms:-none} approve_to_svid_ms ${svid_ms} approve_to_reach_ms ${reach_ms:-none} approve_cmd_start_to_reach_ms ${reach_cmd_ms} limit_ms ${REACH_LIMIT_MS} coord_verify ok"
if [[ -z "$reach_ms" ]] || (( reach_ms > REACH_LIMIT_MS )); then
  echo "nina-pc did not reach srv within ${REACH_LIMIT_MS} ms of the approve." >&2
  exit 1
fi
(( after_bytes > 0 ))
echo "proof_ok"
