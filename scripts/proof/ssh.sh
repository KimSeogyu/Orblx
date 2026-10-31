#!/usr/bin/env bash
# SSH proof (W25-31): SSH user certificates from the coordinator.
# The containers stand in for other hosts on one Linux host.
# The coordinator issues the node SVIDs and tickets (OIDC and token enroll) and the SSH user
# certificates. The proof makes no lab SVIDs and no lab tickets.
#
# Gates:
#   - alice (owner of node a) gets a certificate with life <= 900 s and the principal
#     oidc:alice, and runs a command and a PTY shell on node b.
#   - mallory (no ssh rule) gets no certificate. The coordinator writes 1 deny record.
#   - pat (pending) and rex (rejected) cannot enroll a node, so they cannot ask.
#   - the sharee gets only the sharee login: sharee@b works, alice@b from node s is refused.
#   - a non-root caller on node a is refused. The node SVID key is mode 600, owner root.
#   - a certificate from a CA that is not in the netmap is refused (openssh-client in the
#     image, [C]).
#   - revoke of user sharee and of node a: no new certificate, and the open session ends.
#     The script prints the ms from the revoke command to the session end on node b.
#   - each certificate request writes exactly 1 ssh-cert record (code 39) at the coordinator.
#   - the session recording gates of row 41 (recording, tamper verify, read-only dir).
# The script does not print private keys, ID tokens, enroll tokens, tickets, or certificates.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.ssh.yml"
WORK="$(mktemp -d)"
export POLICY_DIR="$WORK/policy"
export CONFIG_FILE="$WORK/coord.toml"
export IDP_CA_FILE="$WORK/idp-ca.pem"
export SSH_REC_C="$WORK/c-rec"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
ISSUER="https://idp:8443"
CLIENT="orblx-proof"
COORD="172.28.19.10:443"
STATE=/var/lib/orblx
REVOKE_LIMIT_MS="${ORBLX_SSH_REVOKE_LIMIT_MS:-60000}"
# The number of certificate requests that reached the coordinator.
ASKS=0

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root env POLICY_DIR="$POLICY_DIR" CONFIG_FILE="$CONFIG_FILE" IDP_CA_FILE="$IDP_CA_FILE" \
    SSH_REC_C="$SSH_REC_C" docker compose --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  local status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "---- docker logs (tail) ----"
    dc logs --tail 60 2>&1 | grep -v 'PRIVATE KEY' || true
  fi
  jobs -p | xargs -r kill 2>/dev/null || true
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "ssh"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "orblx-ssh" || exit 1

open_legacy_forward() {
  command -v iptables-legacy >/dev/null 2>&1 || return 0
  as_root iptables-legacy -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD DROP' || return 0
  if command -v iptables-nft >/dev/null 2>&1; then
    as_root iptables-nft -S FORWARD 2>/dev/null | read_all grep -qx -- '-P FORWARD ACCEPT' || return 0
  fi
  echo "=== [C] set iptables-legacy FORWARD ACCEPT ==="
  as_root iptables-legacy -P FORWARD ACCEPT
}

now_ms() {
  date +%s%3N
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

idp() {
  dc run --rm --no-deps --entrypoint orblx-test-idp idp "$@"
}

# mint USER: one ID token for USER@example.test (email_verified true) at /tokens/USER.
mint() {
  idp mint --dir /idp --kid rs1 --issuer "$ISSUER" --aud "$CLIENT" --out "/tokens/$1" \
    --sub "$1" --email "$1@example.test" >/dev/null
}

run_node() {
  local service="$1"
  shift
  dc run --rm --no-deps -T --entrypoint orblx "$service" "$@"
}

owner() {
  run_node owner admin "$@" --coord "$COORD" --state "$STATE" --bundle "$STATE/bundle.pem"
}

enroll_token() {
  local name="$1"
  dc exec -T coord orblx coord token create --state "$STATE" --ttl 3600 \
    --out "$STATE/tokens/${name}" >/dev/null
  run_node "$name" coord enroll --name "$name" --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" --endpoint "$(service_ip "$name"):443" >/dev/null
  echo "enrolled ${name} with a token"
}

# enroll_user SERVICE NODE USER STATE_DIR: one OIDC enroll. Keeps the exit code.
enroll_user() {
  run_node "$1" coord enroll --name "$2" --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem --id-token-file "/tokens/$3" \
    --state "$4" --endpoint "$(service_ip "$1"):443"
}

service_ip() {
  case "$1" in
    a) echo 172.28.19.11 ;;
    b) echo 172.28.19.12 ;;
    c) echo 172.28.19.13 ;;
    s) echo 172.28.19.14 ;;
    m) echo 172.28.19.15 ;;
    *) echo 172.28.19.20 ;;
  esac
}

# expect_enroll_refused LABEL TEXT USER: the enroll of USER (in a throwaway state dir) fails.
expect_enroll_refused() {
  local label="$1" text="$2" user="$3" out status
  set +e
  out="$(enroll_user owner "${user}-pc" "$user" "/tmp/${user}" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$out" | grep -v -i 'token' | sed "s/^/  ${label}: /"
  if [[ "$status" -eq 0 ]]; then
    echo "The coordinator enrolled ${label}." >&2
    exit 1
  fi
  printf '%s\n' "$out" | read_all grep -qF -- "$text"
  echo "check ${label} enroll refused (no node SVID, no certificate)"
}

coord_file() {
  dc exec -T coord cat "$STATE/$1"
}

# The ssh-cert records at the coordinator.
cert_records() {
  coord_file config-audit.jsonl | jq -c 'select(.action == "ssh-cert")'
}

cert_count() {
  cert_records | wc -l | tr -d ' '
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

# The SSH server of a target node starts when the node has a fresh netmap with the CA set.
wait_ca() {
  local node="$1" i
  for i in $(seq 1 60); do
    if dc exec -T "$node" sh -c "test -s $STATE/netmap-fresh && jq -e '.ssh_user_ca | length == 2' $STATE/netmap.json" >/dev/null 2>&1; then
      echo "node ${node} netmap ssh_user_ca 2 fresh"
      return 0
    fi
    sleep 1
  done
  echo "The node ${node} has no fresh netmap with the SSH CA set." >&2
  return 1
}

# Copy the current SVID of target node TO into node FROM at /tmp/peers/TO.pem.
peer_pem() {
  local from="$1" to="$2"
  dc exec -T "$to" cat "$STATE/cert.pem" \
    | dc exec -T "$from" sh -c "mkdir -p /tmp/peers && cat > /tmp/peers/${to}.pem"
}

# ssh_cert FROM USER@TO [EXTRA...]: one certificate login from node FROM as root.
ssh_cert() {
  local from="$1" target="$2" to
  shift 2
  to="${target#*@}"
  peer_pem "$from" "$to"
  ASKS=$((ASKS + 1))
  dc exec -T "$from" orblx ssh "$target" --state "$STATE" --peer-cert "/tmp/peers/${to}.pem" \
    --command 'printf '\''%s\n'\'' "$ORBLX_SSH_USER"' "$@"
}

expect_deny() {
  local label="$1" out
  shift
  if out="$(ssh_cert "$@" 2>&1)"; then
    printf '%s\n' "$out"
    echo "The session ${label} was accepted." >&2
    return 1
  fi
  printf '%s\n' "$out" | sed "s/^/  ${label}: /"
  echo "denied ${label}"
}

# The last ssh-cert record for one node: decision, reason, and principal.
last_record() {
  cert_records | jq -r --arg n "spiffe://orblx.local/node/$1" \
    'select(.actor == $n) | .detail' | tail -n 1
}

b_audit_revoked() {
  dc exec -T b sh -c "grep -c '\"reason\":\"revoked\"' $STATE/ssh-audit.jsonl || true" | tr -d '\r'
}

# open_shell FROM USER@TO: start a PTY shell that stays open. SHELL_PID is the host pid of the client.
open_shell() {
  local from="$1" target="$2" to
  to="${target#*@}"
  peer_pem "$from" "$to"
  ASKS=$((ASKS + 1))
  {
    sleep 1
    printf 'echo open-$((40+2))\n'
    sleep 300
  } | dc exec -T "$from" orblx ssh "$target" --state "$STATE" --peer-cert "/tmp/peers/${to}.pem" \
    --shell >"$WORK/shell-${from}.out" 2>&1 &
  SHELL_PID=$!
}

wait_open() {
  local from="$1" i
  for i in $(seq 1 60); do
    if tr -d '\r' <"$WORK/shell-${from}.out" | read_all grep -qx 'open-42'; then
      return 0
    fi
    sleep 0.5
  done
  echo "The shell from ${from} did not open." >&2
  cat "$WORK/shell-${from}.out" >&2 || true
  return 1
}

# measure_revoke LABEL PID BEFORE START_MS: wait until the open session ends.
# The session end is a new revoked deny record on node b, or the end of the client process.
measure_revoke() {
  local label="$1" pid="$2" before="$3" start="$4" now count signal=""
  while :; do
    now="$(now_ms)"
    if ! kill -0 "$pid" 2>/dev/null; then
      signal="client-exit"
      break
    fi
    count="$(b_audit_revoked)"
    if (( count > before )); then
      signal="node-b-revoked-record"
      break
    fi
    if (( now - start > REVOKE_LIMIT_MS )); then
      echo "The open session of ${label} did not end in ${REVOKE_LIMIT_MS} ms." >&2
      exit 1
    fi
    sleep 0.1
  done
  echo "revoke_to_session_end_ms ${label} $((now - start)) signal ${signal}"
  results+=("${label}=$((now - start))")
  # The client process must end too.
  local i
  for i in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "The client of ${label} did not end." >&2
    exit 1
  fi
  echo "client_ended ${label} after $(( $(now_ms) - start )) ms"
  dc logs b 2>&1 | grep 'ssh certificate revoked serial' | sed 's/^[^|]*| //' | tail -n 2 || true
}

results=()
mkdir -p "$POLICY_DIR" "$SSH_REC_C"
: >"$IDP_CA_FILE"
cp "$ROOT/scripts/proof/ssh.hujson" "$POLICY_DIR/policy.hujson"
cat >"$CONFIG_FILE" <<CONF
# [C] coordinator config for the SSH proof.
[oidc]
issuer = "${ISSUER}"
client_id = "${CLIENT}"
allowed_domains = ["example.test"]
allowed_emails = []
ca_file = "/etc/orblx/idp-ca.pem"
CONF

echo "=== [REAL] one Linux host ==="
uname -s
uname -m
open_legacy_forward

echo "=== [C] build image ==="
cargo build -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp --locked
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
IMAGE_DIR="$(stage_proof_image "$ROOT" "$TARGET_DIR/debug/orblx")"
cp "$TARGET_DIR/debug/orblx-test-idp" "$IMAGE_DIR/orblx-test-idp"
{
  printf '%s\n' 'COPY orblx-test-idp /usr/local/bin/orblx-test-idp'
  # [C] openssh-client for the foreign CA gate only. The node does not run sshd.
  printf '%s\n' 'RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*'
} >>"$IMAGE_DIR/Dockerfile"
as_root docker build -q -t orblx-ssh:local "$IMAGE_DIR" >/dev/null
rm -rf "$IMAGE_DIR"

echo "=== [C] test issuer and coordinator ==="
idp init --dir /idp --host idp >/dev/null
dc run --rm --no-deps --entrypoint cat idp /idp/ca.pem >"$IDP_CA_FILE"
grep -q 'BEGIN CERTIFICATE' "$IDP_CA_FILE"
dc up -d idp
wait_log idp "idp serve"
dc up -d coord
wait_bundle
wait_log coord "oidc issuer"
ca_mode="$(dc exec -T coord stat -c '%a %U' "$STATE/ssh-user-ca.json" | tr -d '\r')"
echo "coord ssh-user-ca.json mode ${ca_mode}"
[[ "$ca_mode" == "600 root" ]]

echo "=== [C] enroll: owner, b, c with tokens; a, s, m with OIDC ==="
for name in owner b c; do
  enroll_token "$name"
done
for user in alice sharee mallory pat rex; do
  mint "$user"
done
enroll_user a a alice "$STATE" >/dev/null
echo "enrolled a as oidc:alice (owner user, no wait)"
expect_enroll_refused "sharee pending" "The user waits for owner approval." sharee
expect_enroll_refused "mallory pending" "The user waits for owner approval." mallory
expect_enroll_refused "pat pending" "The user waits for owner approval." pat
expect_enroll_refused "rex pending" "The user waits for owner approval." rex
owner user-approve oidc:sharee >/dev/null
owner user-approve oidc:mallory >/dev/null
owner user-reject oidc:rex >/dev/null
expect_enroll_refused "rex rejected" "The owner rejected this user." rex
expect_enroll_refused "pat still pending" "The user waits for owner approval." pat
enroll_user s s sharee "$STATE" >/dev/null
echo "enrolled s as oidc:sharee (approved)"
enroll_user m m mallory "$STATE" >/dev/null
echo "enrolled m as oidc:mallory (approved)"
owner nodes | read_all awk '$1 == "node" {print "node", $2, $3}'
users_out="$(owner users)"
printf '%s\n' "$users_out" | read_all awk '$1 == "user" {print}'

echo "=== [C] SSH policy on the target nodes b and c ==="
for name in b c; do
  dc run --rm --no-deps -T --entrypoint sh "$name" -c "cat > $STATE/policy.hujson" \
    <"$ROOT/scripts/proof/ssh.hujson"
  echo "policy ${name} written"
done

echo "=== [C] start nodes ==="
dc up -d a b c s m
for name in a b c s m; do
  wait_log "$name" 'The TUN device'
done
wait_path a b
wait_path a c
wait_path s b
wait_path m b
wait_ca b
wait_ca c
b_ip="$(dc exec -T b jq -r '.self.overlay_ip' "$STATE/netmap.json" | tr -d '\r')"
a_ip="$(dc exec -T a jq -r '.self.overlay_ip' "$STATE/netmap.json" | tr -d '\r')"
echo "a_ip ${a_ip} b_ip ${b_ip}"

echo "=== [C] lab-ticket guard: the node tickets come from the coordinator ==="
for name in a b c s m; do
  mkdir -p "$WORK/guard/$name"
  dc exec -T "$name" cat "$STATE/ticket.bin" >"$WORK/guard/$name/ticket.bin"
  dc exec -T "$name" cat "$STATE/node-name" >"$WORK/guard/$name/node-name"
done
proof_ticket_guard coord "$WORK/guard/a" "$WORK/guard/b" "$WORK/guard/c" "$WORK/guard/s" "$WORK/guard/m"
rm -rf "$WORK/guard"

echo "=== [C] gate: the node SVID key is root-only, and a non-root caller is refused ==="
key_mode="$(dc exec -T a stat -c '%a %U' "$STATE/key.pem" | tr -d '\r')"
echo "node a key.pem mode ${key_mode}"
[[ "$key_mode" == "600 root" ]]
peer_pem a b
if nonroot="$(dc exec -T --user 65534 a orblx ssh alice@b --state "$STATE" \
  --peer-cert /tmp/peers/b.pem 2>&1)"; then
  echo "The non-root caller got a session." >&2
  exit 1
fi
printf '%s\n' "$nonroot" | sed 's/^/  nonroot: /'
printf '%s\n' "$nonroot" | read_all grep -q 'needs root'
echo "denied nonroot (no request reached the coordinator)"
[[ "$(cert_count)" -eq 0 ]]

echo "=== [C] gate: alice gets a certificate for oidc:alice and runs a command on b ==="
alice_out="$(ssh_cert a alice@b | tr -d '\r')"
printf '%s\n' "$alice_out"
[[ "$alice_out" == "alice" ]]
rec="$(last_record a)"
echo "coord ssh-cert ${rec}"
echo "$rec" | read_all grep -q 'decision allow'
echo "$rec" | read_all grep -q 'principal oidc:alice'
after="$(echo "$rec" | read_all awk '{for (i = 1; i < NF; i++) if ($i == "valid_after") print $(i + 1)}')"
before="$(echo "$rec" | read_all awk '{for (i = 1; i < NF; i++) if ($i == "valid_before") print $(i + 1)}')"
life=$((before - after))
echo "cert_life_s ${life} (valid_after is now - 60)"
(( life <= 900 + 60 ))
(( before - $(date +%s) <= 900 ))
dc logs b 2>&1 | read_all grep -q 'ssh certificate accepted serial [0-9]* principal oidc:alice'
echo "node b accepted the certificate"

echo "=== [C] gate: mallory is refused at the coordinator ==="
expect_deny mallory m mallory@b
rec="$(last_record m)"
echo "coord ssh-cert ${rec}"
echo "$rec" | read_all grep -q 'decision deny'
echo "$rec" | read_all grep -q 'reason no-grant'

echo "=== [C] gate: the sharee gets only the sharee login ==="
sharee_out="$(ssh_cert s sharee@b | tr -d '\r')"
printf '%s\n' "$sharee_out"
[[ "$sharee_out" == "sharee" ]]
rec="$(last_record s)"
echo "coord ssh-cert ${rec}"
echo "$rec" | read_all grep -q 'principal oidc:sharee'
expect_deny "sharee as alice" s alice@b
dc logs b 2>&1 | read_all grep -Eq 'ssh certificate refused serial [0-9]+ reason (policy|principal)'
echo "node b refused the sharee certificate for the login alice"

echo "=== [C] gate: alice to node c without a rule is refused ==="
expect_deny "alice to c" a alice@c

echo "=== [C] gate: a certificate from a CA that is not in the netmap is refused ==="
# [C] OpenSSH makes a foreign CA and one certificate for oidc:alice with the right
# source-address. The node b SSH server refuses it (reason unknown-ca).
dc exec -T a sh -c "rm -rf /tmp/rogue && mkdir -p /tmp/rogue && cd /tmp/rogue \
  && ssh-keygen -q -t ed25519 -N '' -f ca && ssh-keygen -q -t ed25519 -N '' -f user \
  && ssh-keygen -q -s ca -I rogue -n oidc:alice -z 7 -V -1m:+5m \
     -O clear -O permit-pty -O source-address=${a_ip}/32 user.pub"
if rogue="$(dc exec -T a ssh -F /dev/null -i /tmp/rogue/user \
  -o CertificateFile=/tmp/rogue/user-cert.pub -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 \
  "alice@${b_ip}" true 2>&1)"; then
  echo "The foreign CA certificate got a session." >&2
  exit 1
fi
printf '%s\n' "$rogue" | grep -v -i 'warning' | sed 's/^/  rogue: /' || true
dc logs b 2>&1 | read_all grep -q 'ssh certificate refused serial 7 reason unknown-ca'
echo "denied foreign_ca (node b reason unknown-ca)"
dc exec -T a rm -rf /tmp/rogue

echo "=== [C] row 41: recorded session on node b ==="
rec_out="$(ssh_cert a rec@b | tr -d '\r')"
printf '%s\n' "$rec_out"
[[ "$rec_out" == "rec" ]]
rec_files="$(dc exec -T b sh -c "ls $STATE/recordings/*.cast 2>/dev/null | wc -l" | tr -d '\r ')"
echo "recording_files ${rec_files}"
[[ "$rec_files" -eq 1 ]]
rec_file="$(dc exec -T b sh -c "ls $STATE/recordings/*.cast" | tr -d '\r')"
rec_sha="$(dc exec -T b sha256sum "$rec_file" | cut -d' ' -f1)"
echo "recording_sha256 ${rec_sha}"
dc exec -T b grep -q "\"kind\":\"record\".*\"recording_sha256\":\"${rec_sha}\"" "$STATE/ssh-audit.jsonl"
echo "chain_has_recording_sha256 yes"
b_audit="$(dc exec -T b orblx audit verify --file "$STATE/ssh-audit.jsonl" | tr -d '\r')"
printf '%s\n' "$b_audit"
echo "$b_audit" | read_all grep -qx 'record 1'

echo "=== [C] row 41: one changed byte in the recording fails verify ==="
dc exec -T b cp "$rec_file" /tmp/recording.orig
dc exec -T b sh -c "printf X | dd of='$rec_file' bs=1 seek=1 count=1 conv=notrunc status=none"
if bad="$(dc exec -T b orblx audit verify --file "$STATE/ssh-audit.jsonl" 2>&1)"; then
  echo "The changed recording passed verify." >&2
  exit 1
fi
printf 'verify_failed %s\n' "$bad"
echo "$bad" | read_all grep -q 'recording check failed'
dc exec -T b cp /tmp/recording.orig "$rec_file"
dc exec -T b orblx audit verify --file "$STATE/ssh-audit.jsonl" | tr -d '\r' | read_all grep -qx ok
echo "verify_after_restore ok"

echo "=== [C] row 41: read-only recording directory on node c fails closed ==="
if dc exec -T c sh -c "touch $STATE/recordings/probe" 2>/dev/null; then
  echo "The recording directory on node c is writable." >&2
  exit 1
fi
echo "recording_dir_read_only yes"
expect_deny recording a rec@c
c_rec_deny="$(dc exec -T c sh -c "grep -c '\"kind\":\"deny\".*\"reason\":\"recording\"' $STATE/ssh-audit.jsonl || true" | tr -d '\r')"
echo "deny_recording ${c_rec_deny}"
[[ "$c_rec_deny" -ge 1 ]]

echo "=== [C] row 41: interactive PTY shell on node b is recorded ==="
peer_pem a b
ASKS=$((ASKS + 1))
pty_out="$(
  {
    sleep 3
    printf 'echo pty-$((6*7))\n'
    sleep 2
    printf 'exit\n'
    sleep 2
  } | dc exec -T a orblx ssh rec@b --state "$STATE" --peer-cert /tmp/peers/b.pem --shell
)"
printf '%s\n' "$pty_out" | tr -d '\r' | read_all grep -qx 'pty-42'
echo "pty_output pty-42"
rec_files="$(dc exec -T b sh -c "ls $STATE/recordings/*.cast | wc -l" | tr -d '\r ')"
echo "recording_files ${rec_files}"
[[ "$rec_files" -eq 2 ]]
dc exec -T b orblx audit verify --file "$STATE/ssh-audit.jsonl" | tr -d '\r' | read_all grep -qx 'record 2'
echo "chain record 2"

echo "=== [C] gate: revoke user sharee ends the open sharee session ==="
open_shell s sharee@b
pid_s="$SHELL_PID"
wait_open s
before="$(b_audit_revoked)"
start="$(now_ms)"
owner revoke-all spiffe://orblx.local/user/sharee | read_all grep -x "revoked_all spiffe://orblx.local/user/sharee"
measure_revoke user_sharee "$pid_s" "$before" "$start"
expect_deny "sharee after revoke" s sharee@b
rec="$(last_record s)"
echo "coord ssh-cert ${rec}"
echo "$rec" | read_all grep -q 'decision deny'
echo "$rec" | read_all grep -Eq 'reason (user-revoked|node-revoked)'

echo "=== [C] gate: revoke node a ends the open alice session ==="
open_shell a alice@b
pid_a="$SHELL_PID"
wait_open a
before="$(b_audit_revoked)"
start="$(now_ms)"
owner revoke a | read_all grep -x "revoked a"
measure_revoke node_a "$pid_a" "$before" "$start"
expect_deny "alice after node revoke" a alice@b
rec="$(last_record a)"
echo "coord ssh-cert ${rec}"
echo "$rec" | read_all grep -q 'decision deny'
echo "$rec" | read_all grep -q 'reason node-revoked'
# The netmap of b lists the live serials of the revoked pairs.
revoked_n="$(dc exec -T b jq '.ssh_revoked | length' "$STATE/netmap.json" | tr -d '\r')"
echo "node b netmap ssh_revoked ${revoked_n}"
(( revoked_n >= 1 ))

echo "=== [C] gate: 1 ssh-cert record (code 39) for each request ==="
records="$(cert_count)"
echo "ssh_cert_requests ${ASKS} ssh_cert_records ${records}"
[[ "$records" -eq "$ASKS" ]]
allow="$(cert_records | jq -r '.detail' | grep -c 'decision allow' || true)"
deny="$(cert_records | jq -r '.detail' | grep -c 'decision deny' || true)"
echo "ssh_cert_allow ${allow} ssh_cert_deny ${deny}"
owner audit --verify | read_all grep -E '^verify ok'

echo "=== [C] audit chains on the target nodes ==="
dc exec -T b orblx audit verify --file "$STATE/ssh-audit.jsonl" | tr -d '\r' | read_all grep -qx ok
echo "node b chain ok"
dc exec -T c orblx audit verify --file "$STATE/ssh-audit.jsonl" | tr -d '\r' | read_all grep -qx ok
echo "node c chain ok"

echo "=== [C] no secrets in the logs ==="
if dc logs 2>&1 | read_all grep -Eq 'PRIVATE KEY|ssh-ed25519-cert-v01|BEGIN SSH SIGNATURE'; then
  echo "A log holds a key, a certificate, or a signature." >&2
  exit 1
fi
echo "logs_clean yes"

echo "revoke_ms ${results[*]}"
echo "proof_ok"
