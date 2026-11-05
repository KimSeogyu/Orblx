#!/usr/bin/env bash
# W25-7 proof: the coordinator posts each config audit record to the audit webhook URLs in the policy.
# The host is REAL. coord, receiver, owner, a, b, and client are [C] containers (compose.audit-webhooks.yml).
# Gates:
#   1. The receiver gets each event in 2 s or less, with the id and the sequence number of the audit record.
#      The script prints the latency of each event.
#   2. Each body has an HMAC-SHA256 signature header. The secret is in a file, not in the policy.
#      The receiver checks it. A changed body fails the check.
#      A policy:write API token cannot add or remove a webhook URL (403, reason webhooks).
#   3. The receiver is down for 30 s. All events arrive after it comes back, in order, with 0 duplicates.
#   4. A coordinator kill (SIGKILL) and start while events wait gives 0 lost and 0 duplicates.
#   5. The p50 admin latency with webhooks on and with a dead receiver is within 10 ms of webhooks off.
#      A dead receiver does not block or fail an admin request.
#   6. 0 secret and 0 token text in bodies, logs, and audit records, with a control check.
#      The chain check prints ok.
# Gate 7 (the W23-4 gates) uses nat-realism.sh.
# The script never prints a token, a key, or the webhook secret. It prints proof_ok.
# Environment:
#   HOOKS_PROJECT   Compose project name (default orblx-w25g-webhooks).
#   HOOKS_IMAGE     Image tag (default orblx-w25g-webhooks:local).
#   HOOKS_BIN       An orblx binary to use. Without it, the script builds target/debug/orblx.
#   HOOKS_DOWN_SECS The receiver down time in gate 3 (default 30).
#   HOOKS_BENCH_N   The admin calls for each mode in gate 5 (default 40).
#   ORBLX_NET_HOOK  A root script that the script runs after the network starts.
#   PROOF_LOG       The log file of this run. The secret check also reads this file.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.audit-webhooks.yml"
HOOKS_PROJECT="${HOOKS_PROJECT:-orblx-w25g-webhooks}"
HOOKS_IMAGE="${HOOKS_IMAGE:-orblx-w25g-webhooks:local}"
DOWN_SECS="${HOOKS_DOWN_SECS:-30}"
BENCH_N="${HOOKS_BENCH_N:-40}"
OWNER_ID="spiffe://orblx.local/node/owner"
A_ID="spiffe://orblx.local/node/a"
B_ID="spiffe://orblx.local/node/b"
HOOK_URL="http://receiver:9000/hook"
DEAD_URL="http://192.0.2.1:9000/hook"
LIMIT_MS=2000
WORK="$(mktemp -d)"
ENV_FILE="$WORK/env"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).
trap proof_lock_end EXIT
proof_lock_take "audit-webhooks" "$HOOKS_PROJECT"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"
proof_compose_clean "$HOOKS_PROJECT" || exit 1
printf 'HOOKS_IMAGE=%s\n' "$HOOKS_IMAGE" > "$ENV_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose -p "$HOOKS_PROJECT" --env-file "$ENV_FILE" --progress quiet --profile nodes -f "$FILE" "$@"
}

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# W25-14: the cleanup runs first, then the lock is released.
trap 'cleanup; proof_lock_end' EXIT

# No pipe into head or grep -q: with pipefail, an early reader can fail the pipe (SIGPIPE).
# The script keeps each output in a variable or a file, then checks it.
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

now_ms() {
  date +%s%3N
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
  local status
  status="$(field status "$out")"
  printf '%s\n' "${status:-none}"
}

# policy_json URL... prints a policy with these webhook URLs.
policy_json() {
  local list="" url
  for url in "$@"; do
    list="${list:+$list, }\"$url\""
  done
  printf '{"nodeApproval": false, "owners": ["%s"], "auditWebhooks": [%s], "acls": [{"action": "accept", "src": ["%s"], "proto": "tcp", "dst": ["%s:*"]}]}\n' \
    "$OWNER_ID" "$list" "$A_ID" "$B_ID"
}

# Set the policy with the owner SVID (mTLS).
owner_policy() {
  local out
  owner_sh "cat > /var/lib/orblx/next.hujson" <<< "$1"
  out="$(owner admin policy-set /var/lib/orblx/next.hujson "${ADMIN[@]}")"
  has_line '^policy_set ' "$out" || fail "the owner policy-set failed"
}

chain_len() {
  dc exec -T coord sh -c 'wc -l < /var/lib/orblx/config-audit.jsonl'
}

received_len() {
  dc exec -T receiver sh -c 'if [ -f /recv/received.jsonl ]; then wc -l < /recv/received.jsonl; else echo 0; fi'
}

# wait_received N SECS: wait until the receiver has N good bodies.
wait_received() {
  local want="$1" secs="$2" got=0
  for _ in $(seq 1 $((secs * 5))); do
    got="$(received_len)"
    [[ "$got" -ge "$want" ]] && return 0
    sleep 0.2
  done
  echo "received ${got} want ${want}" >&2
  return 1
}

# Copy the chain, the receiver file, and the coordinator log with timestamps into WORK.
snapshot() {
  dc exec -T coord cat /var/lib/orblx/config-audit.jsonl > "$WORK/chain.jsonl"
  dc exec -T receiver cat /recv/received.jsonl > "$WORK/received.jsonl"
  dc logs -t --no-log-prefix coord > "$WORK/coord-ts.log" 2>&1 || true
}

cat > "$WORK/check.py" <<'PY'
import datetime
import json
import re
import sys

chain_file, recv_file, log_file, lo, hi, mode = sys.argv[1:7]
lo, hi = int(lo), int(hi)
chain = [json.loads(line) for line in open(chain_file) if line.strip()]
recv = [json.loads(line) for line in open(recv_file) if line.strip()]
written = {}
pat = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z config audit (\d+) ")
for line in open(log_file, errors="replace"):
    match = pat.match(line)
    if not match:
        continue
    base = datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    base = base.replace(tzinfo=datetime.timezone.utc)
    frac = (match.group(2) or "0")[:6].ljust(6, "0")
    ms = base.timestamp() * 1000.0 + int(frac) / 1000.0
    written.setdefault(int(match.group(3)), ms)
seqs = [entry.get("seq") for entry in recv]
ids = [entry.get("id") for entry in recv]
dups = len(seqs) - len(set(seqs))
dup_ids = len(ids) - len(set(ids))
order_ok = all(a < b for a, b in zip(seqs, seqs[1:]))
first = {}
for entry in recv:
    first.setdefault(entry["seq"], entry)
want = list(range(lo, hi))
got = [seq for seq in want if seq in first]
match_ok = 0
sig_ok = 0
lat = []
for seq in got:
    entry = first[seq]
    record = chain[seq]
    if (entry["id"] == record["hash"] and record["index"] == seq
            and entry["hdr_seq"] == str(seq) and entry["hdr_id"] == record["hash"]
            and entry["action"] == record["action"]):
        match_ok += 1
    if entry["sig_ok"]:
        sig_ok += 1
    if mode == "latency":
        ms = entry["recv_ms"] - written.get(seq, float("nan"))
        lat.append(ms)
        print("event seq %d action %s latency_ms %.1f" % (seq, record["action"], ms))
print("%s window %d..%d delivered %d of %d id_seq_match %d sig_ok %d duplicates_seq %d duplicates_id %d order %s"
      % (mode, lo, hi - 1, len(got), len(want), match_ok, sig_ok, dups, dup_ids,
         "ok" if order_ok else "fail"))
if mode == "latency" and lat:
    lat_sorted = sorted(lat)
    print("latency_ms min %.1f p50 %.1f max %.1f" % (lat_sorted[0], lat_sorted[len(lat_sorted) // 2], lat_sorted[-1]))
ok = len(got) == len(want) and match_ok == len(want) and sig_ok == len(want) and dups == 0 and dup_ids == 0 and order_ok
if mode == "latency":
    ok = ok and all(ms == ms and ms <= float(sys.argv[7]) for ms in lat)
print("check %s %s" % (mode, "ok" if ok else "fail"))
PY

check() {
  python3 "$WORK/check.py" "$WORK/chain.jsonl" "$WORK/received.jsonl" "$WORK/coord-ts.log" "$@"
}

echo "=== [REAL] host ==="
uname -sm
echo "commit $(git rev-parse HEAD)"

echo "=== [C] build image ${HOOKS_IMAGE} (project ${HOOKS_PROJECT}) ==="
bin="${HOOKS_BIN:-}"
if [[ -z "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --locked
  bin="$ROOT/target/debug/orblx"
fi
[[ -x "$bin" ]] || fail "the orblx binary $bin is missing"
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$bin")"
as_root docker build -q -t "$HOOKS_IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] make the webhook secret (file only, not in the policy) ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
dc run --rm --no-deps -T --entrypoint sh receiver -c \
  'umask 077; python3 -c "import secrets; print(secrets.token_hex(32))" > /secret/webhook.key; chmod 444 /secret/webhook.key; wc -c < /secret/webhook.key' \
  > "$WORK/keylen"
echo "secret_bytes_with_line_end $(cat "$WORK/keylen")"

echo "=== [C] start receiver and coordinator ==="
policy_json "$HOOK_URL" > "$WORK/policy.json"
dc run --rm --no-deps -T --entrypoint sh coord -c 'mkdir -p /var/lib/orblx && cat > /var/lib/orblx/policy.hujson' \
  < "$WORK/policy.json"
policy_has_secret="$(grep -cF -f <(dc run --rm --no-deps -T --entrypoint cat receiver /secret/webhook.key) "$WORK/policy.json" || true)"
echo "policy_secret_hits ${policy_has_secret}"
[[ "$policy_has_secret" == 0 ]] || fail "the policy holds the secret"
dc up -d receiver
for _ in $(seq 1 50); do
  logs="$(dc logs --no-log-prefix receiver 2>&1 || true)"
  has_line '^receiver listen 9000' "$logs" && break
  sleep 0.2
done
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
ADMIN=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)
echo "coord ${COORD}"
logs="$(dc logs --no-log-prefix coord 2>&1)"
has_line '^audit webhook added http://receiver:9000 next_seq 0' "$logs" || {
  sleep 1
  logs="$(dc logs --no-log-prefix coord 2>&1)"
  has_line '^audit webhook added http://receiver:9000' "$logs" || fail "the coordinator did not add the webhook"
}
grep '^audit webhook' <<< "$logs" || true

echo "=== [C] gate 1: control-plane events ==="
gate1_start=0
enroll() {
  local name="$1" out
  out="$(dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 600 \
    --out "/var/lib/orblx/tokens/${name}")"
  grep -E '^token_id' <<< "$out" || true
  out="$(dc run --rm --no-deps -T "$name" coord enroll --name "$name" --coord "$COORD" \
    --bundle /coord-state/trust-bundle.pem --token-file "/coord-state/tokens/${name}" \
    --state /var/lib/orblx --endpoint "${name}:443")"
  grep -E '^enrolled' <<< "$out" || true
}
for name in owner a b; do
  enroll "$name"
done
create_token() {
  owner admin token-create --scope "$2" --ttl "$3" --out "/tokens/$1" "${ADMIN[@]}"
}
out="$(create_token read nodes:read 10m)"; grep '^token_id' <<< "$out"; READ_ID="$(field token_id "$out")"
out="$(create_token pol policy:write 10m)"; grep '^token_id' <<< "$out"
out="$(create_token bench nodes:read 30m)"; grep '^token_id' <<< "$out"
echo "token read admin-nodes status $(client_call read admin-nodes) want 200"
echo "token read admin-revoke status $(client_call read admin-revoke a) want 403"
echo "token read admin-policy-set status $(client_call read admin-policy-set '{}') want 403"
out="$(dc run --rm --no-deps -T a agent grant request --agent bot --node b --service web --port 8080 --ttl 120 \
  "${ADMIN[@]}")"
GRANT_ID="$(field grant_id "$out")"
[[ -n "$GRANT_ID" ]] || fail "no agent grant id"
echo "agent grant ${GRANT_ID} requested"
out="$(owner admin grant-approve "$GRANT_ID" "${ADMIN[@]}")"; echo "grant-approve done"
out="$(owner admin grant-revoke "$GRANT_ID" "${ADMIN[@]}")"; echo "grant-revoke done"
out="$(owner lock keygen --out /var/lib/orblx/lock-owner.key)"
grep '^owner_key_fp' <<< "$out"
out="$(owner lock init --pub-file /var/lib/orblx/lock-owner.key.pub "${ADMIN[@]}")"
has_line '^coord_lock on version' "$out" || fail "lock init"
echo "lock init done"
for name in a b; do
  out="$(owner lock sign "$name" --key-file /var/lib/orblx/lock-owner.key "${ADMIN[@]}")"
  echo "lock sign ${name} done"
done
owner_policy "$(policy_json "$HOOK_URL" | sed 's/"proto": "tcp"/"proto": "udp"/')"
echo "owner policy-set done"
echo "token pol admin-policy-set status $(client_call pol admin-policy-set "$(policy_json "$HOOK_URL")") want 200"
out="$(owner admin revoke b "${ADMIN[@]}")"; echo "revoke b done"
out="$(owner admin revoke-all a "${ADMIN[@]}")"; echo "revoke-all a done"
out="$(owner admin token-revoke "$READ_ID" "${ADMIN[@]}")"; echo "token-revoke done"
gate1_end="$(chain_len)"
echo "chain_records ${gate1_end}"
wait_received "$gate1_end" 10 || fail "gate 1: the receiver did not get every event"
snapshot
gate1_out="$(check "$gate1_start" "$gate1_end" latency "$LIMIT_MS")"
printf '%s\n' "$gate1_out"
has_line '^check latency ok' "$gate1_out" || fail "gate 1"
[[ "$gate1_end" -ge 20 ]] || fail "gate 1 has fewer than 20 events"
jq -r '.action' "$WORK/chain.jsonl" | sort | uniq -c | sort -k2

echo "=== [C] gate 2: HMAC-SHA256 signature ==="
grep -c '"sig_ok": true' "$WORK/received.jsonl" > "$WORK/sigok" || true
echo "receiver sig_ok_true $(cat "$WORK/sigok") of $(wc -l < "$WORK/received.jsonl")"
[[ "$(cat "$WORK/sigok")" == "$(wc -l < "$WORK/received.jsonl")" ]] || fail "gate 2: a body failed the check"
tamper_out="$(dc exec -T receiver sh -c '
set -e
set -- /recv/bodies/1-*.json
body="$1"; sig="${body%.json}.sig"
python3 /proof/audit-webhook-receiver.py verify "$body" "$sig"
python3 -c "import sys; d=open(sys.argv[1],\"rb\").read(); i=d.index(b\"\\\"seq\\\":1\"); open(\"/tmp/changed.json\",\"wb\").write(d[:i]+b\"\\\"seq\\\":2\"+d[i+7:])" "$body"
cmp -s "$body" /tmp/changed.json && echo same || echo changed
python3 /proof/audit-webhook-receiver.py verify /tmp/changed.json "$sig" || true
cp "$sig" /tmp/sig.txt
' 2>&1)"
printf '%s\n' "$tamper_out"
[[ "$(awk 'NR==1' <<< "$tamper_out")" == "verify ok" ]] || fail "gate 2: the original body did not verify"
[[ "$(awk 'NR==2' <<< "$tamper_out")" == "changed" ]] || fail "gate 2: the body did not change"
[[ "$(awk 'NR==3' <<< "$tamper_out")" == "verify fail" ]] || fail "gate 2: the changed body verified"
post_code="$(dc exec -T receiver sh -c 'curl -s -o /dev/null -w "%{http_code}" -H "Content-Type: application/json" -H "X-Orblx-Signature: $(cat /tmp/sig.txt)" --data-binary @/tmp/changed.json http://127.0.0.1:9000/hook')"
echo "receiver post changed_body_with_old_signature http ${post_code} want 401"
[[ "$post_code" == 401 ]] || fail "gate 2: the receiver took a changed body"
# A policy:write token cannot remove or add a webhook URL (only the owner SVID can).
for kind in remove add; do
  case "$kind" in
    remove) text="$(policy_json)" ;;
    add) text="$(policy_json "$HOOK_URL" "http://other:9000/hook")" ;;
  esac
  status="$(client_call pol admin-policy-set "$text")"
  echo "token pol webhooks_${kind} status ${status} want 403"
  [[ "$status" == 403 ]] || fail "KILL: a token changed the audit webhooks"
done
urls_now="$(dc exec -T coord cat /var/lib/orblx/policy.hujson)"
has_line 'other:9000' "$urls_now" && fail "the token added a webhook"
has_line 'receiver:9000/hook' "$urls_now" || fail "the token removed the webhook"
echo "gate2 ok"

echo "=== [C] gate 3: receiver down for ${DOWN_SECS} s ==="
g3_lo="$(chain_len)"
dc stop -t 1 receiver >/dev/null
down_at="$(now_ms)"
for _ in 1 2 3; do
  echo "token bench admin-nodes status $(client_call bench admin-nodes) want 200"
done
echo "token pol admin-revoke status $(client_call pol admin-revoke a) want 403"
owner_policy "$(policy_json "$HOOK_URL" | sed 's/"proto": "tcp"/"proto": "udp"/')"
echo "owner policy-set done"
g3_hi="$(chain_len)"
echo "events_while_down $((g3_hi - g3_lo))"
left=$(( DOWN_SECS * 1000 - ($(now_ms) - down_at) ))
if [[ "$left" -gt 0 ]]; then
  sleep "$(awk -v ms="$left" 'BEGIN {printf "%.3f", ms / 1000}')"
fi
logs="$(dc logs --no-log-prefix coord 2>&1)"
fails="$(grep -c "^audit webhook http://receiver:9000 seq ${g3_lo} failed" <<< "$logs" || true)"
echo "receiver_down_ms $(( $(now_ms) - down_at )) retries_for_seq_${g3_lo} ${fails}"
dc start receiver >/dev/null
up_at="$(now_ms)"
wait_received "$g3_hi" 20 || fail "gate 3: events were lost"
done_at="$(now_ms)"
echo "all_delivered_after_up_ms $((done_at - up_at)) (poll upper bound)"
snapshot
g3_out="$(check "$g3_lo" "$g3_hi" order)"
printf '%s\n' "$g3_out"
has_line '^check order ok' "$g3_out" || fail "gate 3"
all_out="$(check 0 "$g3_hi" all)"
printf '%s\n' "$all_out"
has_line '^check all ok' "$all_out" || fail "gate 3 (all records)"

echo "=== [C] gate 4: coordinator kill while events wait ==="
g4_lo="$(chain_len)"
dc stop -t 1 receiver >/dev/null
for _ in 1 2 3 4; do
  echo "token bench admin-nodes status $(client_call bench admin-nodes) want 200"
done
owner_policy "$(policy_json "$HOOK_URL")"
echo "owner policy-set done"
g4_mid="$(chain_len)"
cursor_before="$(dc exec -T coord sh -c 'cat /var/lib/orblx/audit-webhooks/*.json')"
echo "cursor_before ${cursor_before}"
echo "events_waiting $((g4_mid - g4_lo))"
dc kill -s SIGKILL coord >/dev/null
dc start coord >/dev/null
# The start can give the coordinator a new address.
coord_ip="$(dc exec -T client getent ahostsv4 coord | read_all awk '{print $1; exit}')"
COORD="${coord_ip}:443"
ADMIN=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)
for _ in $(seq 1 60); do
  logs="$(dc logs --no-log-prefix coord 2>&1)"
  [[ "$(grep -c '^coord listen' <<< "$logs" || true)" -ge 2 ]] && break
  sleep 0.5
done
echo "coord restarted ${COORD}"
cursor_after="$(dc exec -T coord sh -c 'cat /var/lib/orblx/audit-webhooks/*.json')"
echo "cursor_after_restart ${cursor_after}"
echo "token bench admin-nodes status $(client_call bench admin-nodes) want 200"
g4_hi="$(chain_len)"
dc start receiver >/dev/null
wait_received "$g4_hi" 20 || fail "gate 4: events were lost"
snapshot
g4_out="$(check "$g4_lo" "$g4_hi" restart)"
printf '%s\n' "$g4_out"
has_line '^check restart ok' "$g4_out" || fail "gate 4"
all_out="$(check 0 "$g4_hi" all)"
printf '%s\n' "$all_out"
has_line '^check all ok' "$all_out" || fail "gate 4 (all records)"
echo "received_lines $(wc -l < "$WORK/received.jsonl") chain_records ${g4_hi}"
[[ "$(wc -l < "$WORK/received.jsonl")" == "$g4_hi" ]] || fail "gate 4: received lines differ from chain records"

echo "=== [C] gate 5: admin latency, webhooks on, dead, off ==="
bench() {
  dc exec -T client sh -c "
i=0
while [ \$i -lt 3 ]; do orblx admin call admin-nodes --token-file /tokens/bench --coord $COORD --bundle /coord-state/trust-bundle.pem >/dev/null 2>&1; i=\$((i+1)); done
i=0
while [ \$i -lt $BENCH_N ]; do
  s=\$(date +%s%N)
  if orblx admin call admin-nodes --token-file /tokens/bench --coord $COORD --bundle /coord-state/trust-bundle.pem >/dev/null 2>&1; then r=ok; else r=fail; fi
  e=\$(date +%s%N)
  echo \"\$r \$(( (e - s) / 1000 ))\"
  i=\$((i+1))
done"
}
summary() {
  awk '{ if ($1 == "ok") ok++; else bad++; print $2 > "/dev/stderr" } END { printf "ok %d fail %d\n", ok, bad + 0 }' "$1" 2> "$1.us"
  sort -n "$1.us" | awk '{a[NR] = $1} END {printf "p50_ms %.3f p90_ms %.3f\n", a[int((NR + 1) / 2)] / 1000, a[int(NR * 0.9 + 0.5)] / 1000}'
}
bench > "$WORK/bench-on.txt"
on_sum="$(summary "$WORK/bench-on.txt" | tr '\n' ' ')"
echo "mode on (receiver up) n ${BENCH_N} ${on_sum}"
dc stop -t 1 receiver >/dev/null
owner_policy "$(policy_json "$HOOK_URL" "$DEAD_URL")"
sleep 1
dead_t0="$(now_ms)"
bench > "$WORK/bench-dead.txt"
dead_sum="$(summary "$WORK/bench-dead.txt" | tr '\n' ' ')"
echo "mode dead (receiver stopped and ${DEAD_URL%/hook} black hole) n ${BENCH_N} ${dead_sum} wall_ms $(( $(now_ms) - dead_t0 ))"
owner_policy "$(policy_json "$HOOK_URL" "$DEAD_URL" | sed 's/"proto": "tcp"/"proto": "udp"/')"
echo "owner policy-set with a dead receiver ok"
logs="$(dc logs --no-log-prefix coord 2>&1)"
echo "dead_receiver_failures_logged $(grep -c '^audit webhook .* failed step' <<< "$logs" || true)"
grep -o '^audit webhook [^ ]* seq [0-9]* failed step [a-z-]*' <<< "$logs" | awk '{print $3, $8}' | sort | uniq -c || true
owner_policy "$(policy_json)"
sleep 1
bench > "$WORK/bench-off.txt"
off_sum="$(summary "$WORK/bench-off.txt" | tr '\n' ' ')"
echo "mode off (no webhooks) n ${BENCH_N} ${off_sum}"
p50() { awk '{for (i = 1; i < NF; i++) if ($i == "p50_ms") print $(i + 1)}' <<< "$1"; }
fails() { awk '{for (i = 1; i < NF; i++) if ($i == "fail") print $(i + 1)}' <<< "$1"; }
on_p50="$(p50 "$on_sum")"; dead_p50="$(p50 "$dead_sum")"; off_p50="$(p50 "$off_sum")"
gate5="$(awk -v on="$on_p50" -v dead="$dead_p50" -v off="$off_p50" 'BEGIN {
  d1 = on - off; d2 = dead - off
  printf "p50_delta_on_ms %.3f p50_delta_dead_ms %.3f limit_ms 10 %s\n", d1, d2, (d1 <= 10 && d2 <= 10) ? "ok" : "fail" }')"
echo "gate5 ${gate5}"
[[ "$(fails "$on_sum")" == 0 && "$(fails "$dead_sum")" == 0 && "$(fails "$off_sum")" == 0 ]] \
  || fail "KILL: an admin request failed (dead receiver)"
has_line ' ok$' "$gate5" || fail "gate 5: the admin latency moved more than 10 ms"
cursor_files="$(dc exec -T coord sh -c 'ls /var/lib/orblx/audit-webhooks | wc -l')"
echo "cursor_files_after_webhooks_off ${cursor_files} want 0"

echo "=== [C] gate 6: no secret or token text; chain check ==="
out="$(owner admin audit --verify "${ADMIN[@]}")"
printf '%s\n' "$out"
has_line '^verify ok' "$out" || fail "audit --verify did not print ok"
verify_out="$(dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl)" \
  || fail "audit verify-config failed"
[[ "${verify_out%%$'\n'*}" == ok ]] || fail "audit verify-config did not print ok"
echo "audit verify-config ok $(grep '^records ' <<< "$verify_out" || true)"
# Needles: the webhook secret and the secret part of each API token. The script does not print them.
dc start receiver >/dev/null
dc exec -T receiver cat /secret/webhook.key > "$WORK/needles"
dc exec -T client sh -c 'for f in /tokens/read /tokens/pol /tokens/bench; do cut -d. -f2 "$f"; done' >> "$WORK/needles"
[[ "$(wc -l < "$WORK/needles")" -eq 4 ]] || fail "the needles are not readable"
control_secret="$(dc exec -T receiver sh -c 'cat > /tmp/needles; grep -lF -f /tmp/needles /secret/webhook.key | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
control_tokens="$(dc exec -T client sh -c 'cat > /tmp/needles; grep -lF -f /tmp/needles /tokens/read /tokens/pol /tokens/bench | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
echo "secret_check control_secret_file ${control_secret} want 1 control_token_files ${control_tokens} want 3"
[[ "$control_secret" == 1 && "$control_tokens" == 3 ]] || fail "the secret check does not find the control files"
hits_state="$(dc exec -T coord sh -c 'cat > /tmp/needles; grep -rlF -f /tmp/needles /var/lib/orblx | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
hits_recv="$(dc exec -T receiver sh -c 'cat > /tmp/needles; grep -rlF -f /tmp/needles /recv | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
recv_bodies="$(dc exec -T receiver sh -c 'ls /recv/bodies | wc -l')"
dc logs --no-log-prefix > "$WORK/logs.txt" 2>&1 || true
dc exec -T coord cat /var/lib/orblx/config-audit.jsonl > "$WORK/chain.jsonl"
hits_logs="$(grep -cF -f "$WORK/needles" "$WORK/logs.txt" || true)"
hits_chain="$(grep -cF -f "$WORK/needles" "$WORK/chain.jsonl" || true)"
hits_proof=0
if [[ -n "${PROOF_LOG:-}" && -f "$PROOF_LOG" ]]; then
  hits_proof="$(grep -cF -f "$WORK/needles" "$PROOF_LOG" || true)"
fi
rm -f "$WORK/needles"
echo "secret_hits coord_state_files ${hits_state} receiver_files ${hits_recv} (bodies ${recv_bodies}) container_logs ${hits_logs} (lines $(wc -l < "$WORK/logs.txt")) audit_records ${hits_chain} (records $(wc -l < "$WORK/chain.jsonl")) proof_log ${hits_proof}"
[[ "$hits_state" == 0 && "$hits_recv" == 0 && "$hits_logs" == 0 && "$hits_chain" == 0 && "$hits_proof" == 0 ]] \
  || fail "a secret or token text was found"

echo "proof_ok"
