#!/usr/bin/env bash
# W25-13 proof: the coordinator streams each config audit record to SIEM sinks.
# The host is REAL. coord, siemhttp, syslog, badsyslog, owner, and client are [C] containers
# (compose.siem-streaming.yml). The receivers stand in for a SIEM.
# Sinks: hec (Splunk HEC), datadog, and ndjson (HTTPS batch POST) and syslog (RFC 5424 over TLS).
# The sink "bad" is syslog TLS to a server with a certificate from a different CA.
# Gates:
#   1. 1000 audit events reach each sink in 10 s or less. Each record has seq, id, and the
#      chain hash. 0 gaps and 0 duplicates.
#   2. orblx-siem-verify.py reads only the sink output and checks the hash chain again.
#      A changed, a removed, or a removed last record fails the check.
#   3. All sinks are down for 60 s. After they come back, the backlog arrives in order with
#      0 lost and 0 duplicates. The admin p50 with dead sinks is within 10 ms of sinks off.
#   4. A coordinator kill (SIGKILL) while records wait: the delivery starts again at the
#      durable cursor with 0 lost and 0 duplicates.
#   5. The sink "bad" gets 0 records and the chain has 1 sink-error record for it.
#   6. A policy:write token cannot add, change, or remove a sink (403, reason sinks).
#      The sink credentials are only in files: 0 hits in logs, state, sink output, and the
#      proof log, with a control check that finds the credential files.
# Gate 7 (the W23-4 gates) uses nat-realism.sh.
# The script never prints a credential, a key, or a token. It prints proof_ok.
# Environment:
#   SIEM_PROJECT    Compose project name (default orblx-w25m-siem).
#   SIEM_IMAGE      Image tag (default orblx-w25m-siem:local).
#   SIEM_BIN        An orblx binary to use. Without it, the script builds target/debug/orblx.
#   SIEM_EVENTS     The events in gate 1 (default 1000).
#   SIEM_DOWN_SECS  The sink down time in gate 3 (default 60).
#   SIEM_BENCH_N    The admin calls for each mode in gate 3 (default 40).
#   PROOF_LOG       The log file of this run. The credential check also reads this file.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.siem-streaming.yml"
SIEM_PROJECT="${SIEM_PROJECT:-orblx-w25m-siem}"
SIEM_IMAGE="${SIEM_IMAGE:-orblx-w25m-siem:local}"
EVENTS="${SIEM_EVENTS:-1000}"
DOWN_SECS="${SIEM_DOWN_SECS:-60}"
BENCH_N="${SIEM_BENCH_N:-40}"
OWNER_ID="spiffe://orblx.local/node/owner"
LIMIT_MS=10000
SINKS=(hec datadog ndjson syslog)
VERIFY="$ROOT/scripts/siem/orblx-siem-verify.py"
WORK="$(mktemp -d)"
LAB="$WORK/lab"
ENV_FILE="$WORK/env"
mkdir -p "$LAB/sinks" "$LAB/recv-conf" "$WORK/ca"
chmod 755 "$WORK" "$LAB" "$LAB/sinks" "$LAB/recv-conf"
printf 'SIEM_IMAGE=%s\nSIEM_LAB=%s\n' "$SIEM_IMAGE" "$LAB" > "$ENV_FILE"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  as_root docker compose -p "$SIEM_PROJECT" --env-file "$ENV_FILE" --progress quiet --profile nodes -f "$FILE" "$@"
}

# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"
cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "siem-streaming:${SIEM_PROJECT}" "${SIEM_PROJECT}-"

# No pipe into head or grep -q: with pipefail, an early reader can fail the pipe (SIGPIPE).
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
  echo "---- coord log (last 40 lines, no config audit lines) ----" >&2
  grep -v '^config audit ' <<< "$logs" | tail -n 40 >&2 || true
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

SINK_HEC='{"name": "hec", "type": "https", "url": "https://siemhttp:8088/services/collector/event", "format": "splunk-hec", "credentialFile": "hec.token", "caFile": "ca.pem"}'
SINK_DD='{"name": "datadog", "type": "https", "url": "https://siemhttp:8088/api/v2/logs", "format": "datadog", "credentialFile": "datadog.token", "caFile": "ca.pem"}'
SINK_ND='{"name": "ndjson", "type": "https", "url": "https://siemhttp:8088/ndjson", "format": "ndjson", "credentialFile": "ndjson.token", "caFile": "ca.pem"}'
SINK_SYS='{"name": "syslog", "type": "syslog-tls", "address": "syslog:6514", "caFile": "ca.pem"}'
SINK_BAD='{"name": "bad", "type": "syslog-tls", "address": "badsyslog:6514", "caFile": "ca.pem"}'
ALL_SINKS="${SINK_HEC}, ${SINK_DD}, ${SINK_ND}, ${SINK_SYS}, ${SINK_BAD}"

# policy_json SINKS_TEXT [PROTO] prints a policy with these sinks.
policy_json() {
  printf '{"nodeApproval": false, "owners": ["%s"], "auditSinks": [%s], "acls": [{"action": "accept", "src": ["*"], "proto": "%s", "dst": ["*:*"]}]}\n' \
    "$OWNER_ID" "$1" "${2:-tcp}"
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

# The receiver volume is read through badsyslog. The proof never stops badsyslog.
recv_sh() {
  dc exec -T badsyslog sh -c "$1"
}

arrivals() {
  recv_sh "if [ -f /recv/$1/arrivals.jsonl ]; then wc -l < /recv/$1/arrivals.jsonl; else echo 0; fi"
}

# wait_all SECS: wait until each sink has every chain record. Print the wait in ms.
wait_all() {
  local secs="$1" start want sink got ok
  start="$(now_ms)"
  for _ in $(seq 1 $((secs * 5))); do
    want="$(chain_len)"
    ok=1
    for sink in "${SINKS[@]}"; do
      got="$(arrivals "$sink")"
      [[ "$got" -ge "$want" ]] || ok=0
    done
    if [[ "$ok" == 1 ]]; then
      echo "all_sinks_have ${want} records wait_ms $(( $(now_ms) - start ))"
      return 0
    fi
    sleep 0.2
  done
  for sink in "${SINKS[@]}"; do
    echo "sink ${sink} arrivals $(arrivals "$sink") want ${want}" >&2
  done
  return 1
}

# Copy the chain, the sink output, and the coordinator log with timestamps into WORK.
snapshot() {
  dc exec -T coord cat /var/lib/orblx/config-audit.jsonl > "$WORK/chain.jsonl"
  rm -rf "$WORK/recv"
  mkdir -p "$WORK/recv"
  recv_sh 'tar -C /recv -cf - .' | tar -C "$WORK/recv" -xf -
  dc logs -t --no-log-prefix coord > "$WORK/coord-ts.log" 2>&1 || true
}

# make_events N: N token calls from the client (each writes one token-use record).
make_events() {
  local want="$1" before now left
  before="$(chain_len)"
  for _ in 1 2 3; do
    now="$(chain_len)"
    left=$(( want - (now - before) ))
    [[ "$left" -le 0 ]] && break
    dc exec -T client sh -c "seq 1 $left | xargs -P 8 -I{} orblx admin call admin-nodes --token-file /tokens/bench --coord $COORD --bundle /coord-state/trust-bundle.pem >/dev/null 2>&1" || true
  done
  now="$(chain_len)"
  echo "events_made $(( now - before )) want ${want}"
}

cat > "$WORK/arrivals.py" <<'PY'
import datetime
import json
import re
import sys

chain_file, recv_dir, log_file, lo, hi, limit = sys.argv[1:7]
sinks = sys.argv[7:]
lo, hi, limit = int(lo), int(hi), float(limit)
chain = [json.loads(line) for line in open(chain_file) if line.strip()]
written = {}
pat = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z config audit (\d+) ")
for line in open(log_file, errors="replace"):
    match = pat.match(line)
    if not match:
        continue
    base = datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    base = base.replace(tzinfo=datetime.timezone.utc)
    frac = (match.group(2) or "0")[:6].ljust(6, "0")
    written.setdefault(int(match.group(3)), base.timestamp() * 1000.0 + int(frac) / 1000.0)
all_ok = True
for sink in sinks:
    rows = [json.loads(line) for line in open("%s/%s/arrivals.jsonl" % (recv_dir, sink)) if line.strip()]
    seqs = [row["seq"] for row in rows]
    dups = len(seqs) - len(set(seqs))
    order_ok = all(a < b for a, b in zip(seqs, seqs[1:]))
    first = {}
    for row in rows:
        first.setdefault(row["seq"], row["recv_ms"])
    want = range(lo, hi)
    got = [seq for seq in want if seq in first]
    gaps = len(want) - len(got)
    lat = sorted(first[seq] - written.get(seq, float("nan")) for seq in got)
    known = [ms for ms in lat if ms == ms]
    span = (max(first[seq] for seq in got) - min(written.get(seq, float("inf")) for seq in got)) if got else 0
    ok = gaps == 0 and dups == 0 and order_ok and len(known) == len(got) and all(ms <= limit for ms in known)
    all_ok = all_ok and ok
    if known:
        print("sink %s window %d..%d delivered %d of %d gaps %d duplicates %d order %s latency_ms min %.1f p50 %.1f p99 %.1f max %.1f first_write_to_last_arrival_ms %.1f %s"
              % (sink, lo, hi - 1, len(got), len(want), gaps, dups, "ok" if order_ok else "fail",
                 known[0], known[len(known) // 2], known[min(len(known) - 1, int(len(known) * 0.99))], known[-1], span,
                 "ok" if ok else "fail"))
    else:
        print("sink %s window %d..%d delivered %d of %d gaps %d duplicates %d order %s no latency %s"
              % (sink, lo, hi - 1, len(got), len(want), gaps, dups, "ok" if order_ok else "fail", "ok" if ok else "fail"))
print("arrivals %s" % ("ok" if all_ok else "fail"))
PY

cat > "$WORK/tamper.py" <<'PY'
import json
import sys

fmt, mode, src, dst = sys.argv[1:5]
data = open(src, "rb").read()


def frames(raw):
    out, at = [], 0
    while at < len(raw):
        space = raw.index(b" ", at)
        end = space + 1 + int(raw[at:space])
        out.append(raw[at:end])
        at = end
    return out


if mode == "change":
    # Change one record field. The byte length does not change, so a frame stays valid.
    needle = b"scope nodes:read"
    at = data.index(needle, len(data) // 2)
    data = data[:at] + b"scope nodes:reax" + data[at + len(needle):]
elif fmt == "syslog":
    items = frames(data)
    index = len(items) // 2 if mode == "delete-middle" else len(items) - 1
    del items[index]
    data = b"".join(items)
elif fmt == "datadog":
    arrays = [json.loads(line) for line in data.decode().split("\n") if line.strip()]
    if mode == "delete-middle":
        arrays[len(arrays) // 2].pop(len(arrays[len(arrays) // 2]) // 2)
    else:
        arrays[-1].pop()
    data = "".join(json.dumps(array, separators=(",", ":")) + "\n" for array in arrays if array).encode()
else:
    lines = [line for line in data.split(b"\n") if line.strip()]
    index = len(lines) // 2 if mode == "delete-middle" else len(lines) - 1
    del lines[index]
    data = b"".join(line + b"\n" for line in lines)
open(dst, "wb").write(data)
PY

verify_sink() {
  local sink="$1"
  shift
  local fmt="$sink"
  python3 "$VERIFY" --format "$fmt" "$@"
}

echo "=== [REAL] host ==="
uname -sm
echo "commit $(git rev-parse HEAD)"

echo "=== [C] build image ${SIEM_IMAGE} (project ${SIEM_PROJECT}) ==="
bin="${SIEM_BIN:-}"
if [[ -z "$bin" ]]; then
  cargo build -p orblx-cli --bin orblx --locked
  bin="$ROOT/target/debug/orblx"
fi
[[ -x "$bin" ]] || fail "the orblx binary $bin is missing"
# shellcheck source=stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$bin")"
as_root docker build -q -t "$SIEM_IMAGE" "$image_dir" >/dev/null
rm -rf "$image_dir"

echo "=== [C] lab CA, server certificates, and sink credentials (files only) ==="
ca() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 \
    -keyout "$WORK/ca/$1.key" -out "$WORK/ca/$1.pem" -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
leaf() {
  local name="$1" issuer="$2" san="$3"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$LAB/recv-conf/${name}.key" -out "$WORK/ca/${name}.csr" -subj "/CN=${name}" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$san" > "$WORK/ca/${name}.ext"
  openssl x509 -req -in "$WORK/ca/${name}.csr" -CA "$WORK/ca/${issuer}.pem" -CAkey "$WORK/ca/${issuer}.key" \
    -CAcreateserial -days 2 -out "$LAB/recv-conf/${name}.pem" -extfile "$WORK/ca/${name}.ext" 2>/dev/null
}
ca lab "orblx siem lab ca"
ca other "orblx other ca"
leaf good lab "DNS:siemhttp,DNS:syslog"
leaf bad other "DNS:badsyslog"
cp "$WORK/ca/lab.pem" "$LAB/sinks/ca.pem"
chmod 644 "$LAB/recv-conf/"* "$LAB/sinks/ca.pem"
for name in hec datadog ndjson; do
  (umask 077; python3 -c 'import secrets; print(secrets.token_hex(24))' > "$LAB/sinks/${name}.token")
  chmod 644 "$LAB/sinks/${name}.token"
done
openssl x509 -in "$LAB/recv-conf/good.pem" -noout -subject -issuer -ext subjectAltName 2>/dev/null | tr '\n' ' '; echo
openssl x509 -in "$LAB/recv-conf/bad.pem" -noout -subject -issuer -ext subjectAltName 2>/dev/null | tr '\n' ' '; echo
echo "credential_files $(ls "$LAB/sinks" | grep -c '\.token$') bytes_with_line_end $(cat "$LAB"/sinks/*.token | wc -c)"

echo "=== [C] start receivers and coordinator (no sinks yet) ==="
dc down -v --remove-orphans >/dev/null 2>&1 || true
policy_json "" > "$WORK/policy.json"
dc run --rm --no-deps -T --entrypoint sh coord -c 'mkdir -p /var/lib/orblx && cat > /var/lib/orblx/policy.hujson' \
  < "$WORK/policy.json"
dc up -d siemhttp syslog badsyslog
for _ in $(seq 1 50); do
  logs="$(dc logs --no-log-prefix siemhttp syslog badsyslog 2>&1 || true)"
  [[ "$(grep -c '^receiver .* listen' <<< "$logs" || true)" -ge 3 ]] && break
  sleep 0.2
done
dc up -d coord client
for _ in $(seq 1 60); do
  dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem && break
  sleep 1
done
dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem || fail "no trust bundle"
coord_ip="$(dc exec -T client getent ahostsv4 coord | awk '{print $1; exit}')"
COORD="${coord_ip}:443"
ADMIN=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)
echo "coord ${COORD}"
out="$(dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 600 --out /var/lib/orblx/tokens/owner)"
grep -E '^token_id' <<< "$out" || true
out="$(dc run --rm --no-deps -T owner coord enroll --name owner --coord "$COORD" \
  --bundle /coord-state/trust-bundle.pem --token-file /coord-state/tokens/owner \
  --state /var/lib/orblx --endpoint owner:443)"
grep -E '^enrolled' <<< "$out" || fail "the owner did not enroll"
create_token() {
  owner admin token-create --scope "$2" --ttl "$3" --out "/tokens/$1" "${ADMIN[@]}"
}
out="$(create_token pol policy:write 30m)"; grep '^token_id' <<< "$out"
out="$(create_token bench nodes:read 30m)"; grep '^token_id' <<< "$out"
echo "token bench admin-nodes status $(client_call bench admin-nodes) want 200"

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
p50() { awk '{for (i = 1; i < NF; i++) if ($i == "p50_ms") print $(i + 1)}' <<< "$1"; }
fails() { awk '{for (i = 1; i < NF; i++) if ($i == "fail") print $(i + 1)}' <<< "$1"; }

echo "=== [C] gate 3 baseline: admin latency with no sinks ==="
bench > "$WORK/bench-off.txt"
off_sum="$(summary "$WORK/bench-off.txt" | tr '\n' ' ')"
echo "mode off (no sinks) n ${BENCH_N} ${off_sum}"

echo "=== [C] owner adds the sinks ==="
owner_policy "$(policy_json "$ALL_SINKS")"
sleep 1
logs="$(dc logs --no-log-prefix coord 2>&1)"
grep '^audit sink' <<< "$logs" || true
for sink in "${SINKS[@]}" bad; do
  has_line "^audit sink added ${sink} next_seq 0" "$logs" || fail "the coordinator did not add the sink ${sink}"
done
wait_all 20 || fail "the sinks did not get the start of the chain"

echo "=== [C] gate 1: ${EVENTS} events reach each sink in ${LIMIT_MS} ms or less ==="
g1_lo="$(chain_len)"
make_events "$EVENTS"
g1_hi=$(( g1_lo + EVENTS ))
[[ "$(chain_len)" -ge "$g1_hi" ]] || fail "gate 1: the client did not make ${EVENTS} events"
wait_all 30 || fail "gate 1: a sink did not get every event"
snapshot
g1_out="$(python3 "$WORK/arrivals.py" "$WORK/chain.jsonl" "$WORK/recv" "$WORK/coord-ts.log" "$g1_lo" "$g1_hi" "$LIMIT_MS" "${SINKS[@]}")"
printf '%s\n' "$g1_out"
has_line '^arrivals ok' "$g1_out" || fail "gate 1"
for sink in "${SINKS[@]}"; do
  out="$(verify_sink "$sink" "$WORK/recv/$sink/sink.out")" || fail "gate 1: ${sink} did not verify: ${out}"
  echo "${sink} ${out}"
done
python3 - "$WORK/recv/hec/sink.out" <<'PY'
import json, sys
line = next(l for l in open(sys.argv[1]) if l.strip())
event = json.loads(line)
body = event["event"]
print("hec_record_fields", " ".join(sorted(body)), "record:", " ".join(sorted(body["record"])))
PY

echo "=== [C] gate 2: chain check from sink output only, with changed and removed records ==="
tip="$(tail -n 1 "$WORK/chain.jsonl" | jq -r '.hash')"
count="$(wc -l < "$WORK/chain.jsonl")"
echo "chain_records ${count} tip_prefix ${tip:0:16}"
g2_fail=0
for sink in "${SINKS[@]}"; do
  out="$(verify_sink "$sink" --count "$count" --tip "$tip" "$WORK/recv/$sink/sink.out")" || g2_fail=1
  echo "${sink} original ${out}"
  for mode in change delete-middle delete-last; do
    python3 "$WORK/tamper.py" "$sink" "$mode" "$WORK/recv/$sink/sink.out" "$WORK/tampered.out"
    if out="$(verify_sink "$sink" --count "$count" --tip "$tip" "$WORK/tampered.out")"; then
      g2_fail=1
    fi
    echo "${sink} ${mode} ${out}"
  done
done
[[ "$g2_fail" == 0 ]] || fail "gate 2"
echo "gate2 ok"

echo "=== [C] gate 3: admin latency with sinks on ==="
bench > "$WORK/bench-on.txt"
on_sum="$(summary "$WORK/bench-on.txt" | tr '\n' ' ')"
echo "mode on (sinks up) n ${BENCH_N} ${on_sum}"
wait_all 30 || fail "gate 3: the sinks did not catch up before the outage"

echo "=== [C] gate 3: all sinks down for ${DOWN_SECS} s ==="
g3_lo="$(chain_len)"
dc stop -t 1 siemhttp syslog >/dev/null
down_at="$(now_ms)"
bench > "$WORK/bench-dead.txt"
dead_sum="$(summary "$WORK/bench-dead.txt" | tr '\n' ' ')"
echo "mode dead (siemhttp and syslog stopped) n ${BENCH_N} ${dead_sum}"
make_events 200
owner_policy "$(policy_json "$ALL_SINKS" udp)"
echo "owner policy-set with dead sinks ok"
g3_mid="$(chain_len)"
echo "events_while_down $((g3_mid - g3_lo))"
left=$(( DOWN_SECS * 1000 - ($(now_ms) - down_at) ))
if [[ "$left" -gt 0 ]]; then
  sleep "$(awk -v ms="$left" 'BEGIN {printf "%.3f", ms / 1000}')"
fi
logs="$(dc logs --no-log-prefix coord 2>&1)"
echo "sinks_down_ms $(( $(now_ms) - down_at ))"
grep -o '^audit sink [a-z]* seq [0-9]* failed step [a-z-]*' <<< "$logs" | awk '{print $3, "step", $8}' | sort | uniq -c || true
dc start siemhttp syslog >/dev/null
wait_all 60 || fail "gate 3: records were lost"
g3_hi="$(chain_len)"
snapshot
g3_out="$(python3 "$WORK/arrivals.py" "$WORK/chain.jsonl" "$WORK/recv" "$WORK/coord-ts.log" "$g3_lo" "$g3_hi" 999999999 "${SINKS[@]}")"
printf '%s\n' "$g3_out"
has_line '^arrivals ok' "$g3_out" || fail "gate 3: order, gaps, or duplicates"
for sink in "${SINKS[@]}"; do
  out="$(verify_sink "$sink" --count "$g3_hi" "$WORK/recv/$sink/sink.out")" || fail "gate 3: ${sink} did not verify: ${out}"
  echo "${sink} ${out}"
done
gate3="$(awk -v on="$(p50 "$on_sum")" -v dead="$(p50 "$dead_sum")" -v off="$(p50 "$off_sum")" 'BEGIN {
  d1 = on - off; d2 = dead - off
  printf "p50_off_ms %.3f p50_on_ms %.3f p50_dead_ms %.3f p50_delta_on_ms %.3f p50_delta_dead_ms %.3f limit_ms 10 %s\n", off, on, dead, d1, d2, (d1 <= 10 && d2 <= 10) ? "ok" : "fail" }')"
echo "gate3 ${gate3}"
[[ "$(fails "$on_sum")" == 0 && "$(fails "$dead_sum")" == 0 && "$(fails "$off_sum")" == 0 ]] \
  || fail "an admin request failed (dead sinks)"
has_line ' ok$' "$gate3" || fail "gate 3: the admin p50 moved more than 10 ms"

echo "=== [C] gate 4: coordinator kill while records wait ==="
g4_lo="$(chain_len)"
dc stop -t 1 siemhttp syslog >/dev/null
make_events 100
g4_mid="$(chain_len)"
echo "events_waiting $((g4_mid - g4_lo))"
cursor_before="$(dc exec -T coord sh -c 'cat /var/lib/orblx/audit-webhooks/*.json; echo')"
printf 'cursor_before %s\n' "$cursor_before" | sed 's/}{/}\ncursor_before {/g'
dc kill -s SIGKILL coord >/dev/null
dc start coord >/dev/null
coord_ip="$(dc exec -T client getent ahostsv4 coord | awk '{print $1; exit}')"
COORD="${coord_ip}:443"
ADMIN=(--coord "$COORD" --state /var/lib/orblx --bundle /var/lib/orblx/bundle.pem)
for _ in $(seq 1 60); do
  logs="$(dc logs --no-log-prefix coord 2>&1)"
  [[ "$(grep -c '^coord listen' <<< "$logs" || true)" -ge 2 ]] && break
  sleep 0.5
done
echo "coord restarted ${COORD}"
sleep 1
cursor_after="$(dc exec -T coord sh -c 'cat /var/lib/orblx/audit-webhooks/*.json; echo')"
printf 'cursor_after_restart %s\n' "$cursor_after" | sed 's/}{/}\ncursor_after_restart {/g'
echo "token bench admin-nodes status $(client_call bench admin-nodes) want 200"
dc start siemhttp syslog >/dev/null
wait_all 60 || fail "gate 4: records were lost"
g4_hi="$(chain_len)"
snapshot
g4_out="$(python3 "$WORK/arrivals.py" "$WORK/chain.jsonl" "$WORK/recv" "$WORK/coord-ts.log" "$g4_lo" "$g4_hi" 999999999 "${SINKS[@]}")"
printf '%s\n' "$g4_out"
has_line '^arrivals ok' "$g4_out" || fail "gate 4"
for sink in "${SINKS[@]}"; do
  out="$(verify_sink "$sink" --count "$g4_hi" --tip "$(tail -n 1 "$WORK/chain.jsonl" | jq -r '.hash')" "$WORK/recv/$sink/sink.out")" \
    || fail "gate 4: ${sink} did not verify: ${out}"
  echo "${sink} ${out} arrivals_lines $(wc -l < "$WORK/recv/$sink/arrivals.jsonl")"
done

echo "=== [C] gate 5: the sink with a bad certificate ==="
bad_frames="$(recv_sh 'if [ -f /recv/bad/arrivals.jsonl ]; then wc -l < /recv/bad/arrivals.jsonl; else echo 0; fi')"
bad_hs="$(recv_sh 'if [ -f /recv/bad/handshake-fail.txt ]; then wc -l < /recv/bad/handshake-fail.txt; else echo 0; fi')"
logs="$(dc logs --no-log-prefix coord 2>&1)"
bad_tries="$(grep -c '^audit sink bad seq 0 failed step tls ' <<< "$logs" || true)"
jq -c 'select(.action == "sink-error") | {index, target, detail}' "$WORK/chain.jsonl"
bad_records="$(jq -r 'select(.action == "sink-error" and .target == "bad") | .index' "$WORK/chain.jsonl" | wc -l)"
echo "bad_sink records_received ${bad_frames} want 0 server_handshake_failures ${bad_hs} coord_tls_failures_logged ${bad_tries} sink_error_records ${bad_records} want 1"
[[ "$bad_frames" == 0 && "$bad_records" == 1 && "$bad_hs" -ge 1 ]] || fail "gate 5"
echo "gate5 ok"

echo "=== [C] gate 6: only an owner changes sinks; credentials only in files ==="
deny_before="$(jq -r 'select(.action == "token-deny") | .detail' "$WORK/chain.jsonl" | grep -c 'reason sinks' || true)"
for kind in remove add change; do
  case "$kind" in
    remove) text="$(policy_json "${SINK_HEC}, ${SINK_DD}, ${SINK_ND}, ${SINK_SYS}" udp)" ;;
    add) text="$(policy_json "${ALL_SINKS}, {\"name\": \"extra\", \"type\": \"syslog-tls\", \"address\": \"syslog:6514\", \"caFile\": \"ca.pem\"}" udp)" ;;
    change) text="$(policy_json "${ALL_SINKS/badsyslog:6514/syslog:6514}" udp)" ;;
  esac
  status="$(client_call pol admin-policy-set "$text")"
  echo "token pol sinks_${kind} status ${status} want 403"
  [[ "$status" == 403 ]] || fail "gate 6: a token changed the sinks"
done
status="$(client_call pol admin-policy-set "$(policy_json "$ALL_SINKS" tcp)")"
echo "token pol same_sinks_new_acl status ${status} want 200"
[[ "$status" == 200 ]] || fail "gate 6: a token could not set a policy with the same sinks"
dc exec -T coord cat /var/lib/orblx/config-audit.jsonl > "$WORK/chain.jsonl"
deny_after="$(jq -r 'select(.action == "token-deny") | .detail' "$WORK/chain.jsonl" | grep -c 'reason sinks' || true)"
echo "token_deny_reason_sinks_records $((deny_after - deny_before)) want 3"
[[ $((deny_after - deny_before)) == 3 ]] || fail "gate 6: the deny records are missing"
policy_now="$(dc exec -T coord cat /var/lib/orblx/policy.hujson)"
has_line '"extra"' "$policy_now" && fail "gate 6: the token added a sink"
has_line 'badsyslog:6514' "$policy_now" || fail "gate 6: the token changed a sink"
out="$(owner admin audit --verify "${ADMIN[@]}")"
has_line '^verify ok' "$out" || fail "audit --verify did not print ok"
echo "owner admin audit --verify ok"
verify_out="$(dc exec -T coord orblx audit verify-config --file /var/lib/orblx/config-audit.jsonl)" \
  || fail "audit verify-config failed"
[[ "${verify_out%%$'\n'*}" == ok ]] || fail "audit verify-config did not print ok"
echo "audit verify-config ok $(grep '^records ' <<< "$verify_out" || true)"
# Needles: the three sink credentials and the secret part of each API token. The script does not print them.
cat "$LAB"/sinks/*.token > "$WORK/needles"
dc exec -T client sh -c 'for f in /tokens/pol /tokens/bench; do cut -d. -f2 "$f"; done' >> "$WORK/needles"
[[ "$(wc -l < "$WORK/needles")" -eq 5 ]] || fail "the needles are not readable"
control_cred="$(dc exec -T coord sh -c 'cat > /tmp/needles; grep -lF -f /tmp/needles /sinks/* | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
control_tokens="$(dc exec -T client sh -c 'cat > /tmp/needles; grep -lF -f /tmp/needles /tokens/pol /tokens/bench | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
echo "credential_check control_credential_files ${control_cred} want 3 control_token_files ${control_tokens} want 2"
[[ "$control_cred" == 3 && "$control_tokens" == 2 ]] || fail "the credential check does not find the control files"
hits_state="$(dc exec -T coord sh -c 'cat > /tmp/needles; grep -rlF -f /tmp/needles /var/lib/orblx | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
hits_recv="$(recv_sh 'cat > /tmp/needles; grep -rlF -f /tmp/needles /recv | wc -l; rm -f /tmp/needles' < "$WORK/needles")"
recv_files="$(recv_sh 'find /recv -type f | wc -l')"
dc logs --no-log-prefix > "$WORK/logs.txt" 2>&1 || true
hits_logs="$(grep -cF -f "$WORK/needles" "$WORK/logs.txt" || true)"
hits_chain="$(grep -cF -f "$WORK/needles" "$WORK/chain.jsonl" || true)"
hits_policy="$(grep -cF -f "$WORK/needles" <<< "$policy_now" || true)"
hits_proof=0
if [[ -n "${PROOF_LOG:-}" && -f "$PROOF_LOG" ]]; then
  hits_proof="$(grep -cF -f "$WORK/needles" "$PROOF_LOG" || true)"
fi
rm -f "$WORK/needles"
echo "credential_hits coord_state_files ${hits_state} sink_output_files ${hits_recv} (files ${recv_files}) container_logs ${hits_logs} (lines $(wc -l < "$WORK/logs.txt")) audit_records ${hits_chain} (records $(wc -l < "$WORK/chain.jsonl")) policy ${hits_policy} proof_log ${hits_proof}"
[[ "$hits_state" == 0 && "$hits_recv" == 0 && "$hits_logs" == 0 && "$hits_chain" == 0 && "$hits_policy" == 0 && "$hits_proof" == 0 ]] \
  || fail "a credential or token text was found"
echo "gate6 ok"

echo "proof_ok"
