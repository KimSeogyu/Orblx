#!/usr/bin/env bash
# W25-11: the SVID renewal packet gap proof on the box.
# Two orblx node daemons ([C] containers, node.rs on TUN) and one [C] coordinator with a short
# node leaf life (ORBLX_RG_TTL, default 30 s, so a node renews every 20 s).
# Each run pings from node-a to the node-b overlay address every 50 ms for ORBLX_RG_SECS
# (default 75 s), with no other load (idle). node-b answers the echo in the datapath.
# renew-gap-table.py puts every ping next to the nearest SVID renewal of node-a or node-b
# (the docker log time of "The node renewed the SVID") and writes runN.samples.tsv (W25-5 format).
# Gate per run: each node renews 2 times or more during the pings, and in the renewal
# windows (5 s before to 5 s after a renewal) no ping is lost and no ping is above
# ORBLX_RG_LIMIT_MS (default 20). The script runs ORBLX_RG_RUNS runs (default 10) one after
# the other under one hold of the box proof lock, and prints proof_ok when every run passes.
# The host is REAL. The nodes, the coordinator and the network are [C].
# Env: ORBLX_RG_OUT (default target/renew-gap) gets runN.ping, runN.renewals, runN.trace and
#      renew-gap.md. ORBLX_RG_PROJECT, ORBLX_RG_IMAGE and ORBLX_RG_NET (a /24 prefix, default
#      172.29.128) change the names and the subnet. ORBLX_NET_HOOK is a root script that runs
#      after the network starts. Run as root (docker).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
RUNS="${ORBLX_RG_RUNS:-10}"
TTL="${ORBLX_RG_TTL:-30}"
SECS="${ORBLX_RG_SECS:-75}"
LIMIT_MS="${ORBLX_RG_LIMIT_MS:-20}"
INTERVAL="0.05"
PROJECT="${ORBLX_RG_PROJECT:-orblx-renew-gap}"
IMAGE="${ORBLX_RG_IMAGE:-orblx-renew-gap:local}"
NET="${ORBLX_RG_NET:-172.29.128}"
OUT="${ORBLX_RG_OUT:-$ROOT/target/renew-gap}"
FILE="$ROOT/scripts/proof/compose.renew-gap.yml"
BIN="$ROOT/target/release/orblx"
work=""
env_file=""

# shellcheck source=scripts/proof/pipe-lib.sh
. "$ROOT/scripts/proof/pipe-lib.sh"
# shellcheck source=scripts/proof/proof-lock.sh
. "$ROOT/scripts/proof/proof-lock.sh"

dc() {
  docker compose -p "$PROJECT" --env-file "$env_file" -f "$FILE" "$@"
}

down() {
  if [[ -n "$env_file" && -f "$env_file" ]]; then
    dc down --remove-orphans --timeout 3 >/dev/null 2>&1 || true
  fi
  if [[ -n "$work" ]]; then
    rm -rf "$work"
  fi
  work=""
  env_file=""
}

finish() {
  down
  proof_lock_end
}
trap 'finish' EXIT

require_root "$@"
proof_lock_take "renew-gap:${PROJECT}" "${PROJECT}-"
# W25-14b: start from a clean compose state (all profiles, all volumes).
# shellcheck source=scripts/proof/compose-clean.sh
. "$ROOT/scripts/proof/compose-clean.sh"
proof_compose_clean "$PROJECT" || exit 1

# The subnet check runs under the lock, so a proof that runs now cannot hold the subnet.
if docker network ls --format '{{.Name}}' | while read -r name; do
  docker network inspect "$name" -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null
done | has_line "^${NET}\.0/24 "; then
  echo "The subnet ${NET}.0/24 is in use. Set ORBLX_RG_NET." >&2
  exit 1
fi

echo "=== REAL build the release binary ==="
if ! cargo build --release -p orblx-cli --bin orblx; then exit 1; fi
# shellcheck source=scripts/proof/stage-image.sh
source "$ROOT/scripts/proof/stage-image.sh"
image_dir="$(stage_proof_image "$ROOT" "$BIN")"
docker build -q -t "$IMAGE" "$image_dir" >/dev/null || exit 1
rm -rf "$image_dir"
echo "image ${IMAGE}"

mkdir -p "$OUT"
rm -f "$OUT"/run*.ping "$OUT"/run*.renewals "$OUT"/run*.trace "$OUT"/run*.exit "$OUT"/renew-gap.md

netmap() {
  local self="$1" self_ip="$2" peer="$3" peer_ip="$4" peer_host="$5"
  cat <<EOF
{
  "version": 1,
  "self": {"name": "${self}", "overlay_ip": "${self_ip}"},
  "peers": [{
    "name": "${peer}",
    "overlay_ip": "${peer_ip}",
    "svid": "spiffe://orblx.local/node/${peer}",
    "endpoints": ["${NET}.${peer_host}:443"],
    "routes": ["${peer_ip}/32"]
  }]
}
EOF
}

wait_direct() {
  local node="$1" peer="$2"
  for _ in $(seq 1 40); do
    if dc exec -T "$node" orblx status 2>/dev/null | has_line "peer ${peer} overlay_ip .* path direct "; then
      return 0
    fi
    sleep 1
  done
  echo "The path from ${node} to ${peer} is not direct." >&2
  return 1
}

# One run. Prints nothing secret: tokens stay in files, and the node logs carry no key.
run_once() {
  local i="$1" name file
  work="$(mktemp -d)"
  mkdir -p "$work/coord" "$work/a" "$work/b" "$work/tickets" "$work/tokens"
  "$BIN" node-issue --out "$work/tickets" --node a=100.64.0.1 --node b=100.64.0.2 >/dev/null || return 1
  netmap a 100.64.0.1 b 100.64.0.2 12 >"$work/netmap-a.json"
  netmap b 100.64.0.2 a 100.64.0.1 11 >"$work/netmap-b.json"
  env_file="$work/rg.env"
  cat >"$env_file" <<EOF
RG_IMAGE=${IMAGE}
RG_NET=${NET}
RG_TTL=${TTL}
RG_COORD_STATE=$work/coord
RG_STATE_A=$work/a
RG_STATE_B=$work/b
RG_NETMAP_A=$work/netmap-a.json
RG_NETMAP_B=$work/netmap-b.json
EOF
  dc up -d coord >/dev/null 2>&1 || return 1
  if [[ -n "${ORBLX_NET_HOOK:-}" ]]; then
    "$ORBLX_NET_HOOK" >/dev/null 2>&1 || true
  fi
  for _ in $(seq 1 60); do
    dc exec -T coord test -s /var/lib/orblx/trust-bundle.pem >/dev/null 2>&1 && break
    sleep 1
  done
  for name in a b; do
    dc exec -T coord orblx coord token create --state /var/lib/orblx --ttl 3600 \
      --out "/var/lib/orblx/tokens/${name}" >/dev/null || return 1
    dc exec -T coord cat "/var/lib/orblx/tokens/${name}" >"$work/tokens/${name}"
    chmod 600 "$work/tokens/${name}"
  done
  "$BIN" coord enroll --name a --coord "${NET}.10:443" --coord-name coord \
    --bundle "$work/coord/trust-bundle.pem" --token-file "$work/tokens/a" \
    --state "$work/a" --endpoint "${NET}.11:443" >/dev/null || return 1
  "$BIN" coord enroll --name b --coord "${NET}.10:443" --coord-name coord \
    --bundle "$work/coord/trust-bundle.pem" --token-file "$work/tokens/b" \
    --state "$work/b" --endpoint "${NET}.12:443" >/dev/null || return 1
  for name in a b; do
    for file in ticket.bin ticket.bin.mac ticket-verifier.pem ticket-mac.key svid-ca.pub ticket-not-before ticket-not-after; do
      cp "$work/tickets/${name}/${file}" "$work/${name}/${file}"
    done
    chmod 600 "$work/${name}/ticket.bin" "$work/${name}/ticket.bin.mac" "$work/${name}/ticket-mac.key"
  done
  dc up -d node-a node-b >/dev/null 2>&1 || return 1
  wait_direct node-a b || return 1
  wait_direct node-b a || return 1
  echo "run ${i} ping start $(proof_lock_now) count $((SECS * 20)) interval ${INTERVAL}"
  host_sample >"$OUT/run${i}.host.tsv" &
  local sampler=$!
  dc exec -T node-a ping -n -D -O -i "$INTERVAL" -c "$((SECS * 20))" -W 1 100.64.0.2 \
    >"$OUT/run${i}.ping" 2>&1
  kill "$sampler" 2>/dev/null
  wait "$sampler" 2>/dev/null
  for name in node-a node-b; do
    dc logs --timestamps --no-log-prefix "$name" 2>/dev/null \
      | awk -v n="$name" '/The node renewed the SVID/ {print "svid_renewal " n " " $1}' >>"$OUT/run${i}.renewals"
    dc logs --no-log-prefix "$name" 2>/dev/null | grep '^trace ' >>"$OUT/run${i}.trace" || true
    if dc logs "$name" 2>&1 | has_line "PRIVATE KEY"; then
      echo "The ${name} log contains a private key." >&2
      return 1
    fi
  done
  return 0
}

# Host load each second during the pings (epoch, CPU busy percent, runnable tasks, 1 min load).
# A spike with a busy host is contention, not renewal. The gate does not use this file.
host_sample() {
  local prev_total=0 prev_idle=0
  echo -e "epoch\tcpu_busy_pct\tprocs_running\tload1"
  while :; do
    local line total idle running load
    line=$(head -1 /proc/stat)
    read -r _ u n sy id io irq sirq st _ <<<"$line"
    total=$((u + n + sy + id + io + irq + sirq + st))
    idle=$((id + io))
    running=$(awk '/^procs_running/ {print $2}' /proc/stat)
    load=$(cut -d' ' -f1 /proc/loadavg)
    if [[ "$prev_total" -gt 0 && "$total" -gt "$prev_total" ]]; then
      echo -e "$(date +%s.%3N)\t$((100 * ((total - prev_total) - (idle - prev_idle)) / (total - prev_total)))\t${running}\t${load}"
    fi
    prev_total=$total
    prev_idle=$idle
    sleep 1
  done
}

status=0
for i in $(seq 1 "$RUNS"); do
  echo "=== [C] renew gap run ${i}/${RUNS} start $(proof_lock_now) ==="
  proof_context "run${i}"
  run_once "$i"
  code=$?
  echo "$code" >"$OUT/run${i}.exit"
  down
  python3 "$ROOT/scripts/proof/renew-gap-table.py" "$OUT" --limit-ms "$LIMIT_MS" --upto "$i" | tail -1
  [[ "$code" -eq 0 ]] || status=1
done

python3 "$ROOT/scripts/proof/renew-gap-table.py" "$OUT" --limit-ms "$LIMIT_MS" | tee "$OUT/renew-gap.md"
if [[ "$status" -eq 0 ]] && python3 "$ROOT/scripts/proof/renew-gap-table.py" "$OUT" --limit-ms "$LIMIT_MS" --gate; then
  echo "proof_ok renew-gap runs ${RUNS}"
else
  echo "proof_fail renew-gap" >&2
  exit 1
fi
