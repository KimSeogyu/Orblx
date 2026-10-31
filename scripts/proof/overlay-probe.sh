#!/usr/bin/env bash
# W25-41 overlay one-way latency diagnostic (no product gate on this script's exit).
# Phase 1 (target): a RELEASE build. Phase 2 (information): a debug build of the
# same head. Each phase starts nodes a and b through the normal coordinator enroll
# path, then runs a plain TCP probe (python, TCP_NODELAY, one write per line) from
# a to b over the overlay. The nodes write the packet stage trace (pkt_trace.rs).
# overlay-stage-split.py prints p50/p90/p99/max for each stage.
# Target (PO, release only): one-way TUN read to TUN write p50 <= 2 ms and
# p99 <= 10 ms; probe RTT p99 <= 20 ms.
# The script does not print enroll tokens, private keys, or tickets.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
FILE="scripts/proof/compose.agent.yml"
PROJECT="${PROOF_PROJECT:-orblx-w25-41-overlay}"
IMAGE_BASE="${OVERLAY_IMAGE_BASE:-orblx-w25-41-overlay}"
WORK="$(mktemp -d)"
export POLICY_FILE="$WORK/policy.hujson"
export COORD_ADDR="127.0.0.1:443"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
STATE=/var/lib/orblx
PROBE_PORT=9090
PROBE_SECS="${OVERLAY_PROBE_SECS:-60}"
PROBE_EVERY_MS=50
PROFILES="${OVERLAY_PROFILES:-release debug}"
export ORBLX_DP_TRACE_FILE="$STATE/dp-trace.txt"
export ORBLX_DP_TRACE_PORTS="$PROBE_PORT"

as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

dc() {
  docker compose --progress quiet -p "$PROJECT" --profile nodes -f "$FILE" "$@"
}

cleanup() {
  dc down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap 'cleanup; proof_lock_end' EXIT
proof_lock_take "overlay-probe" "$PROJECT"
# Fail closed before any build if the disk has less than 15G free (checked under the lock).
free_kb="$(df -Pk /workspace | awk 'NR == 2 {print $4}')"
echo "free_space_kb ${free_kb} (need 15728640)"
if [ "${free_kb:-0}" -lt 15728640 ]; then
  echo "overlay_probe_done result abort reason low_disk free_kb ${free_kb}"
  exit 3
fi
# shellcheck source=scripts/proof/compose-clean.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/compose-clean.sh"

resolve_name() {
  local name="$1"
  dc --profile nodes run --rm --no-deps --entrypoint getent owner ahostsv4 "$name" \
    | read_all awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ /{print $1; exit}'
}

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
  local profile="$1" image_dir bin
  if [[ "$profile" == release ]]; then
    cargo build --release -p orblx-cli --bin orblx --locked
    bin="$TARGET_DIR/release/orblx"
  else
    cargo build -p orblx-cli --bin orblx --locked
    bin="$TARGET_DIR/debug/orblx"
  fi
  # shellcheck source=stage-image.sh
  source "$ROOT/scripts/proof/stage-image.sh"
  image_dir="$(stage_proof_image "$ROOT" "$bin")"
  docker build -q -t "$ORBLX_AGENT_IMAGE" "$image_dir"
  rm -rf "$image_dir"
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

wait_log() {
  local service="$1" needle="$2" i
  for i in $(seq 1 60); do
    if dc logs "$service" 2>&1 | read_all grep -q "$needle"; then
      return 0
    fi
    sleep 1
  done
  echo "The service ${service} did not print: ${needle}" >&2
  return 1
}

run_node() {
  local service="$1"
  shift
  dc --profile nodes run --rm --no-deps --entrypoint orblx "$service" "$@"
}

owner() {
  run_node owner admin "$@" --coord "${coord_ip}:443" --state "$STATE" --bundle "$STATE/bundle.pem"
}

enroll_node() {
  local name="$1"
  echo "=== [C] enroll ${name} with a coordinator token ==="
  run_node "$name" \
    coord enroll \
    --name "$name" \
    --coord "${coord_ip}:443" \
    --bundle /coord-state/trust-bundle.pem \
    --token-file "/coord-state/tokens/${name}" \
    --state "$STATE" \
    --endpoint "${name}:443"
}

run_phase() {
  local profile="$1" nodes b_ip i
  export ORBLX_AGENT_IMAGE="${IMAGE_BASE}:${profile}"
  echo "=== [C] phase ${profile}: clean compose state ==="
  proof_compose_clean "$PROJECT" || return 1
  echo "=== [C] phase ${profile}: build ==="
  build_image "$profile"
  cp "$ROOT/scripts/proof/agent.hujson" "$POLICY_FILE"
  export COORD_ADDR="127.0.0.1:443"
  dc up -d coord
  wait_bundle
  for name in owner a b; do
    dc exec -T coord orblx coord token create --state "$STATE" --ttl 3600 \
      --out "$STATE/tokens/${name}" >/dev/null
    echo "token ${name} written"
  done
  coord_ip="$(resolve_name coord)"
  [[ -n "$coord_ip" ]] || { echo "The coordinator address did not resolve." >&2; return 1; }
  export COORD_ADDR="${coord_ip}:443"
  enroll_node owner
  enroll_node a
  enroll_node b
  owner approve a
  owner approve b
  nodes="$(owner nodes)"
  printf '%s\n' "$nodes"
  b_ip="$(printf '%s\n' "$nodes" | read_all awk '$1 == "node" && $2 == "b" {print $3; exit}')"
  echo "b_ip ${b_ip}"
  for name in a b; do
    run_node "$name" coord netmap --coord "${coord_ip}:443" --bundle "$STATE/bundle.pem" --state "$STATE"
  done
  dc --profile nodes up -d a b
  wait_log a 'The TUN device'
  wait_log b 'The TUN device'
  for i in $(seq 1 60); do
    if dc exec -T a orblx status --state-dir "$STATE" 2>/dev/null | read_all grep -q '^peer b .* path direct '; then
      break
    fi
    if [[ "$i" -eq 60 ]]; then
      echo "The path from a to b did not come up." >&2
      return 1
    fi
    sleep 1
  done
  dc exec -T a orblx status --state-dir "$STATE"
  echo "=== [C] phase ${profile}: overlay ping a to b (information) ==="
  dc exec -T a ping -c 20 -i 0.2 "$b_ip" || true
  echo "other_orblx_containers $(docker ps --format '{{.Names}}' | grep orblx | grep -vc "^${PROJECT}-" || true)"
  echo "=== [C] phase ${profile}: plain TCP probe a to b ${b_ip}:${PROBE_PORT}, ${PROBE_SECS} s, every ${PROBE_EVERY_MS} ms ==="
  for name in a b; do
    dc exec -T "$name" sh -c "cat >/tmp/tcp-rtt-probe.py" <"$ROOT/scripts/proof/tcp-rtt-probe.py"
  done
  dc exec -d b python3 /tmp/tcp-rtt-probe.py serve "$b_ip" "$PROBE_PORT"
  sleep 1
  dc exec -T a sh -c "true >$STATE/dp-trace.txt" || true
  dc exec -T b sh -c "true >$STATE/dp-trace.txt" || true
  dc exec -T a python3 /tmp/tcp-rtt-probe.py probe "$b_ip" "$PROBE_PORT" "$PROBE_SECS" "$PROBE_EVERY_MS" >"$WORK/probe-${profile}.txt"
  dc exec -T a cat "$STATE/dp-trace.txt" >"$WORK/dp-a-${profile}.txt"
  dc exec -T b cat "$STATE/dp-trace.txt" >"$WORK/dp-b-${profile}.txt"
  echo "trace_lines ${profile} a $(wc -l <"$WORK/dp-a-${profile}.txt") b $(wc -l <"$WORK/dp-b-${profile}.txt") probe $(wc -l <"$WORK/probe-${profile}.txt")"
  if [[ -n "${OVERLAY_KEEP_DIR:-}" ]]; then
    mkdir -p "$OVERLAY_KEEP_DIR"
    cp "$WORK/dp-a-${profile}.txt" "$WORK/dp-b-${profile}.txt" "$WORK/probe-${profile}.txt" "$OVERLAY_KEEP_DIR/"
    echo "raw_kept ${OVERLAY_KEEP_DIR}"
  fi
  echo "=== [C] phase ${profile}: stage split ==="
  python3 "$ROOT/scripts/proof/overlay-stage-split.py" "$WORK/dp-a-${profile}.txt" \
    "$WORK/dp-b-${profile}.txt" "$WORK/probe-${profile}.txt" "$profile"
  dc down -v --remove-orphans >/dev/null 2>&1 || true
}

open_legacy_forward
for profile in $PROFILES; do
  run_phase "$profile"
done
echo "overlay_probe_done profiles ${PROFILES}"
