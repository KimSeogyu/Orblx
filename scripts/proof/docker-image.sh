#!/usr/bin/env bash
# Official Docker image proof (W25-8).
# The script builds docker/Dockerfile and checks these gates:
#   1. The image is at most ORBLX_DIMG_MAX_BYTES (default 60000000 bytes).
#   2. A container with only an enroll token (b: file, a: env file), NET_ADMIN, and
#      /dev/net/tun enrolls, gets an SVID, and pings the peer on the overlay. No --privileged.
#   3. A restart with the state volume keeps the overlay IP and does not enroll again.
#   4. The node renews the SVID in the container with a short life (ORBLX_DIMG_SVID_TTL).
#   5. The image has no token, key, or PEM item: docker history and a scan of docker save.
#      A control image with a planted fake PEM block and a planted string must fail the scan.
# The coordinator runs from the same image ("coord serve").
# Run as root, or with sudo -n available for docker.
# The script does not print enroll tokens, keys, or certificates.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
PREFIX="${ORBLX_DIMG_PREFIX:-orblx-w25h-dimg}"
IMAGE="${ORBLX_DIMG_IMAGE:-orblx-w25h-image:local}"
MAX_BYTES="${ORBLX_DIMG_MAX_BYTES:-60000000}"
TTL="${ORBLX_DIMG_SVID_TTL:-60}"
PINGS="${ORBLX_DIMG_PINGS:-20}"
NET="${PREFIX}-net"
STATE=/var/lib/orblx
WORK="$(mktemp -d)"
# W25-14: the proof takes the box proof lock itself (proof-lock.sh, W25-5).
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
trap proof_lock_end EXIT
proof_lock_take "docker-image"
chmod 700 "$WORK"

docker() {
  if [[ "$(id -u)" -eq 0 ]]; then
    command docker "$@"
  else
    sudo -n docker "$@"
  fi
}

teardown() {
  docker rm -f "${PREFIX}-coord" "${PREFIX}-a" "${PREFIX}-b" >/dev/null 2>&1 || true
  docker volume rm "${PREFIX}-coord" "${PREFIX}-a" "${PREFIX}-b" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker rmi -f "${PREFIX}-control:local" >/dev/null 2>&1 || true
}

cleanup() {
  if [[ "${PROOF_KEEP:-0}" == 1 ]]; then
    echo "PROOF_KEEP=1 keeps the containers for debug."
    return
  fi
  teardown
  rm -rf "$WORK"
}
# W25-14: the cleanup runs first, then the lock is released.
trap 'cleanup; proof_lock_end' EXIT

die() {
  echo "FAIL: $*" >&2
  exit 1
}

wait_log() {
  local name="$1" needle="$2" want="${3:-1}" limit="${4:-90}" i count
  for i in $(seq 1 "$limit"); do
    count="$(docker logs "$name" 2>&1 | grep -cF -- "$needle" || true)"
    if [[ "$count" -ge "$want" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "The container ${name} did not print '${needle}' ${want} times." >&2
  docker logs "$name" 2>&1 | tail -20 >&2
  return 1
}

log_count() {
  docker logs "$1" 2>&1 | grep -cF -- "$2" || true
}

status_field() {
  local name="$1" field="$2"
  docker exec "$name" orblx status --state-dir "$STATE" 2>/dev/null \
    | read_all awk -v f="$field" '$1 == f {print $2; exit}'
}

wait_status() {
  local name="$1" i ip
  for i in $(seq 1 60); do
    ip="$(status_field "$name" overlay_ip)"
    if [[ -n "$ip" ]]; then
      printf '%s\n' "$ip"
      return 0
    fi
    sleep 1
  done
  return 1
}

ping_peer() {
  local from="$1" ip="$2" label="$3" out loss
  out="$(docker exec "$from" ping -n -c "$PINGS" -i 0.2 -W 1 "$ip" 2>&1 | tail -2 || true)"
  echo "${label} ${out//$'\n'/ | }"
  loss="$(awk '/packet loss/ {for (i = 1; i <= NF; i++) if ($i ~ /%$/) print $i}' <<<"$out")"
  [[ "$loss" == "0%" ]] || die "${label}: the overlay ping lost packets (${loss:-no result})."
}

wait_ping() {
  local from="$1" ip="$2" i
  for i in $(seq 1 60); do
    if docker exec "$from" ping -n -c 1 -W 1 "$ip" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

node_run() {
  local name="$1"
  shift
  docker run -d --name "${PREFIX}-${name}" --hostname "$name" \
    --network "$NET" --network-alias "$name" \
    --cap-add NET_ADMIN --device /dev/net/tun \
    -e "ORBLX_COORD=${coord_ip}:443" \
    -e "ORBLX_NAME=${name}" \
    -e "ORBLX_BUNDLE_FILE=/run/orblx/bundle.pem" \
    -e "ORBLX_ENDPOINT=${name}:443" \
    -v "$WORK/bundle.pem:/run/orblx/bundle.pem:ro" \
    -v "${PREFIX}-${name}:${STATE}" \
    "$@" >/dev/null
}

echo "=== [C] gate 1: build and size ==="
if [[ "${ORBLX_DIMG_SKIP_BUILD:-0}" != 1 ]]; then
  docker build -q -f docker/Dockerfile -t "$IMAGE" . >/dev/null
fi
size="$(docker image inspect "$IMAGE" --format '{{.Size}}')"
layers="$(docker image inspect "$IMAGE" --format '{{len .RootFS.Layers}}')"
echo "image ${IMAGE} size_bytes ${size} size_mb $((size / 1000000)) layers ${layers} max_bytes ${MAX_BYTES}"
[[ "$size" -le "$MAX_BYTES" ]] || die "The image is larger than ${MAX_BYTES} bytes."
echo "gate1 ok"

echo "=== [C] start the coordinator from the image (svid ttl ${TTL}) ==="
teardown
docker network create "$NET" >/dev/null
docker run -d --name "${PREFIX}-coord" --hostname coord --network "$NET" --network-alias coord \
  -e ORBLX_OIDC_MODE=mock -e "ORBLX_SVID_TTL=${TTL}" \
  -v "${PREFIX}-coord:${STATE}" \
  "$IMAGE" coord serve --state "$STATE" --listen 0.0.0.0:443 --name coord >/dev/null
for i in $(seq 1 60); do
  if docker exec "${PREFIX}-coord" test -s "$STATE/trust-bundle.pem"; then
    break
  fi
  sleep 1
done
docker exec "${PREFIX}-coord" cat "$STATE/trust-bundle.pem" >"$WORK/bundle.pem"
coord_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "${PREFIX}-coord")"
echo "coord ${coord_ip}:443"
for name in a b; do
  docker exec "${PREFIX}-coord" orblx coord token create --state "$STATE" --ttl 3600 \
    --out "$STATE/tokens/${name}" | grep -E '^(wrote|expires_unix)' || true
  (umask 077 && docker exec "${PREFIX}-coord" cat "$STATE/tokens/${name}" >"$WORK/token-${name}")
done
(umask 077 && printf 'ORBLX_ENROLL_TOKEN=%s\n' "$(cat "$WORK/token-a")" >"$WORK/a.env")

echo "=== [C] gate 2: enroll b with a token file, a with a token env var ==="
node_run b -e ORBLX_ENROLL_TOKEN_FILE=/run/orblx/token \
  -v "$WORK/token-b:/run/orblx/token:ro" "$IMAGE"
wait_log "${PREFIX}-b" "orblx-entrypoint: enrolled b."
node_run a --env-file "$WORK/a.env" "$IMAGE"
wait_log "${PREFIX}-a" "orblx-entrypoint: enrolled a."
for name in a b; do
  docker inspect -f "${name} privileged {{.HostConfig.Privileged}} cap_add {{.HostConfig.CapAdd}} devices {{len .HostConfig.Devices}}" "${PREFIX}-${name}"
  [[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "${PREFIX}-${name}")" == false ]] || die "${name} is privileged."
done
# b got its netmap before a enrolled. A restart gets the netmap again (no enroll).
docker restart "${PREFIX}-b" >/dev/null
wait_log "${PREFIX}-b" "orblx-entrypoint: state found, no enroll."
ip_a="$(wait_status "${PREFIX}-a")" || die "a has no status."
ip_b="$(wait_status "${PREFIX}-b")" || die "b has no status."
svid_a="$(status_field "${PREFIX}-a" svid_expiry)"
echo "overlay a ${ip_a} b ${ip_b} svid_expiry_a ${svid_a}"
[[ -n "$svid_a" && "$svid_a" != null ]] || die "a has no SVID expiry."
wait_ping "${PREFIX}-a" "$ip_b" || die "a cannot ping b on the overlay."
ping_peer "${PREFIX}-a" "$ip_b" "ping a->b"
env_count="$(docker exec "${PREFIX}-a" sh -c 'tr "\0" "\n" </proc/1/environ | grep -c "^ORBLX_ENROLL_TOKEN" || true')"
echo "a pid1 token env vars ${env_count}"
[[ "$env_count" == 0 ]] || die "The node process has the enroll token in its environment."
tmp_count="$(docker exec "${PREFIX}-a" sh -c 'ls /tmp | grep -c orblx-token || true')"
echo "a temp token files ${tmp_count}"
[[ "$tmp_count" == 0 ]] || die "The temp token file is still in the container."
dns_lines="$(log_count "${PREFIX}-a" "The command resolvectl is not available.")"
echo "a resolvectl missing lines ${dns_lines} (the node continues without the ~orblx DNS domain)"
echo "gate2 ok"

echo "=== [C] gate 3: restart a with the state volume ==="
docker restart "${PREFIX}-a" >/dev/null
wait_log "${PREFIX}-a" "orblx-entrypoint: state found, no enroll."
ip_a2="$(wait_status "${PREFIX}-a")" || die "a has no status after the restart."
enrolls_a="$(log_count "${PREFIX}-a" "orblx-entrypoint: enrolled a.")"
noenroll_a="$(log_count "${PREFIX}-a" "orblx-entrypoint: state found, no enroll.")"
echo "a overlay before ${ip_a} after ${ip_a2} enrolled_lines ${enrolls_a} no_enroll_lines ${noenroll_a}"
[[ "$ip_a" == "$ip_a2" ]] || die "The overlay IP of a changed."
[[ "$enrolls_a" == 1 && "$noenroll_a" == 1 ]] || die "a enrolled again."
wait_ping "${PREFIX}-a" "$ip_b" || die "a cannot ping b after the restart."
ping_peer "${PREFIX}-a" "$ip_b" "ping a->b after restart"
echo "gate3 ok"

echo "=== [C] gate 4: SVID renew in the container ==="
before="$(status_field "${PREFIX}-a" svid_expiry)"
wait_log "${PREFIX}-a" "The node renewed the SVID" 1 $((TTL * 2)) || die "a did not renew the SVID."
sleep 2
after="$(status_field "${PREFIX}-a" svid_expiry)"
docker logs "${PREFIX}-a" 2>&1 | show_matching -F "The node renewed the SVID" | tail -1
echo "a svid_expiry before ${before} after ${after}"
[[ "$after" -gt "$before" ]] || die "The SVID expiry did not move."
ping_peer "${PREFIX}-a" "$ip_b" "ping a->b after renew"
echo "gate4 ok"

echo "=== [C] gate 5: no secrets in the image ==="
hist_hits=0
history="$(docker history --no-trunc --format '{{.CreatedBy}}' "$IMAGE")"
for needle in "$(cat "$WORK/token-a")" "$(cat "$WORK/token-b")" "BEGIN" "ORBLX_ENROLL_TOKEN="; do
  if grep -qF -- "$needle" <<<"$history"; then
    hist_hits=$((hist_hits + 1))
  fi
done
echo "history lines $(wc -l <<<"$history") hits ${hist_hits}"
[[ "$hist_hits" == 0 ]] || die "docker history has a secret."
docker image inspect "$IMAGE" --format '{{json .Config.Env}}'
docker save "$IMAGE" | python3 scripts/proof/image-secrets-scan.py \
  --needle-file "$WORK/token-a" --needle-file "$WORK/token-b" || die "The image scan found a secret."

echo "=== [C] gate 5 control: a planted fake PEM and string must be found ==="
python3 - "$WORK" <<'PY'
import base64, os, secrets, sys
work = sys.argv[1]
body = base64.encodebytes(os.urandom(96)).decode()
with open(os.path.join(work, "planted.pem"), "w") as f:
    f.write("-----BEGIN " + "PRIVATE KEY-----\n" + body + "-----END " + "PRIVATE KEY-----\n")
with open(os.path.join(work, "planted-token"), "w") as f:
    f.write("orblx-planted-" + secrets.token_hex(16) + "\n")
PY
mkdir -p "$WORK/control"
cp "$WORK/planted.pem" "$WORK/control/planted.pem"
printf 'FROM %s\nCOPY planted.pem /etc/planted.pem\nRUN echo %s > /etc/planted-token\n' \
  "$IMAGE" "$(cat "$WORK/planted-token")" >"$WORK/control/Dockerfile"
docker build -q -t "${PREFIX}-control:local" "$WORK/control" >/dev/null
control_hist="$(docker history --no-trunc --format '{{.CreatedBy}}' "${PREFIX}-control:local")"
if grep -qF -- "$(cat "$WORK/planted-token")" <<<"$control_hist"; then
  echo "control history hit 1"
else
  die "The history check did not find the planted string."
fi
docker save "${PREFIX}-control:local" | python3 scripts/proof/image-secrets-scan.py \
  --needle-file "$WORK/planted-token" --expect-hit || die "The scan did not find the planted items."
echo "gate5 ok"

echo "proof_ok docker-image size_bytes ${size} svid_ttl ${TTL}"
