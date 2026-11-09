#!/usr/bin/env bash
# W25-47 release proof. One run covers DoD a, DoD b, and DoD f.
# Eng Lead runs it on the final pull request head, after a release build.
# Any later push voids the run.
#
# This proof steps CLOCK_REALTIME. It is not in sweep-manifest.txt.
# The release sweep must not step the clock. The script prints head= and
# bin_sha256= for the checkout it ran, and it stops when the tree is dirty
# or the binary is older than HEAD.
#
# Build, then run as root:
#   cargo build --release --locked -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp
#   sudo -n scripts/proof/w25-47-reauth.sh
# The state directories are under mktemp. The script does not use /var/lib/orblx.
#
# NTP: when chronyd, ntpd, or systemd-timesyncd is running, the script refuses
# with exit 2. It does not stop a daemon, because a host without systemd cannot
# start that daemon again. When none of them is running, the script steps the
# clock 2 min and checks that the step is still there. If the clock is put back,
# the script refuses with exit 2. The trap sets the clock back after a real run.
#
# PASS lines, in order:
#   DoD f passed.
#   DoD a passed.
#   DoD b passed.
#   W25-47 PASS a b f
# A pass exits 0. A failed check exits 1. A missing privilege, or an active
# time sync, exits 2. The proof lock uses status 3, 4, or 5. The alarm exits 124.
#
# The alarm is 300 s (ORBLX_W25_47_TIMEOUT). DoD b waits up to 60 s for peer
# traffic after two clock steps and two node starts. One pass prints elapsed_s
# before the final PASS line. 180 s does not cover that work.
# DoD f steps the clock before either node starts, so the step does not land
# in the middle of a node handshake. DoD a then steps again, past the grace.
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).

if ! capsh --print 2>/dev/null | read_all grep -q cap_sys_time && [[ "$(id -u)" != "0" ]]; then
  echo "The W25-47 release proof needs CAP_SYS_TIME or root. Eng Lead runs it."
  exit 2
fi

ntp_name=
for ntp_name in chronyd ntpd systemd-timesyncd; do
  if pgrep -x "$ntp_name" >/dev/null 2>&1; then
    echo "Time sync is active (${ntp_name}). This proof does not stop it, because it cannot start it again. Stop ${ntp_name}, then run the proof."
    exit 2
  fi
done
echo "ntp none"
# A hypervisor can put the clock back within a second. The proof needs the step to stay.
clock_before=$(date +%s)
date -u -s "+2 min" >/dev/null
sleep 0.4
clock_after=$(date +%s)
if [[ $((clock_after - clock_before)) -lt 60 ]]; then
  echo "The clock did not stay stepped. Something other than chronyd, ntpd, or systemd-timesyncd put it back within 1 s. This proof cannot run on this host."
  exit 2
fi
date -u -s "-2 min" >/dev/null

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="${ORBLX_BIN:-$root/target/release/orblx}"
idp="${ORBLX_IDP_BIN:-$(dirname "$bin")/orblx-test-idp}"
case "$bin" in
  */debug/*)
    echo "The proof refuses a debug binary ($bin)."
    exit 1
    ;;
esac
case "$idp" in
  */debug/*)
    echo "The proof refuses a debug binary ($idp)."
    exit 1
    ;;
esac
if [[ ! -x "$bin" || ! -x "$idp" ]]; then
  echo "Build the release binaries first. The proof looks for $bin and $idp."
  exit 1
fi
if [[ -n "$(git -C "$root" status --porcelain)" ]]; then
  echo "The tree is dirty. Eng Lead runs this proof on the exact head."
  exit 1
fi
head_sha=$(git -C "$root" rev-parse HEAD)
head_ct=$(git -C "$root" log -1 --format=%ct)
bin_mt=$(stat -c %Y "$bin")
idp_mt=$(stat -c %Y "$idp")
if [[ "$bin_mt" -lt "$head_ct" || "$idp_mt" -lt "$head_ct" ]]; then
  echo "The binary is older than HEAD. Build the release binaries again."
  exit 1
fi
bin_sha=$(sha256sum "$bin" | awk '{print $1}')
echo "head=${head_sha}"
echo "bin_sha256=${bin_sha}"

proof_lock_take "w25-47-reauth"

saved=$(date -u +%Y-%m-%dT%H:%M:%S)
coord_pid=
idp_pid=
node_a_pid=
node_b_pid=
watchdog_pid=
work=
ns_a=w2547a
ns_b=w2547b
forward_was=
rp_was=
cleaned=0

fail() {
  echo "$1" >&2
  if [[ -n "$work" && -d "$work" ]]; then
    echo "proof work $work" >&2
    for log in coord.log idp.log node-a.log node-b.log; do
      if [[ -f "$work/$log" ]]; then
        echo "--- $log ---" >&2
        tail -n 40 "$work/$log" >&2 || true
      fi
    done
  fi
  exit 1
}

cleanup() {
  if [[ "$cleaned" == 1 ]]; then
    return
  fi
  cleaned=1
  # Put the clock back before any wait. A later signal must not leave it stepped.
  if [[ -n "$saved" ]]; then
    date -u -s "$saved" >/dev/null || true
    saved=
  fi
  if [[ -n "$watchdog_pid" ]]; then
    kill "$watchdog_pid" 2>/dev/null || true
  fi
  for pid in "$node_a_pid" "$node_b_pid" "$coord_pid" "$idp_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for ns in "$ns_a" "$ns_b"; do
    if ip netns list 2>/dev/null | awk '{print $1}' | read_all grep -qx "$ns"; then
      ip netns pids "$ns" 2>/dev/null | while read -r pid; do
        kill "$pid" 2>/dev/null || true
      done
      ip netns del "$ns" 2>/dev/null || true
    fi
  done
  ip link del veth-a 2>/dev/null || true
  ip link del veth-b 2>/dev/null || true
  if [[ -n "$forward_was" ]]; then
    printf '%s\n' "$forward_was" >/proc/sys/net/ipv4/ip_forward || true
  fi
  if [[ -n "$rp_was" ]]; then
    printf '%s\n' "$rp_was" >/proc/sys/net/ipv4/conf/all/rp_filter || true
  fi
  proof_lock_end
}
trap cleanup EXIT INT TERM HUP
on_alarm() {
  echo "The iteration timed out after ${limit} s." >&2
  exit 124
}
trap on_alarm USR1

# One iteration. The alarm fires after this many seconds.
limit="${ORBLX_W25_47_TIMEOUT:-300}"
(
  sleep "$limit"
  kill -USR1 $$ 2>/dev/null || true
) &
watchdog_pid=$!

wait_grep() {
  local file="$1" pattern="$2" seconds="$3" i
  for i in $(seq 1 "$seconds"); do
    if [[ -f "$file" ]] && read_all grep -q -- "$pattern" <"$file"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

key_id() {
  openssl x509 -in "$1" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | tail -c 32 \
    | od -An -tx1 \
    | tr -d ' \n'
}

work=$(mktemp -d)
coord_dir="$work/coord"
state_a="$work/node-a"
state_b="$work/node-b"
idp_dir="$work/idp"
mkdir -p "$coord_dir" "$idp_dir"
chmod 700 "$coord_dir" "$idp_dir"

ip netns del "$ns_a" 2>/dev/null || true
ip netns del "$ns_b" 2>/dev/null || true
ip link del veth-a 2>/dev/null || true
ip link del veth-b 2>/dev/null || true
ip netns add "$ns_a"
ip netns add "$ns_b"
ip link add veth-a type veth peer name peer-a
ip link add veth-b type veth peer name peer-b
ip link set peer-a netns "$ns_a"
ip link set peer-b netns "$ns_b"
ip addr add 10.200.0.1/24 dev veth-a
ip addr add 10.200.1.1/24 dev veth-b
ip link set veth-a up
ip link set veth-b up
ip netns exec "$ns_a" ip link set lo up
ip netns exec "$ns_b" ip link set lo up
ip netns exec "$ns_a" ip addr add 10.200.0.2/24 dev peer-a
ip netns exec "$ns_b" ip addr add 10.200.1.2/24 dev peer-b
ip netns exec "$ns_a" ip link set peer-a up
ip netns exec "$ns_b" ip link set peer-b up
ip netns exec "$ns_a" ip route add default via 10.200.0.1
ip netns exec "$ns_b" ip route add default via 10.200.1.1
forward_was=$(cat /proc/sys/net/ipv4/ip_forward)
rp_was=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)
printf '1\n' >/proc/sys/net/ipv4/ip_forward
printf '0\n' >/proc/sys/net/ipv4/conf/all/rp_filter
ip netns exec "$ns_a" ping -c 1 -W 2 10.200.0.1 >/dev/null
ip netns exec "$ns_b" ping -c 1 -W 2 10.200.0.1 >/dev/null

issuer=https://127.0.0.1:8443
client=orblx-w25-47
"$idp" init --dir "$idp_dir" --host 127.0.0.1 >/dev/null
stdbuf -oL -eL "$idp" serve --dir "$idp_dir" --issuer "$issuer" --listen 127.0.0.1:8443 >"$work/idp.log" 2>&1 &
idp_pid=$!
wait_grep "$work/idp.log" "idp serve" 20 || fail "The test issuer did not stay up."

cat >"$coord_dir/policy.hujson" <<'POLICY'
{
  "owners": ["spiffe://orblx.local/node/a"],
  "userApproval": {
    "ownerUsers": ["oidc:ada"]
  }
}
POLICY
cat >"$work/coord.toml" <<CONF
[oidc]
issuer = "${issuer}"
client_id = "${client}"
allowed_domains = []
allowed_emails = []
ca_file = "${idp_dir}/ca.pem"
CONF

stdbuf -oL -eL "$bin" coord serve --state "$coord_dir" --name coord --listen 0.0.0.0:7443 \
  --policy "$coord_dir/policy.hujson" --config "$work/coord.toml" >"$work/coord.log" 2>&1 &
coord_pid=$!
wait_grep "$work/coord.log" "oidc issuer" 20 || fail "The coordinator did not stay up."
for _ in $(seq 1 20); do
  [[ -f "$coord_dir/trust-bundle.pem" ]] && break
  sleep 1
done
[[ -f "$coord_dir/trust-bundle.pem" ]] || fail "The coordinator did not write the trust bundle."

echo "DoD f: step the clock 11 min so the coordinator leaf is due, before a node is up."
date -u -s "+11 min" >/dev/null
wait_grep "$work/coord.log" "coord svid renewed" 30 || fail "DoD f failed. The coordinator log has no coord svid renewed line."
echo "DoD f passed."

"$idp" mint --dir "$idp_dir" --kid rs1 --issuer "$issuer" --aud "$client" \
  --sub ada --ttl 3600 --out "$work/ada-1.token" >/dev/null
enroll_a=$("$bin" coord enroll --name a --coord 10.200.0.1:7443 \
  --bundle "$coord_dir/trust-bundle.pem" --id-token-file "$work/ada-1.token" \
  --state "$state_a" --coord-name coord --endpoint 10.200.0.2:443)
printf '%s\n' "$enroll_a"
overlay_a=$(printf '%s\n' "$enroll_a" | awk '/^overlay_ip /{print $2}')
name_a=$(printf '%s\n' "$enroll_a" | awk '/^name /{print $2}')
[[ "$name_a" == "a" && -n "$overlay_a" ]] || fail "The first enroll did not keep the name."
old_key=$(key_id "$state_a/cert.pem")
[[ "$old_key" =~ ^[0-9a-f]{64}$ ]] || fail "The first leaf key id is not 64 hex digits."

ip netns exec "$ns_a" stdbuf -oL -eL "$bin" up --state-dir "$state_a" --listen 10.200.0.2:443 \
  --coord 10.200.0.1:7443 --coord-name coord --bundle "$coord_dir/trust-bundle.pem" \
  --metrics off >"$work/node-a.log" 2>&1 &
node_a_pid=$!
wait_grep "$work/node-a.log" "The TUN device is" 30 || fail "Node a did not open the TUN device."

echo "DoD a: step the clock 17 min so the node leaf is past the grace."
date -u -s "+17 min" >/dev/null
status_a=
for _ in $(seq 1 30); do
  status_a=$("$bin" status --state-dir "$state_a" || true)
  if printf '%s\n' "$status_a" | read_all grep -q "state needs-reauth" \
    && printf '%s\n' "$status_a" | read_all grep -q "reauth orblx login --name a"; then
    break
  fi
  sleep 1
  status_a=
done
[[ -n "$status_a" ]] || fail "DoD a failed."
printf '%s\n' "$status_a"
echo "DoD a passed."

echo "DoD b: owner re-auth for the same name."
reauth_start=$(date +%s)
"$idp" mint --dir "$idp_dir" --kid rs1 --issuer "$issuer" --aud "$client" \
  --sub ada --ttl 3600 --nonce aabbccdd --out "$work/ada-2.token" >/dev/null
enroll_again=$("$bin" coord enroll --name a --coord 10.200.0.1:7443 \
  --bundle "$coord_dir/trust-bundle.pem" --id-token-file "$work/ada-2.token" \
  --nonce aabbccdd --state "$state_a" --coord-name coord --endpoint 10.200.0.2:443)
printf '%s\n' "$enroll_again"
name_again=$(printf '%s\n' "$enroll_again" | awk '/^name /{print $2}')
overlay_again=$(printf '%s\n' "$enroll_again" | awk '/^overlay_ip /{print $2}')
[[ "$name_again" == "a" ]] || fail "DoD b failed. The name changed."
[[ "$overlay_again" == "$overlay_a" ]] || fail "DoD b failed. The overlay address changed."
new_key=$(key_id "$state_a/cert.pem")
[[ "$new_key" != "$old_key" ]] || fail "DoD b failed. The key id did not change."
python3 - "$coord_dir/deny.json" "$old_key" "$new_key" <<'PY'
import json
import sys
path, old_key, new_key = sys.argv[1:]
file = json.load(open(path))
ids = [item["key_id"] for item in file.get("revoked_leaf_keys", [])]
if old_key not in ids:
    raise SystemExit("old key is not denied")
if new_key in ids:
    raise SystemExit("new key is denied")
PY
reauth_n=$(python3 - "$coord_dir/config-audit.jsonl" <<'PY'
import json
import sys
count = 0
for line in open(sys.argv[1]):
    line = line.strip()
    if line and json.loads(line).get("action") == "reauth":
        count += 1
print(count)
PY
)
[[ "$reauth_n" == "1" ]] || fail "DoD b failed. The reauth audit count is ${reauth_n}."

"$idp" mint --dir "$idp_dir" --kid rs1 --issuer "$issuer" --aud "$client" \
  --sub ada --ttl 3600 --out "$work/ada-b.token" >/dev/null
enroll_b=$("$bin" coord enroll --name b --coord 10.200.0.1:7443 \
  --bundle "$coord_dir/trust-bundle.pem" --id-token-file "$work/ada-b.token" \
  --state "$state_b" --coord-name coord --endpoint 10.200.1.2:443)
overlay_b=$(printf '%s\n' "$enroll_b" | awk '/^overlay_ip /{print $2}')
[[ -n "$overlay_b" ]] || fail "Node b did not enroll."
ip netns exec "$ns_b" stdbuf -oL -eL "$bin" up --state-dir "$state_b" --listen 10.200.1.2:443 \
  --coord 10.200.0.1:7443 --coord-name coord --bundle "$coord_dir/trust-bundle.pem" \
  --metrics off >"$work/node-b.log" 2>&1 &
node_b_pid=$!

traffic=0
while [[ $(( $(date +%s) - reauth_start )) -lt 60 ]]; do
  status_b=$("$bin" status --state-dir "$state_a" || true)
  if printf '%s\n' "$status_b" | read_all grep -q "peer b .* path direct " \
    && ip netns exec "$ns_a" ping -c 1 -W 1 "$overlay_b" >/dev/null 2>&1; then
    traffic=1
    break
  fi
  sleep 1
done
[[ "$traffic" == "1" ]] || fail "DoD b failed. Peer traffic did not pass within 60 s."
echo "DoD b passed."
echo "elapsed_s ${SECONDS}"
echo "W25-47 PASS a b f"
exit 0
