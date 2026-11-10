#!/usr/bin/env bash
# W25-47 release proof. One run covers DoD a, DoD b, and DoD f.
# Eng Lead runs it on the final pull request head, after a release build.
# Any later push voids the run.
#
# This proof steps CLOCK_REALTIME. It is not in sweep-manifest.txt.
# The release sweep must not step the clock.
#
# Build, then run as root:
#   cargo build --release --locked -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp
#   sudo -n scripts/proof/w25-47-reauth.sh
# The state directories are under mktemp. The script does not use /var/lib/orblx.
#
# W25_47_LOCK=outer skips the in-script lock. The box launcher holds the lock.
# That mode requires W25_47_RUN_ID. The default mode takes the in-script lock.
# W25_47_ALARM_S is the iteration alarm (default 300). W25_47_SETUP_WAIT_S is the
# pre-marker orblx wait (default 20). The DoD recovery limit is 60 s. It is not
# an environment setting.
# W25_47_DRY=1 prints the start lines and does not step the clock. It does not
# print the PASS line.
#
# The stay-probe runs before any orblx process. It refuses with exit 2 when the
# step does not stay, or when the restored clock is more than 1 s from the
# monotonic elapsed time.
#
# The marker line is W25-47 first_clock_step. It is printed just before DoD b
# branch 2 (the live leaf). After that line the only exit is 1.
# Setup enroll and the first TUN run before the marker. Branch 2 re-auths that
# leaf while it is still inside not_after. The clock steps for DoD f and DoD a
# come after branch 2. DoD b branch 1 then re-auths the expired leaf.
#
# Exit codes:
#   0    DoD a, b, and f passed.
#   1    A check failed after the marker. This is the only exit after the marker.
#   2    Host clock precondition. Privilege, time sync, or the stay-probe.
#   3    Lock sampler invalid. Only before the marker.
#   4    Lock disk check. Only before the marker.
#   5    Lock foreign container. Only before the marker.
#   6    An orblx command failed before the marker.
#   7    A tool or file check failed. That step runs no orblx code.
#   124  The alarm or a signal fired before the marker.
#
# PASS lines, in order:
#   DoD b live passed.
#   DoD f passed.
#   DoD a passed.
#   DoD b passed.
#   W25-47 PASS a b f run_id=<id>
set -euo pipefail
# shellcheck source=scripts/proof/pipe-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pipe-lib.sh"
# shellcheck source=scripts/proof/proof-lock.sh
. "$PROOF_LIB_DIR/proof-lock.sh"
PROOF_MIN_FREE_GIB=15  # reason: the floor (PROOF_DISK_FLOOR_GIB, PO rule: 15 GiB free before builds).

RECOVERY_NS=60000000000
NS_PER_S=1000000000
NS_PER_MS=1000000
STOP_WAIT_NS=20000000000
NODE_URI="spiffe://orblx.local/node/a"
SESSION_UP_LINE="The peer SPIFFE ID is "

export W25_47_PROOF=1
run_id="${W25_47_RUN_ID:-}"
export W25_47_RUN_ID="$run_id"
lock_mode="${W25_47_LOCK:-script}"
alarm_s="${W25_47_ALARM_S:-300}"
setup_wait_s="${W25_47_SETUP_WAIT_S:-20}"
dry="${W25_47_DRY:-}"

if [[ "$lock_mode" != "script" && "$lock_mode" != "outer" ]]; then
  echo "W25-47 SETUP_FAIL lock run_id=${run_id}"
  exit 7
fi
if [[ "$lock_mode" == "outer" && -z "$run_id" ]]; then
  echo "W25-47 SETUP_FAIL run_id run_id="
  exit 7
fi
if [[ ! "$alarm_s" =~ ^[0-9]+$ || "$alarm_s" -lt 2 ]]; then
  echo "W25-47 SETUP_FAIL alarm run_id=${run_id}"
  exit 7
fi
if [[ ! "$setup_wait_s" =~ ^[0-9]+$ || "$setup_wait_s" -lt 1 ]]; then
  echo "W25-47 SETUP_FAIL setup_wait run_id=${run_id}"
  exit 7
fi

transcript=$(mktemp)
say() {
  printf '%s\n' "$1"
  printf '%s\n' "$1" >>"$transcript"
}

setup_fail() {
  say "W25-47 SETUP_FAIL $1 run_id=${run_id}"
  exit 7
}

host_invalid() {
  say "W25-47 HOST_INVALID_PRESTEP step=$1 run_id=${run_id}"
  exit 6
}

clock_fail() {
  echo "$1 run_id=${run_id}" >&2
  exit 2
}

mono_ns() {
  python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_MONOTONIC))'
}

realtime_ns() {
  python3 -c 'import time; print(time.clock_gettime_ns(time.CLOCK_REALTIME))'
}

set_clock_ns() {
  local target="$1" sec frac
  sec=$(( target / NS_PER_S ))
  frac=$(printf '%09d' $(( target % NS_PER_S )))
  date -u -s "@${sec}.${frac}" >/dev/null
}

restore_marked_clock() {
  local now elapsed target
  [[ -n "${mono_origin:-}" && -n "${real_origin:-}" ]] || return 0
  now=$(mono_ns) || return 0
  elapsed=$(( now - mono_origin ))
  target=$(( real_origin + elapsed ))
  set_clock_ns "$target" || true
  mono_origin=
  real_origin=
}

dod_fail() {
  local dod="$1" start_ns="$2" now elapsed
  now=$(mono_ns)
  elapsed=$(( (now - start_ns) / NS_PER_S ))
  say "W25-47 FAIL ${dod} recovery_mono_s=${elapsed} run_id=${run_id}"
  exit 1
}

say "run_id=${run_id}"

command -v python3 >/dev/null 2>&1 || setup_fail python3
command -v rustc >/dev/null 2>&1 || setup_fail rustc
command -v sha256sum >/dev/null 2>&1 || setup_fail sha256sum
command -v uname >/dev/null 2>&1 || setup_fail uname
command -v openssl >/dev/null 2>&1 || setup_fail openssl
command -v stdbuf >/dev/null 2>&1 || setup_fail stdbuf
command -v ip >/dev/null 2>&1 || setup_fail ip
command -v timeout >/dev/null 2>&1 || setup_fail timeout
command -v pgrep >/dev/null 2>&1 || setup_fail pgrep
[[ -r /sys/devices/system/clocksource/clocksource0/current_clocksource ]] || setup_fail clocksource

root=$(cd "$(dirname "$0")/../.." && pwd)
bin="${ORBLX_BIN:-$root/target/release/orblx}"
idp="${ORBLX_IDP_BIN:-$(dirname "$bin")/orblx-test-idp}"
case "$bin" in
  */debug/*) setup_fail "debug ${bin}" ;;
esac
case "$idp" in
  */debug/*) setup_fail "debug ${idp}" ;;
esac
[[ -x "$bin" && -x "$idp" ]] || setup_fail binary
head_sha=$(git -C "$root" rev-parse HEAD) || setup_fail git
bin_sha=$(sha256sum "$bin" | awk '{print $1}') || setup_fail sha256sum
idp_sha=$(sha256sum "$idp" | awk '{print $1}') || setup_fail sha256sum
clocksource=$(cat /sys/devices/system/clocksource/clocksource0/current_clocksource) || setup_fail clocksource

say "rustc $(rustc -V)"
say "cargo_profile=release"
say "head=${head_sha}"
say "bin_sha256=${bin_sha}"
say "idp_sha256=${idp_sha}"
say "uname_r=$(uname -r)"
say "clocksource=${clocksource}"
say "W25_47_ALARM_S=${alarm_s}"
say "W25_47_SETUP_WAIT_S=${setup_wait_s}"
say "lock=${lock_mode}"

if [[ "$dry" == "1" ]]; then
  say "new_key_id=0000000000000000000000000000000000000000000000000000000000000000"
  secret_scan "$transcript" || setup_fail secret_scan
  say "W25-47 DRY run_id=${run_id}"
  rm -f "$transcript"
  exit 0
fi

rm_transcript() {
  rm -f "$transcript"
}

if ! capsh --print 2>/dev/null | read_all grep -q cap_sys_time && [[ "$(id -u)" != "0" ]]; then
  clock_fail "The W25-47 release proof needs CAP_SYS_TIME or root. Eng Lead runs it."
fi

ntp_active() {
  local name="$1" pat
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$name" 2>/dev/null; then
    return 0
  fi
  pat="[${name:0:1}]${name:1}"
  pgrep -f "$pat" >/dev/null 2>&1
}

ntp_name=
for ntp_name in chronyd ntpd systemd-timesyncd; do
  if ntp_active "$ntp_name"; then
    clock_fail "Time sync is active (${ntp_name}). This proof does not stop it, because it cannot start it again. Stop ${ntp_name}, then run the proof."
  fi
done
say "ntp none"

# The stay-probe is a host precondition. It runs before any orblx process.
probe_mono=$(mono_ns) || setup_fail python3
probe_real=$(realtime_ns) || setup_fail python3
date -u -s "+2 min" >/dev/null || clock_fail "The stay-probe could not step the clock."
sleep 0.4
clock_mid=$(realtime_ns) || setup_fail python3
if [[ $(( clock_mid - probe_real )) -lt 60000000000 ]]; then
  elapsed=$(( $(mono_ns) - probe_mono ))
  set_clock_ns $(( probe_real + elapsed )) >/dev/null 2>&1 || true
  clock_fail "The clock did not stay stepped. Something other than chronyd, ntpd, or systemd-timesyncd put it back within 1 s. This proof cannot run on this host."
fi
elapsed=$(( $(mono_ns) - probe_mono ))
set_clock_ns $(( probe_real + elapsed )) || clock_fail "The stay-probe could not restore the clock."
clock_after=$(realtime_ns) || setup_fail python3
clock_want=$(( probe_real + elapsed ))
clock_delta=$(( clock_after - clock_want ))
if [[ "$clock_delta" -lt 0 ]]; then
  clock_delta=$(( -clock_delta ))
fi
if [[ "$clock_delta" -gt 1000000000 ]]; then
  set_clock_ns "$clock_want" >/dev/null 2>&1 || true
  clock_fail "The restored clock is ${clock_delta} ns from the monotonic elapsed time. This proof cannot run on this host."
fi
say "W25-47 stay_probe ok"
mono_origin=$(mono_ns) || setup_fail python3
real_origin=$(realtime_ns) || setup_fail python3

if [[ -n "$(git -C "$root" status --porcelain)" ]]; then
  setup_fail dirty
fi
command -v cargo >/dev/null 2>&1 || setup_fail cargo
cargo build --release --locked -p orblx-cli --bin orblx -p orblx-test-idp --bin orblx-test-idp \
  || setup_fail cargo
built_bin="$root/target/release/orblx"
built_idp="$root/target/release/orblx-test-idp"
[[ -x "$built_bin" && -x "$built_idp" ]] || setup_fail binary
built_bin_sha=$(sha256sum "$built_bin" | awk '{print $1}') || setup_fail sha256sum
built_idp_sha=$(sha256sum "$built_idp" | awk '{print $1}') || setup_fail sha256sum
run_bin_sha=$(sha256sum "$bin" | awk '{print $1}') || setup_fail sha256sum
run_idp_sha=$(sha256sum "$idp" | awk '{print $1}') || setup_fail sha256sum
if [[ "$run_bin_sha" != "$built_bin_sha" || "$run_idp_sha" != "$built_idp_sha" ]]; then
  setup_fail sha256
fi

# Outer mode has no in-script lock. The call below stays at the top level.
if [[ "$lock_mode" == "outer" ]]; then
  proof_lock_take() { :; }
  proof_lock_end() { :; }
fi
proof_lock_take "w25-47-reauth"

coord_pid=
idp_pid=
node_a_pid=
node_b_pid=
hello_pid=
watchdog_pid=
work=
ns_a=w2547a
ns_b=w2547b
forward_was=
rp_was=
cleaned=0
past_marker=0
alarm_start_ns=0

cleanup() {
  local decided=$?
  trap - EXIT INT TERM HUP
  if [[ "$cleaned" == 1 ]]; then
    exit "$decided"
  fi
  cleaned=1
  if [[ -n "${watchdog_pid:-}" ]]; then
    kill "$watchdog_pid" 2>/dev/null || true
    watchdog_pid=
  fi
  if [[ -n "${hello_pid:-}" ]]; then
    kill "$hello_pid" 2>/dev/null || true
    hello_pid=
  fi
  restore_marked_clock
  for pid in "${node_a_pid:-}" "${node_b_pid:-}" "${coord_pid:-}" "${idp_pid:-}"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for ns in "$ns_a" "$ns_b"; do
    if ip netns list 2>/dev/null | awk '{print $1}' | read_all grep -qx "$ns"; then
      while read -r pid; do
        [[ -n "$pid" ]] || continue
        kill "$pid" 2>/dev/null || true
      done < <(ip netns pids "$ns" 2>/dev/null || true)
      ip netns del "$ns" 2>/dev/null || true
    fi
  done
  ip link del veth-a 2>/dev/null || true
  ip link del veth-b 2>/dev/null || true
  if [[ -n "${forward_was:-}" ]]; then
    printf '%s\n' "$forward_was" >/proc/sys/net/ipv4/ip_forward || true
  fi
  if [[ -n "${rp_was:-}" ]]; then
    printf '%s\n' "$rp_was" >/proc/sys/net/ipv4/conf/all/rp_filter || true
  fi
  ( proof_lock_end ) || true
  if [[ -n "${work:-}" ]]; then
    rm -rf "$work"
  fi
  rm -f "$transcript"
  exit "$decided"
}
trap cleanup EXIT

on_signal() {
  if [[ "$past_marker" == 1 ]]; then
    say "W25-47 FAIL signal recovery_mono_s=0 run_id=${run_id}"
    exit 1
  fi
  echo "The proof got a signal before the marker. run_id=${run_id}" >&2
  exit 124
}
trap on_signal INT TERM HUP

on_alarm() {
  if [[ "$past_marker" == 1 ]]; then
    local now elapsed
    now=$(mono_ns)
    elapsed=$(( (now - alarm_start_ns) / NS_PER_S ))
    say "W25-47 FAIL iteration recovery_mono_s=${elapsed} run_id=${run_id}"
    exit 1
  fi
  echo "The iteration timed out after ${alarm_s} s. run_id=${run_id}" >&2
  exit 124
}
trap on_alarm USR1

alarm_start_ns=$(mono_ns) || setup_fail python3
(
  sleep "$alarm_s"
  kill -USR1 $$ 2>/dev/null || true
) &
watchdog_pid=$!

check_deadline() {
  local now elapsed limit_ns
  [[ "$past_marker" == 1 ]] || return 0
  now=$(mono_ns)
  elapsed=$(( now - alarm_start_ns ))
  limit_ns=$(( (alarm_s - 1) * NS_PER_S ))
  if [[ "$elapsed" -ge "$limit_ns" ]]; then
    say "W25-47 FAIL iteration recovery_mono_s=$(( elapsed / NS_PER_S )) run_id=${run_id}"
    exit 1
  fi
}

wait_prestep() {
  local step="$1" file="$2" pattern="$3" start now limit_ns
  start=$(mono_ns)
  limit_ns=$(( setup_wait_s * NS_PER_S ))
  while true; do
    now=$(mono_ns)
    if [[ $(( now - start )) -ge "$limit_ns" ]]; then
      host_invalid "$step"
    fi
    if [[ -f "$file" ]] && read_all grep -q -- "$pattern" <"$file"; then
      return 0
    fi
    sleep 1
  done
}

wait_file_prestep() {
  local step="$1" file="$2" start now limit_ns
  start=$(mono_ns)
  limit_ns=$(( setup_wait_s * NS_PER_S ))
  while true; do
    now=$(mono_ns)
    [[ -f "$file" ]] && return 0
    if [[ $(( now - start )) -ge "$limit_ns" ]]; then
      host_invalid "$step"
    fi
    sleep 1
  done
}

mark_elapsed() {
  local dod="$1" start="$2" what="$3" now ms
  now=$(mono_ns)
  ms=$(( (now - start) / NS_PER_MS ))
  say "W25-47 elapsed ${dod} ${what} mono_ms=${ms}"
}

wait_from() {
  local dod="$1" start="$2" file="$3" pattern="$4" what="$5" now
  while true; do
    check_deadline
    now=$(mono_ns)
    if [[ $(( now - start )) -ge "$RECOVERY_NS" ]]; then
      dod_fail "$dod" "$start"
    fi
    if [[ -f "$file" ]] && read_all grep -q -- "$pattern" <"$file"; then
      mark_elapsed "$dod" "$start" "$what"
      return 0
    fi
    sleep 1
  done
}

client_stopped() {
  local state
  [[ -n "${hello_pid:-}" ]] || return 0
  if [[ ! -d "/proc/${hello_pid}" ]]; then
    return 0
  fi
  state=$(awk '/^State:/ { print $2 }' "/proc/${hello_pid}/status" 2>/dev/null || true)
  [[ "$state" == "Z" ]]
}

child_alive() {
  local pid="$1" state
  [[ -n "$pid" ]] || return 1
  if [[ ! -d "/proc/${pid}" ]]; then
    return 1
  fi
  state=$(awk '/^State:/ { print $2 }' "/proc/${pid}/status" 2>/dev/null || true)
  [[ -n "$state" && "$state" != "Z" ]]
}

stop_timeout() {
  local step="$1"
  if [[ "$past_marker" == 1 ]]; then
    say "W25-47 FAIL stop-timeout step=${step} run_id=${run_id}"
    exit 1
  fi
  say "W25-47 HOST_INVALID_PRESTEP step=${step} run_id=${run_id}"
  exit 6
}

# Poll for 20 s on CLOCK_MONOTONIC, then SIGKILL. This clock decides.
# The iteration alarm does not decide a stop.
stop_child() {
  local pid="$1" step="$2" start now
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  start=$(mono_ns) || stop_timeout "$step"
  while child_alive "$pid"; do
    now=$(mono_ns) || stop_timeout "$step"
    if [[ $(( now - start )) -ge "$STOP_WAIT_NS" ]]; then
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 0.2
  done
  start=$(mono_ns) || stop_timeout "$step"
  while child_alive "$pid"; do
    now=$(mono_ns) || stop_timeout "$step"
    if [[ $(( now - start )) -ge "$STOP_WAIT_NS" ]]; then
      stop_timeout "$step"
    fi
    sleep 0.2
  done
  wait "$pid" 2>/dev/null || true
}

key_id() {
  openssl x509 -in "$1" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | tail -c 32 \
    | od -An -tx1 \
    | tr -d ' \n'
}

key_id_bounded() {
  timeout 60 bash -c '
    openssl x509 -in "$1" -pubkey -noout 2>/dev/null \
      | openssl pkey -pubin -outform DER 2>/dev/null \
      | tail -c 32 | od -An -tx1 | tr -d " \n"
  ' bash "$1"
}

work=$(mktemp -d) || setup_fail work
coord_dir="$work/coord"
state_a="$work/node-a"
state_b="$work/node-b"
state_c="$work/node-c"
idp_dir="$work/idp"
mkdir -p "$coord_dir" "$idp_dir" || setup_fail work
chmod 700 "$coord_dir" "$idp_dir" || setup_fail work
: >"$work/orblx.err" || setup_fail work

ip netns del "$ns_a" 2>/dev/null || true
ip netns del "$ns_b" 2>/dev/null || true
ip link del veth-a 2>/dev/null || true
ip link del veth-b 2>/dev/null || true
ip netns add "$ns_a" || setup_fail netns
ip netns add "$ns_b" || setup_fail netns
ip link add veth-a type veth peer name peer-a || setup_fail netns
ip link add veth-b type veth peer name peer-b || setup_fail netns
ip link set peer-a netns "$ns_a" || setup_fail netns
ip link set peer-b netns "$ns_b" || setup_fail netns
ip addr add 10.200.0.1/24 dev veth-a || setup_fail netns
ip addr add 10.200.1.1/24 dev veth-b || setup_fail netns
ip link set veth-a up || setup_fail netns
ip link set veth-b up || setup_fail netns
ip netns exec "$ns_a" ip link set lo up || setup_fail netns
ip netns exec "$ns_b" ip link set lo up || setup_fail netns
ip netns exec "$ns_a" ip addr add 10.200.0.2/24 dev peer-a || setup_fail netns
ip netns exec "$ns_b" ip addr add 10.200.1.2/24 dev peer-b || setup_fail netns
ip netns exec "$ns_a" ip link set peer-a up || setup_fail netns
ip netns exec "$ns_b" ip link set peer-b up || setup_fail netns
ip netns exec "$ns_a" ip route add default via 10.200.0.1 || setup_fail netns
ip netns exec "$ns_b" ip route add default via 10.200.1.1 || setup_fail netns
forward_was=$(cat /proc/sys/net/ipv4/ip_forward) || setup_fail sysctl
rp_was=$(cat /proc/sys/net/ipv4/conf/all/rp_filter) || setup_fail sysctl
printf '1\n' >/proc/sys/net/ipv4/ip_forward || setup_fail sysctl
printf '0\n' >/proc/sys/net/ipv4/conf/all/rp_filter || setup_fail sysctl
ip netns exec "$ns_a" ping -c 1 -W 2 10.200.0.1 >/dev/null || setup_fail netns
ip netns exec "$ns_b" ping -c 1 -W 2 10.200.0.1 >/dev/null || setup_fail netns

issuer=https://127.0.0.1:8443
client=orblx-w25-47
"$idp" init --dir "$idp_dir" --host 127.0.0.1 >/dev/null || host_invalid idp
stdbuf -oL -eL "$idp" serve --dir "$idp_dir" --issuer "$issuer" --listen 127.0.0.1:8443 >"$work/idp.log" 2>&1 &
idp_pid=$!
wait_prestep idp "$work/idp.log" "idp serve"

cat >"$coord_dir/policy.hujson" <<'POLICY' || setup_fail policy
{
  "owners": ["spiffe://orblx.local/node/a"],
  "userApproval": {
    "ownerUsers": ["oidc:ada"]
  }
}
POLICY
cat >"$work/coord.toml" <<CONF || setup_fail config
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
wait_prestep coord "$work/coord.log" "oidc issuer"
wait_file_prestep coord "$coord_dir/trust-bundle.pem"

"$idp" mint --dir "$idp_dir" --kid rs1 --issuer "$issuer" --aud "$client" \
  --sub ada --ttl 3600 --out "$work/ada-1.token" >/dev/null || host_invalid token
enroll_a=$("$bin" coord enroll --name a --coord 10.200.0.1:7443 \
  --bundle "$coord_dir/trust-bundle.pem" --id-token-file "$work/ada-1.token" \
  --state "$state_a" --coord-name coord --endpoint 10.200.0.2:443 2>>"$work/orblx.err") || host_invalid enroll
overlay_a=$(printf '%s\n' "$enroll_a" | awk '/^overlay_ip /{print $2}')
name_a=$(printf '%s\n' "$enroll_a" | awk '/^name /{print $2}')
[[ "$name_a" == "a" && -n "$overlay_a" ]] || host_invalid enroll
old_key=$(key_id "$state_a/cert.pem") || host_invalid enroll
[[ "$old_key" =~ ^[0-9a-f]{64}$ ]] || host_invalid enroll
say "old_key_id=${old_key}"

ip netns exec "$ns_a" stdbuf -oL -eL "$bin" up --state-dir "$state_a" --listen 10.200.0.2:443 \
  --coord 10.200.0.1:7443 --coord-name coord --bundle "$coord_dir/trust-bundle.pem" \
  --metrics off >"$work/node-a.log" 2>&1 &
node_a_pid=$!
wait_prestep tun "$work/node-a.log" "The TUN device is"
stop_child "$node_a_pid" stop-node-a
node_a_pid=

step_mono=$(mono_ns) || dod_fail setup "$alarm_start_ns"
say "W25-47 first_clock_step mono_ns=${step_mono} realtime_ns=$(realtime_ns)"
past_marker=1

say "DoD b live: re-auth while the old leaf is inside not_after."
say "DoD b order: a_crash_after_deny_and_a_crash_after_nodes_match_the_audit_rule"
live_mono=$(mono_ns)
cp -a "$state_a" "$work/state-a-old" || dod_fail b "$live_mono"
old_keys=$(timeout 60 python3 - "$coord_dir/nodes.json" <<'PY'
import json
import sys
file = json.load(open(sys.argv[1]))
keys = []
for node in file["nodes"]:
    if node.get("name") != "a":
        continue
    for item in node.get("live_leaf_keys") or []:
        keys.append(item["key_id"])
if not keys:
    raise SystemExit("no live leaf key")
print(",".join(keys))
PY
) || dod_fail b "$live_mono"
old_nonces=$(timeout 60 python3 - "$coord_dir/nodes.json" <<'PY'
import json
import sys
file = json.load(open(sys.argv[1]))
nonces = []
for node in file["nodes"]:
    if node.get("name") != "a":
        continue
    for item in node.get("live_ticket_nonces") or []:
        nonces.append(item["nonce"])
if not nonces:
    raise SystemExit("no live nonce")
print(",".join(nonces))
PY
) || dod_fail b "$live_mono"

timeout 60 "$idp" mint --dir "$idp_dir" --kid rs1 --issuer "$issuer" --aud "$client" \
  --sub ada --ttl 3600 --nonce aabbccdd --out "$work/ada-2.token" >/dev/null || dod_fail b "$live_mono"
enroll_again=$(timeout 60 "$bin" coord enroll --name a --coord 10.200.0.1:7443 \
  --bundle "$coord_dir/trust-bundle.pem" --id-token-file "$work/ada-2.token" \
  --nonce aabbccdd --state "$state_a" --coord-name coord --endpoint 10.200.0.2:443 \
  2>>"$work/orblx.err") || dod_fail b "$live_mono"
name_again=$(printf '%s\n' "$enroll_again" | awk '/^name /{print $2}')
overlay_again=$(printf '%s\n' "$enroll_again" | awk '/^overlay_ip /{print $2}')
[[ "$name_again" == "a" ]] || dod_fail b "$live_mono"
[[ "$overlay_again" == "$overlay_a" ]] || dod_fail b "$live_mono"
new_key=$(key_id_bounded "$state_a/cert.pem") || dod_fail b "$live_mono"
[[ "$new_key" != "$old_key" ]] || dod_fail b "$live_mono"
say "new_key_id=${new_key}"
checked=$(timeout 60 python3 - "$coord_dir/deny.json" "$coord_dir/config-audit.jsonl" "$old_key" "$new_key" "$old_keys" "$old_nonces" "$NODE_URI" <<'PY'
import json
import re
import sys
deny_path, audit_path, old_key, new_key, key_text, nonce_text, node_uri = sys.argv[1:]
deny = json.load(open(deny_path))
ids = [item["key_id"] for item in deny.get("revoked_leaf_keys", [])]
old_keys = [item for item in key_text.split(",") if item]
if not old_keys:
    raise SystemExit("no live leaf key")
for key in old_keys:
    if key not in ids:
        raise SystemExit("old key is not denied")
if new_key in ids:
    raise SystemExit("new key is denied")
revoked = set(deny.get("revoked_ticket_nonces", []))
old_nonces = [item for item in nonce_text.split(",") if item]
if not old_nonces:
    raise SystemExit("no old nonce")
for nonce in old_nonces:
    if nonce not in revoked:
        raise SystemExit("old nonce is not denied")
records = []
for line in open(audit_path):
    line = line.strip()
    if not line:
        continue
    item = json.loads(line)
    if item.get("action") == "reauth":
        records.append(item)
if len(records) != 1:
    raise SystemExit("reauth count %s" % len(records))
detail = records[0].get("detail", "")
if node_uri not in detail:
    raise SystemExit("detail has no node uri")
match = re.search(r"\bold ([0-9a-f]{64}(?:,[0-9a-f]{64})*) new ([0-9a-f]{64})\b", detail)
if match is None:
    raise SystemExit("detail has no key fields")
old_field = match.group(1).split(",")
if old_key not in old_field or match.group(2) != new_key:
    raise SystemExit("detail keys do not match")
print(
    "live_leaf_keys_checked=%d live_ticket_nonces_checked=%d"
    % (len(old_keys), len(old_nonces))
)
PY
) || dod_fail b "$live_mono"
[[ "$checked" == live_leaf_keys_checked=* ]] || dod_fail b "$live_mono"
say "$checked"

timeout 60 "$idp" mint --dir "$idp_dir" --kid rs1 --issuer "$issuer" --aud "$client" \
  --sub ada --ttl 3600 --out "$work/ada-b.token" >/dev/null || dod_fail b "$live_mono"
enroll_b=$(timeout 60 "$bin" coord enroll --name b --coord 10.200.0.1:7443 \
  --bundle "$coord_dir/trust-bundle.pem" --id-token-file "$work/ada-b.token" \
  --state "$state_b" --coord-name coord --endpoint 10.200.1.2:443 2>>"$work/orblx.err") || dod_fail b "$live_mono"
[[ -n "$enroll_b" ]] || dod_fail b "$live_mono"
cp "$coord_dir/deny.json" "$state_b/deny.json" || dod_fail b "$live_mono"
ip netns exec "$ns_b" stdbuf -oL -eL "$bin" up --state-dir "$state_b" --listen 10.200.1.2:443 \
  --coord 10.200.0.1:7443 --coord-name coord --bundle "$coord_dir/trust-bundle.pem" \
  --metrics off >"$work/node-b.log" 2>&1 &
node_b_pid=$!
wait_from b "$live_mono" "$work/node-b.log" "The TUN device is" "live-tun"

present() {
  local start="$1" log="$2" pattern="$3" cert="$4" key="$5" ticket="$6" what="$7"
  local now hello_code
  : >"$work/hello.out"
  : >"$work/hello.err"
  "$bin" hello-quic client \
    --cert "$cert" --key "$key" --bundle "$coord_dir/trust-bundle.pem" \
    --ticket "$ticket" --connect 10.200.1.2:443 \
    >"$work/hello.out" 2>"$work/hello.err" &
  hello_pid=$!
  wait_from b "$start" "$log" "$pattern" "${what}-refusal"
  while true; do
    check_deadline
    now=$(mono_ns)
    if [[ $(( now - start )) -ge "$RECOVERY_NS" ]]; then
      stop_child "$hello_pid" stop-hello
      hello_pid=
      if [[ -s "$work/hello.err" ]]; then
        cat "$work/hello.err" >>"$work/orblx.err"
      fi
      dod_fail b "$start"
    fi
    if client_stopped; then
      break
    fi
    sleep 1
  done
  hello_code=0
  local reap_start
  reap_start=$(mono_ns) || stop_timeout stop-hello
  while child_alive "$hello_pid"; do
    now=$(mono_ns) || stop_timeout stop-hello
    if [[ $(( now - reap_start )) -ge "$STOP_WAIT_NS" ]]; then
      kill -KILL "$hello_pid" 2>/dev/null || true
      stop_timeout stop-hello
    fi
    sleep 0.2
  done
  wait "$hello_pid" || hello_code=$?
  hello_pid=
  if [[ -s "$work/hello.err" ]]; then
    cat "$work/hello.err" >>"$work/orblx.err"
  fi
  if [[ "$hello_code" -eq 0 || "$hello_code" -eq 127 ]]; then
    dod_fail b "$start"
  fi
  if read_all grep -q -F -- "$SESSION_UP_LINE" <"$work/hello.out" \
    || read_all grep -q -F -- "$SESSION_UP_LINE" <"$work/hello.err"; then
    dod_fail b "$start"
  fi
  mark_elapsed b "$start" "$what"
}

present "$live_mono" "$work/node-b.log" "The leaf check failed. The deny list contains this identifier." \
  "$work/state-a-old/cert.pem" "$work/state-a-old/key.pem" "$work/state-a-old/ticket.bin" "old-leaf"
rm -rf "$work/state-a-ticket"
cp -a "$state_a" "$work/state-a-ticket" || dod_fail b "$live_mono"
cp "$work/state-a-old/ticket.bin" "$work/state-a-ticket/ticket.bin" || dod_fail b "$live_mono"
cp "$work/state-a-old/ticket.bin.mac" "$work/state-a-ticket/ticket.bin.mac" || dod_fail b "$live_mono"
present "$live_mono" "$work/node-b.log" "The capability ticket check rejected the peer. The deny list contains this identifier." \
  "$work/state-a-ticket/cert.pem" "$work/state-a-ticket/key.pem" "$work/state-a-ticket/ticket.bin" "old-ticket"
stop_child "$node_b_pid" stop-node-b
node_b_pid=
say "DoD b live passed."

say "DoD f: step the clock 11 min so the coordinator leaf is due."
date -u -s "+11 min" >/dev/null || dod_fail f "$step_mono"
wait_from f "$step_mono" "$work/coord.log" "coord svid renewed" "coord-renew"
say "DoD f passed."

ip netns exec "$ns_a" stdbuf -oL -eL "$bin" up --state-dir "$state_a" --listen 10.200.0.2:443 \
  --coord 10.200.0.1:7443 --coord-name coord --bundle "$coord_dir/trust-bundle.pem" \
  --metrics off >"$work/node-a-again.log" 2>&1 &
node_a_pid=$!
wait_from a "$step_mono" "$work/node-a-again.log" "The TUN device is" "node-tun"

say "DoD a: step the clock 17 min so the node leaf is past the grace."
date -u -s "+17 min" >/dev/null || dod_fail a "$step_mono"
a_start=$(mono_ns)
status_a=
while true; do
  check_deadline
  now=$(mono_ns)
  if [[ $(( now - a_start )) -ge "$RECOVERY_NS" ]]; then
    dod_fail a "$a_start"
  fi
  status_a=$(timeout 60 "$bin" status --state-dir "$state_a" 2>>"$work/orblx.err" || true)
  if printf '%s\n' "$status_a" | read_all grep -q "state needs-reauth" \
    && printf '%s\n' "$status_a" | read_all grep -q "reauth orblx login --name a"; then
    break
  fi
  status_a=
  sleep 1
done
say "$status_a"
say "DoD a passed."

say "DoD b expired: re-auth after the leaf end."
expired_mono=$(mono_ns)
cp -a "$state_a" "$work/state-a-expired" || dod_fail b "$expired_mono"
expired_key=$(key_id_bounded "$work/state-a-expired/cert.pem") || dod_fail b "$expired_mono"
timeout 60 "$idp" mint --dir "$idp_dir" --kid rs1 --issuer "$issuer" --aud "$client" \
  --sub ada --ttl 3600 --nonce bbeeff00 --out "$work/ada-3.token" >/dev/null || dod_fail b "$expired_mono"
enroll_late=$(timeout 60 "$bin" coord enroll --name a --coord 10.200.0.1:7443 \
  --bundle "$coord_dir/trust-bundle.pem" --id-token-file "$work/ada-3.token" \
  --nonce bbeeff00 --state "$state_a" --coord-name coord --endpoint 10.200.0.2:443 \
  2>>"$work/orblx.err") || dod_fail b "$expired_mono"
name_late=$(printf '%s\n' "$enroll_late" | awk '/^name /{print $2}')
overlay_late=$(printf '%s\n' "$enroll_late" | awk '/^overlay_ip /{print $2}')
[[ "$name_late" == "a" ]] || dod_fail b "$expired_mono"
[[ "$overlay_late" == "$overlay_a" ]] || dod_fail b "$expired_mono"
late_key=$(key_id_bounded "$state_a/cert.pem") || dod_fail b "$expired_mono"
[[ "$late_key" != "$expired_key" ]] || dod_fail b "$expired_mono"
say "expired_new_key_id=${late_key}"
timeout 60 python3 - "$coord_dir/deny.json" "$coord_dir/config-audit.jsonl" "$late_key" "$expired_key" "$NODE_URI" <<'PY' || dod_fail b "$expired_mono"
import json
import sys
import time
deny_path, audit_path, new_key, expired_key, node_uri = sys.argv[1:]
deny = json.load(open(deny_path))
now = int(time.time())
for item in deny.get("revoked_leaf_keys", []):
    if now > int(item["not_after"]) + 60:
        raise SystemExit("stale leaf")
    if item["key_id"] == expired_key:
        raise SystemExit("expired key is still denied")
records = []
none_records = []
for line in open(audit_path):
    line = line.strip()
    if not line:
        continue
    item = json.loads(line)
    if item.get("action") != "reauth":
        continue
    records.append(item)
    detail = item.get("detail", "")
    if " old none " in " %s " % detail:
        none_records.append(item)
if len(records) != 2:
    raise SystemExit("reauth count %s" % len(records))
if len(none_records) != 1:
    raise SystemExit("old none count %s" % len(none_records))
detail = none_records[0].get("detail", "")
if node_uri not in detail or "new %s" % new_key not in detail:
    raise SystemExit("old none detail does not match")
PY

timeout 60 "$idp" mint --dir "$idp_dir" --kid rs1 --issuer "$issuer" --aud "$client" \
  --sub ada --ttl 3600 --out "$work/ada-c.token" >/dev/null || dod_fail b "$expired_mono"
enroll_c=$(timeout 60 "$bin" coord enroll --name c --coord 10.200.0.1:7443 \
  --bundle "$coord_dir/trust-bundle.pem" --id-token-file "$work/ada-c.token" \
  --state "$state_c" --coord-name coord --endpoint 10.200.1.2:443 2>>"$work/orblx.err") || dod_fail b "$expired_mono"
[[ -n "$enroll_c" ]] || dod_fail b "$expired_mono"
cp "$coord_dir/deny.json" "$state_c/deny.json" || dod_fail b "$expired_mono"
ip netns exec "$ns_b" stdbuf -oL -eL "$bin" up --state-dir "$state_c" --listen 10.200.1.2:443 \
  --coord 10.200.0.1:7443 --coord-name coord --bundle "$coord_dir/trust-bundle.pem" \
  --metrics off >"$work/node-c.log" 2>&1 &
node_b_pid=$!
wait_from b "$expired_mono" "$work/node-c.log" "The TUN device is" "expired-tun"
present "$expired_mono" "$work/node-c.log" "The leaf check failed. The end time has passed." \
  "$work/state-a-expired/cert.pem" "$work/state-a-expired/key.pem" "$work/state-a-expired/ticket.bin" "expired-leaf"
rm -rf "$work/state-a-expired-ticket"
cp -a "$state_a" "$work/state-a-expired-ticket" || dod_fail b "$expired_mono"
cp "$work/state-a-expired/ticket.bin" "$work/state-a-expired-ticket/ticket.bin" || dod_fail b "$expired_mono"
cp "$work/state-a-expired/ticket.bin.mac" "$work/state-a-expired-ticket/ticket.bin.mac" || dod_fail b "$expired_mono"
present "$expired_mono" "$work/node-c.log" "The capability ticket check rejected the peer. The end time has passed." \
  "$work/state-a-expired-ticket/cert.pem" "$work/state-a-expired-ticket/key.pem" "$work/state-a-expired-ticket/ticket.bin" "expired-ticket"

say "DoD b passed."
say "elapsed_s $(( ($(mono_ns) - alarm_start_ns) / NS_PER_S ))"
secret_scan "$transcript" || dod_fail secret "$expired_mono"
if [[ -s "$work/orblx.err" ]]; then
  secret_scan "$work/orblx.err" || dod_fail secret "$expired_mono"
fi
for scan_file in "$work"/*.log; do
  [[ -s "$scan_file" ]] || continue
  secret_scan "$scan_file" || dod_fail secret "$expired_mono"
done
say "W25-47 PASS a b f run_id=${run_id}"
exit 0
