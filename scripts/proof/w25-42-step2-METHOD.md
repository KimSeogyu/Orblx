# W25-42 step 2: METHOD (written and committed before the run)

Diagnostic run only. The gates are not changed. The 200 ms limit is not changed.
The 20:17 failure stays counted and unproven. Step 1 (22:04:43 KST stall) stays PROVISIONAL HARNESS.

## Run
- Run `scripts/proof/coord-cert-soak.sh` one time.
- Set `SOAK_S=7200`.
- Set `SOAK_TR_ENDS=6`.

The script sets the ticket-end count to the largest of `SOAK_TR_ENDS` (when set), `ends_for_soak`, and `ends_for_coord`. A set `SOAK_TR_ENDS` stays at or above `ends_for_soak`. `ticket-renewal.sh` sizes the run end from the latest first ticket end. The earlier intervals use the renewal period. The last interval uses the ticket life. Gate 1 counts an end when `e + MAX_SKEW` is before the run end. Gate 1 requires `TR_ENDS` ends. The last interval keeps a late renewal inside that count.

- Set `TR_DIAG=2`.
- Set `ORBLX_SOAK_TRACE=1` on the host before the script starts.
- Use a new persistent `TR_OUT_DIR`.
- Run the script under `scripts/proof/proof-lock.sh`.
- Check free space before the lock. The minimum is 15 GiB.
- When free space is below 15 GiB, the script prints `proof_infra_abort`.
- A `proof_infra_abort` stops the run before the lock and before the build.
- Set `RUSTUP_TOOLCHAIN=stable` for the build.
- The run log records the text from `rustc -V`.
- The run log records the cargo release `Finished` line.
- The stack does not use the Docker DNS server at 127.0.0.11. The subnet is `TR_NET.0/24`. This soak sets `TR_NET` to 172.28.49, so the subnet is 172.28.49.0/24. The static addresses are coord 172.28.49.10, a 172.28.49.11, b 172.28.49.12, c 172.28.49.13, and owner 172.28.49.20. The pool `ip_range` is 172.28.49.64/26, and that pool does not contain the static addresses. Each service has hosts entries for coord, owner, a, b, and c. The script prints one line, `preflight docker_dns ok` or `preflight docker_dns unavailable (not needed: fixed IPs and hosts entries)`. That line does not fail the run. The script then runs `getent hosts` for each of those names inside the coord, owner, a, b, and c containers. A name that does not resolve stops the run.
- Quote each full `proof_contention` line.
- The run is valid only when `samples` is 1 or more, `contended_samples` is 0, and `unknown_samples` is 0.
- When `unknown_samples` is more than 0, the run is INVALID.

- `ORBLX_SOAK_TRACE=1` on every node (owner, a, b, …). The compose x-node block passes
  `ORBLX_SOAK_TRACE` from the host. The host exports `ORBLX_SOAK_TRACE=1` before
  `coord-cert-soak.sh`. Any other value, or an unset variable, leaves the traces off
  (no clock, no allocate, no log on the forward path).   The soak lines
  (`tun_write`, `to_tun_queued`, `to_tun_send_wait`, `to_tun_stall`,
  `to_tun_stall_keepalive`, `session_close`, `idle_timeout_ms`, `runtime_tick_late`)
  are required for the stall report. `to_tun_send_wait` includes `stall_ms`.
  `to_tun_stall peer=NAME stall_ms=N` is one per-link `to_tun.send` wait.
  An open stall prints that line once per second after 1 s.
  A finished stall of 100 ms or more prints that line once, with that `stall_ms`.
  `unix_ms` on `to_tun_stall` is the print time. `stall_ms` is whole milliseconds, rounded down.
  A finished wait under 100 ms is only on `to_tun_send_wait` (`stall_ms` may be 0 when `max_us` is under 1000).
  Field 2 is `to_tun_stall_keepalive peer=<p> inbound_keepalive_during_stall=<count>`, once per finished stall episode.
  Field 4 is `session_close peer=<p> reason=<idle_timeout|...> during_stall=<0|1>`, whenever a peer session closes.
  Each node prints `idle_timeout_ms` once at start for the peer QUIC timeout, the QUIC keepalive,
  the relay `PEER_IDLE`, and the coordinator QUIC timeout, with `src` file:line.
  This needs the ORBLX_SOAK_TRACE code from main (PR #153) and the stall lines (PR #171).
- Hard wall-clock limit: `SOAK_S + 15` minutes (8100 s when `SOAK_S=7200`), counted from
  wrapper start (lock wait included). A cancel for that limit:
  1. prints `proof_cancel reason=hard_limit_<N>s INVALID` to the run log,
  2. sends TERM to the soak process group so the soak EXIT trap runs `proof_lock_end`
     and prints `proof_lock <label> released at <time> pid=<pid>`,
  3. if the lock is still held after a short wait, prints the same release line from the
     wrapper and clears the holder, then stops the project with compose down.
  A hard-limit cancel makes the diagnostic run INVALID. It must not leave the proof lock held.

## Per-link stall (option (c) merge gate)
For each node log and each peer, take the maximum `stall_ms` on `to_tun_stall` and the maximum
`stall_ms` on `to_tun_send_wait`. The per-link stall is the larger of those two values.
A peer with no `stall_ms` field has no recorded `to_tun.send` wait in that log.

## PASS rules
1. Direct path: max stall_ms must be clearly under the QUIC max_idle_timeout 30 s (crates/orblx-datapath/src/quic.rs:864), with the margin stated. It is preferred that max stall_ms is also under the keepalive interval 10 s (quic.rs:867), so that inbound keepalives do not wait a full period.
2. Relayed path: max stall_ms must be under the relay PEER_IDLE 1 s (crates/orblx-relay/src/server.rs:25), with the margin stated. If the max stall on a relayed link is >= 1 s, option (c) alone FAILS for relay. Then (b) or a control-frame reader is required. A change to PEER_IDLE needs a decision from PO and Crypto first.
3. Fields 2 and 4 are required before the soak starts.

This METHOD does not change the gates. The gates stay as they are.

## What is measured (all inside TR_OUT_DIR)
1. In-container ping, 12 directions (`dc exec SRC ping -D -O`), unchanged: `ping-SRC-DST.txt`.
2. Host prober, same 12 directions, raw ICMP sent from the host inside each node's net namespace
   (`nsenter --net=/proc/<node pid>/ns/net`), to the overlay IPs 100.64.0.x, 20/s per target,
   kernel receive timestamps: `hostprobe-SRC.txt`. The path (route via orblx0, source address)
   is recorded at start with `ip route get` per target: `prober-path.txt`.
3. Kernel TUN netdev counters of each node, orblx0 rx/tx packets, read on the host from
   `/proc/<node pid>/net/dev` every 10 ms by a separate process (`sched-sampler.py`), not by the
   node: `N` lines in `sched-threads.txt.gz`. A paused node diag thread cannot fake these.
4. Per-thread scheduler state every 10 ms for every node thread, every ping process and every
   host prober: state, CPU (stat field 39), run and run-queue wait time (schedstat): `T` lines.
5. Per-CPU /proc/stat tick deltas every 100 ms (user..steal): `cpu-stat.txt`.
6. Per-CPU heartbeat: one process pinned to each CPU sleeps 5 ms; a wake >= 20 ms late is an
   `L` line: `cpu-heartbeat.txt`.
7. Scheduler trace (tracefs instance, clock mono): sched_switch, sched_wakeup,
   sched_migrate_task for comm ping, orblx*, tokio-runtime-w: `sched-trace.txt.gz`.
8. Everything from step 1 (node diag files, host samples, docker events, dmesg).

## Classification rule (per window of overlapping in-container ping gaps > 200 ms)
Applied by `scripts/proof/sched-analyze.py`, in this order:
1. UNCLASSIFIED (missing data): a stalled direction has no sampled ping process, or the
   sampler has no samples in the window.
2. PRODUCT: a host prober gap > 200 ms overlaps the window, or a kernel orblx0 rx or tx counter
   of any node does not move for > 200 ms inside the window.
3. HARNESS-VCPU: every stalled ping process was last sampled on the same CPU X before its gap,
   and CPU X was frozen in the window (heartbeat >= 100 ms late, or /proc/stat <= 1 tick per
   100 ms for >= 200 ms), while probers and TUN counters continued.
4. HARNESS-OTHER: probers and TUN counters continued, but rule 3 does not hold.
Any host prober gap > 200 ms with no in-container gap is printed as PROBER_GAP (product evidence).

## Pass / fail of this diagnostic run
- Valid: the run completes under the lock with samples >= 1, contended 0, unknown 0, and all
  files 1-7 exist and are complete (gzip readable).
- The TR gates are reported as they are, unchanged; a gate 4 FAIL still counts.
- Gate 2 counts the coordinator leaf ends. This branch renews the coordinator leaf. The change is a port of ea14d77 (#155).
- Result reported: each window's classification with its evidence lines. Acceptance condition (a)
  for the later gate change is met only if every window > 200 ms is HARNESS-VCPU.

## Discriminating release run plan

This section is a plan. It does not start the proof.
R2 on `d16e3fb` stays FAIL. The cause stays UNCLASSIFIED.
Do not record R2 as `proof_infra_abort`.
Do not raise a TTL. Do not raise a limit. Do not drop a stall window.

R2 used `SOAK_S=7200`, `SOAK_COORD_ENDS=3`, and an unset `SOAK_TR_ENDS`.
The host sample file has `CLOCK_REALTIME` only.
`dt_ms` comes from that same clock. A match of `dt_ms` to the wall gap is not a second clock.
`cgroup_cpu_some_ms` is PSI cpu.pressure stall time. It is not CPU time consumed.
The renewal at 06:12:58 and the leaf expiry at 06:17:58 sit inside the unsampled wall gap 06:03:50.897 to 06:25:35.131.
`unknown_samples=0` on the contention line does not mean that interval was fully observed.

### Knobs

Use these knobs. Do not use `TR_DIAG=2`.

- `SOAK_S=7200`
- `SOAK_COORD_ENDS=3`
- Leave `SOAK_TR_ENDS` unset. The script keeps `TR_ENDS` at or above `ends_for_soak`.
- `TR_DIAG=0`. This starts the host sampler. It does not start host probers, scheduler sampling, docker events, or `ping -O`.
- `ORBLX_SOAK_TRACE=0`. Product stall traces stay off.
- Set a new persistent `TR_OUT_DIR`.
- `RUSTUP_TOOLCHAIN=stable`.
- Run under `scripts/proof/proof-lock.sh`.
- The free-space floor stays 15 GiB. `proof_infra_abort` applies only when free space is below that floor before the lock.
- The wrapper timeout is at least `SOAK_S + 15` minutes (8100 s). Count it from wrapper start.

`TR_DIAG=0` still runs the product gates inside `ticket-renewal.sh`.
The harness writes `host-samples.txt`, `host-coverage.txt`, and `stack.log` under `TR_OUT_DIR`.
`stack.log` is the docker log. It is the raw renewal and refusal record.
Ping files stay in the work directory. The script removes that directory at exit.

### Clocks

Each host sample stores three clocks in nanoseconds.

- `clk_realtime_ns` is `CLOCK_REALTIME`. It is wall time. It can step forward or backward.
- `clk_monotonic_ns` is `CLOCK_MONOTONIC`. It does not include Linux suspend. It does not follow a wall step.
- `clk_boottime_ns` is `CLOCK_BOOTTIME`. It includes Linux suspend. It does not follow a wall step.

The three reads are sequential.
`clk_capture_skew_ns` is a later `CLOCK_REALTIME` read minus `clk_realtime_ns`.
A gap smaller than that skew is inside the capture spread.
A missing clock is the token `unsupported`. The sampler does not copy another clock into that field.
No pattern of these three clocks identifies every hypervisor pause.

### What the patterns can show

- `cadence`: all three deltas stay within 5 sample intervals. This is the normal sample gap. A pause shorter than the gap stays invisible.
- `wall_forward`: realtime jumps by 1 s or more, and monotonic and boottime stay small. The wall clock stepped forward. This is not Linux suspend. Suspend also moves boottime.
- `wall_backward`: realtime moves backward and monotonic stays non-negative. The report keeps the negative delta.
- `suspend_shaped`: monotonic stays small, and realtime and boottime both jump by 1 s or more. This matches Linux suspend accounting. It does not name a hypervisor pause.
- `unresolved_gap`: all three clocks jump by 1 s or more and stay close to each other. This matches a sampler delay. It also matches a guest pause that moves all three clocks. These clocks cannot separate those causes.
- `clock_unsupported`: one clock is missing. The report does not call the span fully observed.
- `mixed` or `clock_backward`: the span does not match a pattern above. The report keeps the raw deltas.

### Coverage fields

`host-coverage.txt` and the proof log report:

- `observation_samples`
- `observation_elapsed_realtime_ns`, `observation_elapsed_monotonic_ns`, `observation_elapsed_boottime_ns` for the whole run, including every gap
- `observation_max_unsampled_realtime_ns`, `observation_max_unsampled_monotonic_ns`, `observation_max_unsampled_boottime_ns` with `start_ns` and `end_ns`
- `observation_negative_*_spans` and `observation_min_*_dt_ns` when a delta is negative
- `observation_large_spans` and `observation_clock_pattern_counts`
- `observation_max_capture_skew_ns` and `observation_min_capture_skew_ns`
- `observation_mark <name> fully_observed yes|no reason <pattern>` for each recorded ticket end
- `observation_note contention_unknown_samples_do_not_mean_a_renewal_interval_was_fully_observed`
- `observation_pressure_note cgroup_cpu_some_ms_is_psi_stall_not_cpu_time_consumed`
- `observation_pattern_limit no_clock_pattern_identifies_every_hypervisor_pause`

A mark is `fully_observed yes` only when every overlapping span is `cadence`.
A large unsampled gap over a renewal or expiry is `fully_observed no`.
`unknown_samples=0` does not change that result.

### Gates and outcomes

Keep every product gate and every security gate.
A peer that rejects an expired ticket still fails the proof.
The run keeps the full `SOAK_S` window.
A clock gap does not delete samples and does not relabel the run as `proof_infra_abort`.
Record `rustc -V`, the cargo release `Finished` line, and `orblx_bin_sha256` from the proof log.
Record the `proof_lock` acquire line and the `proof_lock` release line.
Quote the `proof_contention` line.
`unknown_samples` remains the contention check. It is not an observation check.

### Observer limit

No independent observer is confirmed for this plan.
Containers on this computer share this VM. They are not an independent clock.
The registered Mac lists connected. No independent heartbeat is configured on it.
The Android endpoint lists offline.
This plan does not provision an observer. It does not send proof telemetry off the host.
A later run may add an observer only after a separate authorization.
The missing observer does not block the local three-clock sampler.
The local sampler cannot replace that observer.
