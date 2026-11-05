# W25-42 step 2: METHOD (written and committed before the run)

Diagnostic run only. The gates are not changed. The 200 ms limit is not changed.
The 20:17 failure stays counted and unproven. Step 1 (22:04:43 KST stall) stays PROVISIONAL HARNESS.

## Run
- One run: `coord-cert-soak.sh` with `TR_DIAG=2`, `SOAK_TR_ENDS=6`, a new persistent `TR_OUT_DIR`,
  under `proof-lock.sh`, free space >= 15G checked first (else `proof_infra_abort`, no lock, no build).
- RELEASE build, `RUSTUP_TOOLCHAIN=stable` (1.99.1). `rustc -V` and the cargo
  "Finished `release` profile" line are recorded in the run log.
- The full `proof_contention` lines are quoted. samples >= 1, contended_samples 0 and
  unknown_samples 0 are required; unknown_samples > 0 makes the run INVALID.

- `ORBLX_SOAK_TRACE=1` on every node (owner, a, b, …). The compose x-node block passes
  `ORBLX_SOAK_TRACE` from the host. The host exports `ORBLX_SOAK_TRACE=1` before
  `coord-cert-soak.sh`. Any other value, or an unset variable, leaves the traces off
  (no clock, no allocate, no log on the forward path). The soak lines
  (`tun_write`, `to_tun_queued`, `to_tun_send_wait`, `runtime_tick_late`) are required
  for the stall report. This needs the ORBLX_SOAK_TRACE code from main (PR #153).
- Hard wall-clock limit: `SOAK_S + 15` minutes (8100 s when `SOAK_S=7200`), counted from
  wrapper start (lock wait included). A cancel for that limit:
  1. prints `proof_cancel reason=hard_limit_<N>s INVALID` to the run log,
  2. sends TERM to the soak process group so the soak EXIT trap runs `proof_lock_end`
     and prints `proof_lock <label> released at <time> pid=<pid>`,
  3. if the lock is still held after a short wait, prints the same release line from the
     wrapper and clears the holder, then stops the project with compose down.
  A hard-limit cancel makes the diagnostic run INVALID. It must not leave the proof lock held.

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
- Result reported: each window's classification with its evidence lines. Acceptance condition (a)
  for the later gate change is met only if every window > 200 ms is HARNESS-VCPU.
