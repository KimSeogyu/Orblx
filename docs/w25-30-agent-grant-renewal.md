# W25-30: Agent grant renewal without a restart

## Scope

W25-26 (#117) fixes the node path only: on renewal, `apply_leaf` in `orblx-datapath` reloads the new capability ticket.
This item fixes the agent path (area "IdentityAgents": W21 agent JIT grant, W22 Python SDK).
The agent path does not use the datapath. This change does not need #117. The branch starts from `main`.

No new crypto, no wire change, and no policy change are in this change.

## Behavior on main

- Coordinator: `orblx agent grant request`, then a human owner approves with `orblx admin grant-approve ID`, then `orblx agent grant fetch --id ID --out DIR`.
  The fetch works one time only. It issues the agent SVID, the agent JIT ticket, and the signed grant.
  The window is from the fetch time to fetch time + TTL (300 s or less).
  The coordinator accepts many grants for one agent name at the same time. Its tick writes `agent-expire` at the end.
- Guard: it admits each connection on its own. After `expires` it denies new connections with `expired` (strict ms, no skew). It does not cut open streams.
- CLI: `orblx agent connect` and `orblx agent http` read the grant files one time at start.
  In loop mode (`--every-ms`) the loop stops at the first deny.
  A new grant that the agent writes into the same directory has no effect until a restart.
- Fetch writes `agent.crt.pem`, `agent.key.pem`, the ticket file, and `grant.json` (last). Each file is an atomic rename. The set of 4 files is not atomic.
- Python SDK: each call starts a new `orblx` process, so each call reads the current files. The SDK has no gap.

Result: at each grant end, a long-running CLI agent gets `expired` and stops. The operator must start it again.

## Smallest fix (client only)

1. `GrantFiles::load` refuses a mixed set of files:
   - It reads `grant.json` before and after the other files. The two reads must be equal.
   - The hash of the ticket file must equal `grant.ticket_hash`.
   - The public key of `agent.key.pem` must equal the public key in `agent.crt.pem`.
2. New `GrantDir` with `refresh()`. Before each attempt, the loop reads the directory again. It takes the new grant only when:
   - the set is complete (rule 1),
   - the scope is the same (agent, node, address, service, port, path prefix),
   - the end time is later than the end time of the grant in use,
   - the node deny list does not revoke it (see rule 4).
   In other cases it keeps the grant in use and prints `loop grant_kept reason incomplete|scope|older|revoked|ticket|deny-unknown`.
3. The `connect` and `http` loops print `loop grant_switch from A to B at_ms T expires_ms E`, `loop ok_attempts N`, `loop max_ok_gap_ms N`, and `loop grant_switches N`.
   The exit codes do not change: 0 after a deny, 3 when no deny occurs before `--max-wait`.
4. Deny check (PO gate). Before a switch, `NodeDeny` reads two files in the node state directory (`--state`, default `/var/lib/orblx`):
   - `ticket-verifier.pem`: the ticket signature and time window of the new grant must be good (else `ticket`).
   - `deny.json`: `orblx up` keeps this file current with the existing `deny-wait` call. When the list holds the ticket nonce or the agent URI of the new grant, the agent does not take it (`revoked`).
   - When a file is missing or not valid, the agent keeps the current grant (`deny-unknown`) and checks again before the next attempt. The check fails closed.
   The check does no network call and uses only existing files and functions (`verify_ticket`, `DenySet`).

A revoked next grant or a next grant with another scope is never taken.
In that case the loop stops at the end of the current grant with deny `expired`.
A revoke before the fetch is refused by the coordinator (`The grant is revoked.`), so no files arrive.

Caveat: when the owner revokes a grant after the agent switched to it, or before `deny.json` on the agent node has the revoke, the guard denies it with `revoked`. This is the W22-2 revoke path and it does not change.

The grant policy does not change. Each grant still needs a human approval.
An agent without an owner approval before the end still stops at the end. This is by design.
The approved release note stays correct: "an agent grant is single-use; after it expires, the agent requests a new grant".
With this fix, the agent (or its operator) requests and fetches the next grant before the end, into the same directory, and the running loop uses it.

## Tests

- `orblx-agent/tests/guard.rs`: `a_grant_dir_takes_only_a_complete_newer_grant_with_the_same_scope`.
  It covers Same, Switched, incomplete (ticket swap, key swap), scope, and older.
- `orblx` bin: `grant_end_tests::a_connect_loop_crosses_a_grant_end_with_a_new_grant`.
  A real guard, grant a1 with TTL 3 s, then grant a2 with TTL 10 s in the same directory after 1 s.
  - On main: FAIL. `loop deny_reason expired` at the a1 end (`left: Ok(0)`, `right: Ok(3)`).
  - With the fix: PASS. 1 switch a1 to a2, 47 attempts, 47 ok, `max_ok_gap_ms` 170, no deny, chain verifies.
  - No timing assert is below 1000 ms.
- `orblx-agent/tests/guard.rs`: `a_grant_dir_never_takes_a_revoked_next_grant` (revoked, deny-unknown, ticket from another signer, then a good grant).
- `orblx` bin: `grant_end_tests::a_connect_loop_never_takes_a_revoked_or_other_scope_next_grant`.
  A real guard that reads the same deny list. Grant a1 (TTL 3 s), then a grant for service `db`, then a revoked grant a2.
  - Without the deny check (the 922bdd8 behavior): FAIL. The loop switches to a2 and the guard denies with `revoked`.
  - With the check: PASS. `grant_kept reason scope`, `grant_kept reason revoked`, 0 switches, `deny_reason expired` at the a1 end. The guard chain has no use of the other grants.

## Docker proof plan

Script: `scripts/proof/agent-grant-renew.sh` (compose `compose.agent.yml`, project `orblx-w25-30-renew`).
The PO approved a run before #117, because the agent path does not use the node renewal code.

1. Define `as_root` and `dc`, take the FIFO lock (`proof_lock_take`) for this run only, then `proof_compose_clean`.
2. Build the image. Enroll owner, a, and b with coordinator tokens through the normal enroll path. The owner approves a and b. No lab tickets.
3. Start a guard on b (`:8080`, target `127.0.0.1:8081`).
4. Grant TTL 60 s, 6 grant ends. For each end: request, owner approve, fetch into the same directory 20 s before the end.
5. One `orblx agent connect --every-ms 50 --trace-file FILE` loop on a for the whole run. No restart.
   The trace file gets one line for each attempt: `start_ms` (before the directory read), `send_ms` (before the connect), and `done_ms` (after the reply). The trace is for the logs only. It holds no key or ticket.
6. Pass criteria:
   - Container `StartedAt` and `RestartCount` do not change.
   - The loop exits 3 (no deny), attempts equal ok attempts, 0 failed, 0 client denies, 0 guard denies.
   - Grant switches are 6 or more.
   - Gap gate (PO method, after run 3): for each of the 6 switches, the gap is the time from the last guard use of the old grant to the first guard use of the new grant. Each gap is 200 ms or less.
   - Each grant end has guard uses in the 5 s after it (no lost access). The largest gap in the 2 s around each end is printed for information only.
   - The script prints a gap split for information only (no gate): `request_ms` (send to reply), `to_guard_ms`, `from_guard_ms`, `refresh_ms`, `sleep_ms`, and one `big_gap` line for each gap above 200 ms.
   - Guard chain verify and coordinator audit verify are ok. `agent-approve` records are 7 or more.
   - Secret grep is 0.
7. Phase 2 (gate), in the same run: a new loop on a gate grant (TTL 60 s).
   - A newer grant with another scope (port 8082) is fetched into the same directory.
   - A grant that the owner revokes before the fetch: the fetch must fail.
   - A grant that the owner revokes after the fetch: the set goes into the directory after `deny.json` on a has the revoke version.
   - Pass: the loop exits 0 with `deny_reason expired` at or after the gate grant end, 0 switches, `grant_kept` scope and revoked lines, no guard use of the other grants, no guard `revoked` deny.
8. The script prints `gate_ok`, `summary ...`, and `proof_ok`. The lock is released at exit.

## Run 3 (failed, 2026-10-31 14:02 to 14:07 KST)

- Run 3 used the old gap rule: the largest gap between two guard uses in the 2 s around each end.
- End 1: 161 ms. End 2: 213 ms. The script stopped at end 2 (exit 1). Ends 3 to 6 and phase 2 did not run.
- The loop switched to the next grant 19 s before end 2. The 213 ms gap was 641 ms after the end, between two uses of the same new grant.
- Guard use gaps in run 3: 1827 gaps, p50 149 ms, p99 201 ms, max 238 ms, 21 gaps above 200 ms. The client `loop max_ok_gap_ms` was 287 ms (client send times, not guard times).
- The run 3 log has no per-attempt client times. Thus the trace above was added before the next run.
- The PO approved the switch gap method. The 200 ms limit did not change.
