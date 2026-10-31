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
   - the end time is later than the end time of the grant in use.
   In other cases it keeps the grant in use and prints `loop grant_kept reason incomplete|scope|older`.
3. The `connect` and `http` loops print `loop grant_switch from A to B at_ms T expires_ms E`, `loop ok_attempts N`, `loop max_ok_gap_ms N`, and `loop grant_switches N`.
   The exit codes do not change: 0 after a deny, 3 when no deny occurs before `--max-wait`.

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

## Docker proof plan

Script: `scripts/proof/agent-grant-renew.sh` (compose `compose.agent.yml`, project `orblx-w25-30-renew`).
Run it only after #117 is on `main`, because the node sessions must stay up for more than 5 minutes.

1. Define `as_root` and `dc`, take the FIFO lock (`proof_lock_take`) for this run only, then `proof_compose_clean`.
2. Build the image. Enroll owner, a, and b with coordinator tokens through the normal enroll path. The owner approves a and b. No lab tickets.
3. Start a guard on b (`:8080`, target `127.0.0.1:8081`).
4. Grant TTL 60 s, 6 grant ends. For each end: request, owner approve, fetch into the same directory 20 s before the end.
5. One `orblx agent connect --every-ms 50` loop on a for the whole run. No restart.
6. Pass criteria:
   - Container `StartedAt` and `RestartCount` do not change.
   - The loop exits 3 (no deny), attempts equal ok attempts, 0 failed, 0 client denies, 0 guard denies.
   - Grant switches are 6 or more.
   - The gap between guard uses around each end is 200 ms or less, and uses occur after each end.
   - Guard chain verify and coordinator audit verify are ok. `agent-approve` records are 7 or more.
   - Secret grep is 0.
7. The script prints `summary ...` and `proof_ok`. The lock is released at exit.
