# W25-6 Automatic policy and peer sync

This change makes `orblx up --coord` apply each coordinator change with no restart and no manual fetch.
A change can be a policy file change (ACL, split DNS, routes), a revoke, or a new peer.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test` on that host.
- **[C]**: a container. The coordinator, the subnet router, node `a`, node `b`, the 50 load identities, and the Docker networks are [C].

The change adds no new crypto design. The coordinator signs the netmap and the grants with the
existing netmap key. The node verifies each reply with the pinned netmap key, as at enroll.

## 1. Coordinator: `policy-wait`

- New operation `policy-wait`. It is a long poll with an ETag, the same model as `deny-wait` (W25-2, #86).
- The ETag is the SHA-256 digest of the signed netmap, the signed grants, the endpoints,
  the approved and advertised routes, the exit approval, and the deny list ETag of the caller.
- When the ETag of the caller is not the current ETag, the coordinator replies at once.
  Otherwise it holds the request for 20 s or until the ETag changes.
- The coordinator checks for a change each 100 ms (`STAMP_TICK`). The check reads only the file
  metadata of the state files and the policy file. Thus a held request costs almost no CPU.
- The reply holds the signed netmap, the signed grants, the endpoints, the deny list, and the new ETag.

## 2. Node: `orblx up --coord`

- The policy thread asks `policy-wait` first. If the coordinator does not know the operation,
  the thread uses `deny-wait` and asks `policy-wait` again after 30 s.
- When the ETag changes, the node writes `deny.json` first. Then it writes the netmap, the grants,
  and the endpoints, each with a rename. It prints `The node applied a new policy from the coordinator.`
- A node that runs with its own `--netmap` file keeps that file. Only the deny list changes for that node.
- The datapath reads the files and applies them with no restart:
  - `deny.json`: each 100 ms (W25-1). A revoke closes the sessions of the denied peer.
  - Grants: each 1 s.
  - Split DNS: each 1 s. The DNS proxy uses the new table at once. The node then refreshes the
    system resolver in a background task. Before this change, the node ran `resolvectl` first,
    and the new answers waited for that command (up to 5 s for each call).
  - Netmap peers (new): each 250 ms. The node replaces the router table, installs the kernel routes
    of the new prefixes, adds the new peers to the status, and starts a link task for each new peer.
    A peer that leaves the netmap loses its routes. The deny list and the node lock stop its sessions.
- `orblx coord netmap --watch` uses the same client. It prints `policy_update UNIX_MS` for each change.

## 3. Results

Proof: `scripts/proof/policy-sync.sh`. The script takes the box proof lock (`proof-lock.sh`, W25-5).
The build is release. Branch run: commit `d8c7d3ae`, 2026-10-31 01:44 to 01:48 KST,
log `w256-br2-d8c7d3ae-policy-sync-run3.log` in the proof log directory. Result: `proof_ok`.
The lock sampler saw other orblx containers in all 86 samples (max 7, load1 max 2.84).

| Gate | Label | Limit | Measured |
|---|---|---|---|
| 1. Policy change to the new DNS answer on node `a` (remove `corp.lan`) | [C] | 2000 ms | 272 ms |
| 1. Policy change to the new DNS answer on node `a` (add `corp.lan` again) | [C] | 2000 ms | 234 ms |
| 1. Node `a` applied a new policy (stage, remove / add) | [C] | - | +120 ms / +202 ms |
| 1. The DNS table follows the new netmap (stage, remove / add) | [C] | - | +265 ms / +233 ms |
| 4. Late peer `b`: first ICMP reply on `a`, from `docker compose up b` | [C] | 2000 ms | 1066 ms |
| 4. Late peer `b`: first ICMP reply on `a`, from the container start | [C] | - | 855 ms |
| 4. Late peer `b`: first ICMP reply on `a`, from the start of the enroll | [C] | - | 1731 ms |
| 4. Restarts of `a` and the router | [C] | 0 | 0 |
| 3. Coordinator CPU, 50 `policy-wait` clients, no change, 60.3 s | [C] | < 5% of one core | 1.38% |
| 3. Coordinator CPU, 50 clients, one change each 10 s, 60.4 s | [C] | < 5% of one core | 4.35% |
| 3. Policy updates that the 50 clients got in the change window | [C] | >= 300 | 300 |
| 3. CPU of one client (no change / change) | [C] | - | 0.037% / 0.070% |
| 2. Last datagram from `a` at the router after `revoke_done_ms` | [C] | 1000 ms | 230 ms |
| Logs with `PRIVATE KEY` | [C] | 0 | 0 |

No node restarted, and the script did not run a manual netmap fetch on a node.
The late peer gate is a Docker measurement. The unit test `a_peer_that_enrolls_later` is extra.

Other checks on the branch:

- REAL: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  and `cargo test --workspace` pass (rustc 1.99.1).
- [C] W23-4 NAT realism (`nat-realism.sh`, release, `nat-realism-acl.hujson`) on `431e1fef`:
  `proof_ok` (log `w256-br2-431e1fef-natr-run1.log`). The commits after `431e1fef` change only
  the policy sync proof files.

### Failed runs and causes

- Run 1 (`431e1fef`): gate 3 stopped at the enroll of the load identities.
  Cause: the coordinator needs one endpoint at enroll, and the script gave none.
  Fix: the load container has the fixed address 172.30.126.9, and each identity gives its own port.
- Run 2 (`7d1bebfa`, debug build): gate 3 failed. Coordinator CPU 99.60% with no change.
  Cause: the debug build. Each client asks again after the 20 s hold, with a new QUIC and TLS
  handshake, and the coordinator signs the netmap for each reply. In a debug build these steps are slow.
  A host check with 10 debug clients showed a burst of 127 CPU ticks (1.27 s) for each 20 s cycle.
  The same host check with 50 release clients showed 82 ticks in 60 s (1.37%).
  Fix: the proof uses the release build by default (`ORBLX_SYNC_PROFILE`). The gate limit did not change.

## 4. Limits

- A changed endpoint list of a peer that the node already dials does not restart that dial task.
  The dial task uses the endpoints from the netmap at the time it started.
- The coordinator reply is the full view of the node. The view is small (one netmap and one grant set).
