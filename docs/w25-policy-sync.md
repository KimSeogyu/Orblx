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

The proof results follow after the proof run.

## 4. Limits

- A changed endpoint list of a peer that the node already dials does not restart that dial task.
  The dial task uses the endpoints from the netmap at the time it started.
- The coordinator reply is the full view of the node. The view is small (one netmap and one grant set).
