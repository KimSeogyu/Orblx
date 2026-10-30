# W24-A port ACL in the datapath

The policy can allow or deny traffic by protocol and port for each principal.
The receiving node enforces the policy in the datapath.

Marks: **[C]** = shown in the container proof on one Linux host. **REAL** = shown on real hosts.
This change has no REAL result. All results below are [C].

## Policy

The `acls` list of the HuJSON policy (W18-5) gives the allowed flows.
Each rule has `src`, `proto` (`tcp`, `udp`, or `icmp`), and `dst` (`principal:ports`).
An ICMP destination must use the port `*`.

| Policy | Datapath |
|---|---|
| The policy has an `acls` list (also an empty list). | Default deny. The receiving node drops each packet to its overlay address that no rule allows. |
| The policy has no `acls` key. | Old behavior. The node does not check the protocol or the port. |

The coordinator compiles the rules into the signed receiver grants of each node (W18-5).
The grants now have the field `filter`. The field is true when the policy has an `acls` list.
The node reads `grants.signed.json` again each second, so a policy change gets to the filter without a restart.

## Datapath rules

- The filter checks each packet from a peer that has the overlay address of this node as its destination.
  The check uses the SPIFFE ID of the peer session (the mTLS identity), the IP protocol, and the destination port.
- A reply to a flow that this node started passes. The filter keeps a flow table (idle time 180 s, at most 65 536 flows).
- An ICMP error passes only when the packet in the error is from a flow that this node started.
- A fragment after the first fragment has no port. The filter drops it when the filter is on.
- A packet to another address (a subnet route or an exit route) keeps the old behavior.
- The filter is in both datapaths: `orblx up` (`crates/orblx-datapath/src/node.rs`) and `orblx nat run` (`crates/orblx-edge/src/nat_run.rs`).

## Deny audit

The node writes the drops to the config audit chain `packet-audit.jsonl` in the node state directory, action `packet-deny`.
The chain uses the hash chain of `orblx-audit`. It does not add a new crypto design.

- At most one record for each source, protocol, and port in 10 s.
- At most 5 records in one second.
- A separate thread writes the records. The queue holds 64 records. When the queue is full, the datapath does not wait.
- The `detail` of each record has `unwritten_before N`: the number of drops that the node did not write since the last record.
  Thus the sum of the records and the `unwritten_before` values accounts for the drops.

## Revoke to datapath drop

`orblx admin revoke-all` (W24-D) adds the SVID of the principal to the coordinator deny list.

| Step | Before | Now |
|---|---|---|
| `orblx up` fetches the deny list | each 500 ms after the end of the fetch | each 500 ms from the start of the fetch |
| The datapath reads `deny.json` | each 10 s | each 50 ms. The node parses the file only when its bytes change. |
| Live sessions of the revoked peer | stay open | The node ends them when the deny list changes. |

The node lock allow list is still set again each 10 s (200 deny reads).

## Proof

`scripts/proof/datapath-acl.sh` ([C], 3 nodes a, b, c and a coordinator, Docker on one host).
The policy is `scripts/proof/datapath-acl.hujson`: a may reach b on TCP 8080, UDP 9000 and 9500, and ICMP.
c may reach b on TCP 8080 only. No rule lets b open a flow to a or c.

PROOF_RESULTS

## Changes to other proofs

A policy with an `acls` list now turns on the filter.
Thus the proof policies `admin.hujson`, `oidc.hujson`, and `w18-names.hujson` get the rules that their proofs need.
`file-send.sh`, `revoke-all.sh`, and `w18-names.sh` get small changes for the same reason.
`nat-realism.sh` can set a policy with `ORBLX_NATR_POLICY`. The W23-4 gates in this change run with `scripts/proof/nat-realism-acl.hujson`, so the filter is on in the measured path.

## Limits

- `orblx nat run` (the NAT lab datapath) has the packet filter, but it does not read `deny.json`.
  The revoke time above is for `orblx up`.
- IPv4 only. The overlay is IPv4.
- The filter does not track TCP state. A flow that this node started stays open for replies for 180 s after its last packet.
- When the flow table is full (65 536 flows), a new outbound flow is not recorded, and its replies are dropped.
- The proof does not measure the filter cost at high flow counts.
- The proof runs on one host with other workers. The load was not measured during each run.
