# Changelog

## 0.1.0-rc.3

This section lists the pull requests on main after tag `v0.1.0-rc.2`.
The version on main is `0.1.0-rc.3-dev`.
This file does not cut a tag.

### Changes

- #143 (`d3f4ef7`) Proofs with a millisecond limit build the release binary.
- #142 (`b82c949`) Main uses version `0.1.0-rc.3-dev`. CI checks that main is not a release version.
- #139 (`e5310c9`) Each proof checks free disk space before it takes the lock.
- #107 (`067f95d`) The coord-enroll proof brings a node up with a real TUN device and removes its containers.
- #137 (`995ea4d`) The SSH server reads the current node key for each connection.
- #109 (`c546262`) Each node uses one QUIC connection for the policy wait. The coordinator signs a netmap only when the netmap changes.
- #132 (`393f7df`) The proof lock counts containers with sudo. A run with unknown samples fails.
- #118 (`8806405`) The node writes `node.json` only after the TUN device opens.
- #93 (`1459cc2`) HA subnet routers keep a client on one router until that router fails.
- #91 (`130af38`) The node fixes the packet gap at SVID renewal.
- #126 (`819c33a`) The API token proof uses names that do not look like a secret.
- #115 (`1b5ba80`) The join-time proof runs 20 late peer joins, from enroll and listener start to the first packet.
- #120 (`5a55a0d`) The startup-cost test binds port 0 and prints the node error.
- #122 (`9562b16`) The row 54 proof runs the systemd unit and `orblx down`.
- #102 (`538b154`) A new OIDC user needs approval.
- #111 (`d9704cf`) The proof lock is fair for ticket time, old checkouts, and plain flock wrappers.
- #114 (`690558d`) Each compose proof starts from a clean state.
- #108 (`f3bee5b`) The nat-realism steady stall limit is 200 ms. A stall above 100 ms is `steady_warn`.
- #113 (`5de3821`) The startup-cost test measures the time from enroll to listener start.
- #112 (`6815863`) The late peer gate starts at the listener start that the node logs.
- #110 (`015f930`) The sweep checks for 30 GB of free disk. The rc.3 release checklist is in the sweep doc.
- #95 (`37fdba6`) The proof sweep runs the shipped rows in one command and prints a summary for each row.
- #103 (`87ffc33`) A node dials a late peer again soon after that peer starts to listen.
- #105 (`4bcc3b0`) SIEM streaming leak checks fail closed. Gate 1 uses one clock.
- #104 (`92c698e`) The sym relay throughput check uses 30 s samples. `serial-rtt.sh` prints the current row.
- #101 (`a5a3801`) The proof log keeps the full step output. The policy-sync leak scan is fixed.
- #100 (`ce1dcb7`) The policy sync doc records the branch run and the main proof results.
- #96 (`184d299`) The config audit chain can stream to SIEM sinks.
- #99 (`9d53d3c`) The steady ping check has a max RTT gate. The proof lock is FIFO and records wait time.
- #92 (`c32d46f`) The node applies coordinator policy and new peers with no restart.
- #98 (`8996f4e`) The w18-names proof takes the lock outside the iptables block.
- #97 (`aa219cc`) Proof scripts read pipes to the end. Proof scripts take the lock. Proof scripts can run as root.
- #90 (`cd6c8ee`) The share scope follows the port ACL.
- #94 (`5dd9976`) The nat-realism proof does not end a pipe reader early.
- #89 (`4ac56c1`) The exit node TCP Relay keeps the Relay slot of a quiet bridge.
- #78 (`d0ddf7f`) RTT and throughput proofs use one box-wide lock.
- #87 (`9867339`) The repository has an official container image.
- #88 (`dcd4643`) The perf watch throughput floor is 200 Mbit/s.
- #84 (`372138c`) Config audit webhooks are signed.
- #86 (`33cb923`) Revoke closes open SSH sessions. The node can undo a revoke. The node waits for deny changes.
- #85 (`06e4a0b`) `orblx policy diff` and `orblx policy apply` support policy GitOps.
- #80 (`d153c70`) The datapath enforces the port ACL.
- #82 (`38a5730`) The serve doc records that WebSocket upgrades pass through.
- #83 (`1dbbec6`) The perf watch CI floor is 300 Mbit/s for each path.
- #77 (`38b1638`) One node can be shared with a guest user.
- #81 (`130fe35`) Serve passes a WebSocket upgrade through.
- #79 (`f19d5a3`) A scoped API token cannot escalate past its scope.
- #75 (`76c90ac`) The perf watch CI gate uses the ping median and the spike count.
- #76 (`5b5bb3e`) The API token proof has no SIGPIPE race.
- #73 (`7c5b7fb`) Split DNS sends a policy domain through a subnet router.
- #74 (`be8cbec`) The coordinator admin API accepts scoped API tokens.
- #72 (`c3c536b`) CI runs a perf watch for the release nat-realism RTT and throughput gates.
- #71 (`d341f19`) Serve rejects a forged peer address and limits an HTTP/1.1 body.
- #70 (`8972192`) One command revokes all access of one principal.
- #69 (`f1811d8`) The gateway signs all request headers. The nonce file is separate.
- #68 (`3464fdf`) The rc.2 release doc records the `v0.1.0-rc.2` release and its proof.
