# W20-1 NAT realism

This document shows the W20-1 NAT work and its proof.

Labels:

- **REAL**: the Linux host, the Docker engine, and `cargo test`.
- **[C]**: a container. All routers, nodes, the coordinator, and the relay are [C].

The proof ran at commit `b72a2f4b` (PR #47).
Later commits on the branch change only this document.

## What changed

### Port-restricted cone router (prc)

`scripts/proof/nat-router.sh` has a new mode `prc`.

- Mapping: endpoint-independent. `SNAT --to-source WAN_IP` keeps the source port for all destinations.
- No port forward and no DNAT.
- Filter: port-restricted. The router forwards inbound UDP only when the conntrack 5-tuple matches a flow from the LAN.
  `FORWARD -i WAN -o LAN -m conntrack ! --ctstate ESTABLISHED,RELATED -j DROP`.
- All modes drop new UDP to the router WAN address in INPUT.
  Without this rule, the router sends ICMP port unreachable, and that makes a conntrack entry.
  That entry can force SNAT to change the source port of a later flow.
- The symmetric mode now uses `MASQUERADE --random-fully --to-ports 1024-65535`.
  Without the range, Linux picks a port below 512 for a source port below 1024.

The symmetric routers, the LAN isolation rules, and the no-shortcut and no-hairpin checks did not change.

### NAT mapping kind

- `orblx nat run --stun-alt ADDR` asks a second STUN port from the same socket.
- Same IP and same port: `endpoint-independent`. Same IP and two ports: `endpoint-dependent`.
- The node publishes the two reflexive endpoints. The coordinator signs each one.
- The peer finds the mapping kind from the two signed endpoints.
- Without `--stun-alt`, the kind is `unknown`, and the node uses the W19 plain punch.

### Punch plan

| Local | Peer | Plan | Result in the lab |
| --- | --- | --- | --- |
| endpoint-independent | endpoint-independent | plain | direct |
| endpoint-independent | endpoint-dependent | port-spray | direct (birthday) |
| endpoint-dependent | endpoint-independent | birthday-sockets | direct (birthday) |
| endpoint-dependent | endpoint-dependent | relay-only | relay |

Birthday bounds (`crates/orblx-edge/src/birthday.rs`):

- The hard side opens 256 sockets and sends one punch on each socket every 2 seconds.
- The easy side sends to 32 predicted ports, then to random ports in 1024-65535.
- The rate limit is 200 probes per second with a burst of 20, on each side.
- The limit is 2048 spray probes and 15 seconds. Then the node stays on the relay.
- A node accepts a punch only from the signed peer IP with the session token.

### Make-before-break switching

- Each probe has a flag that tells the peer "I receive on this path".
- A path is good only when probes went in the two directions in the last 300 ms.
- The node seals each packet one time. It can send the same frame on the two paths.
  The replay window of the peer drops the second copy.
- After relay to direct, the node sends on the two paths for 600 ms.
- When the node leaves the direct path, it sends the direct frames of the last 500 ms again on the relay.
- `orblx status` shows the path that carries traffic (`direct` or `relay`).

### Peer SVID expiry

- The hello is: X25519 public key (32) || Ed25519 signature (64) || leaf SVID DER.
- The signature covers `"orblx-nat-hello-v1\n" || session || X25519 public key` with the SVID key.
- The peer checks the leaf against the trust bundle, checks the SPIFFE ID against the netmap, and checks the signature.
  Then `orblx status` shows the real `svid_expiry` on the peer line.
- A hello with a wrong SVID, a leaf from another CA, or a changed key is rejected (unit tests in `nat_path.rs`).

## Commands

```sh
export PATH=$HOME/.cargo/bin:$PATH
E="env PATH=$PATH RUSTUP_HOME=$HOME/.rustup CARGO_HOME=$HOME/.cargo"
sudo -n $E ./scripts/proof/nat-realism.sh   # new cases
sudo -n $E ./scripts/proof/nat.sh           # W19 regression
sudo -n chown -R "$(id -un)" target
```

Logs:

- `/workspace/orblx-w18-proof/pr47-b72a2f4b-nat-realism.log`
- `/workspace/orblx-w18-proof/pr47-b72a2f4b-nat.log`

The script fails when a switch loses more than 1 of 50 pings, when a gap between ping replies is more than 1 second, or when `svid_expiry` is not a number on the self line or the peer line.

## Results

### [C] Router checks

```text
router-a dnat_rules 0
router-b dnat_rules 0
router-c dnat_rules 0
router-d dnat_rules 0
node-a: mapping inner:40000 to 172.29.20.10:5001 seen_as 172.29.20.11:40000
node-a: mapping inner:40000 to 172.29.20.20:5001 seen_as 172.29.20.11:40000
node-a mapping endpoint_independent port 40000
node-c: mapping inner:40000 to 172.29.20.10:5001 seen_as 172.29.20.13:27613
node-c: mapping inner:40000 to 172.29.20.20:5001 seen_as 172.29.20.13:50514
node-c mapping symmetric ports 27613 50514
node-a: filter received same_endpoint@172.29.20.10:5011
node-a filter port_restricted true
node-b: filter received same_endpoint@172.29.20.10:5011
node-b filter port_restricted true
lan_shortcut false
```

The filter probe sends one datagram to `172.29.20.10:5011`.
The server answers from `172.29.20.10:5012` (same IP, other port), from `172.29.20.20` (third host), and from `172.29.20.10:5011`.
Only the answer from `172.29.20.10:5011` arrives.

### [C] Per case

| Case | Path (both sides) | Steady loss | Evidence |
| --- | --- | --- | --- |
| prc to prc (node-a, node-b) | direct direct | 0/50 | `The hole punch reached 172.29.20.12:443.` |
| prc to symmetric (node-a, node-c) | direct direct | 0/50 | `The port spray reached 172.29.20.13:2099 after 84 probes.` and `The birthday punch reached 172.29.20.11:443 with socket 236 after 256 probes.` |
| symmetric to symmetric (node-c, node-d) | relay relay | 0/50 | `The punch plan is relay-only.` No hole punch line. |

### [C] Switches (each switch is a separate run of 50 pings at 200 ms)

| Switch | Detect | Lost | Max gap |
| --- | --- | --- | --- |
| prc to prc, direct to relay (UDP blocked) | 506 ms | 0/50 | 300 ms |
| prc to prc, relay to direct (UDP restored) | 625 ms | 0/50 | 251 ms |
| prc to symmetric, direct to relay | 393 ms | 0/50 | 300 ms |
| prc to symmetric, relay to direct | 499 ms | 0/50 | 266 ms |

```text
switch prc_prc direct_to_relay detect_ms 506 lost 0/50 max_gap_ms 300
switch prc_prc relay_to_direct detect_ms 625 lost 0/50 max_gap_ms 251
switch prc_sym direct_to_relay detect_ms 393 lost 0/50 max_gap_ms 300
switch prc_sym relay_to_direct detect_ms 499 lost 0/50 max_gap_ms 266
orblx-natr-a: The node sent 2 recent frames again on the relay.
```

"Detect" is the time from the iptables change to the new path in `orblx status`.
The W19 log (PR #45) lost 3 of 50 pings at a switch, with gaps of 556 ms and 250 ms.

### [C] svid_expiry

```text
state up
name node-a
overlay_ip 100.64.0.1
svid spiffe://orblx.local/node/node-a
svid_expiry 1793319815
peer node-b overlay_ip 100.64.0.2 path direct svid spiffe://orblx.local/node/node-b svid_expiry 1793319816
prc_prc node-a svid_expiry self 1793319815 peer 1793319816
prc_sym node-a svid_expiry self 1793319815 peer 1793319816
sym_sym node-c svid_expiry self 1793319816 peer 1793319817
```

The peer line now has a number in all cases, on the direct path and on the relay path.

### [C] W19 regression (`nat.sh`)

```text
case1 path direct
case2 path direct
case3 path relay
case3 return direct
case3 switch1 from direct to relay detect_ms 1405 max_gap_ms 250
case3 switch2 from relay to direct detect_ms 787 max_gap_ms 200
case4 rejected true
case5 path relay
proof_ok
```

## Lab assumptions and limits

- The NAT routers are Linux iptables and conntrack in containers. Real home routers and carrier-grade NAT can use other port allocation and other timeouts.
- The prc filter comes from the conntrack 5-tuple. A router that answers new UDP with ICMP would change the mapping. The lab routers drop that UDP.
- The symmetric routers use `--random-fully` over 1024-65535. A NAT with sequential ports makes the prediction better. A NAT with a small port pool or a per-host port limit can make the birthday attempt fail.
- The birthday attempt is probabilistic. With 256 sockets and up to 2048 probes over 64512 ports, the expected number of hits is about 8, so the chance of no hit is about 0.03 percent. When it fails, the node uses the relay. The node makes one birthday attempt for each process start.
- Two symmetric NATs always use the relay. The code does not try a punch in that case.
- The hello carries the SVID at the start of the session. The NAT runtime does not send a new hello after an SVID renewal, so the peer line shows the expiry of the SVID from the hello.
- The overlay RTT in the lab is about 50 ms on a direct path. It was 100 ms in W19. The bridge RTT is below 1 ms, so the delay is in the node. A poll timer in the node is a possible cause. This change did not measure or fix it.
- One host runs all containers. The bridge has no packet loss and no delay. The switch numbers do not include real WAN loss.
