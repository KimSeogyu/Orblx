# W12 local TUN round-trip bench

The product name is Orblx.
The bench measures one local TUN round trip on a Linux host.
The bench uses the in-tree TUN path in `orblx-datapath`.
The bench does not use WireGuard.
The bench does not use Headscale.
The bench does not use DERP.

Datapath owns the script.
Datapath owns the measured rate.
The command is `./scripts/tun-bench.sh`.
That command is the same file as `scripts/tun-bench.sh`.

## Record

| Field | Value |
| --- | --- |
| Command | `./scripts/tun-bench.sh` |
| Method | Linux TUN send and receive. Each packet is one ADR-0002 DATA frame. Mbps from wall-clock bytes. |
| Gate | at least 100 Mbps |
| Measured Mbps | 8091.299206 |
| Result | pass |
| Script in this tree | `scripts/tun-bench.sh` |
| Supporting PR | https://github.com/KimSeogyu/Orblx/pull/23 |
| Datapath agent | `bc-551a2bb3` |

The measured rate is 8091.299206 Mbps.
The result is pass.
The minimum rate is 100 Mbps.
A host that is not Linux exits 0 and prints the K3 note.
A host with no TUN device exits 0 and prints the K3 note.
That exit is not a pass of the 100 Mbps gate.

## Result

This host ran `scripts/tun-bench.sh` once.
The script printed these lines:

```
host_uname=Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct 27 12:38:43 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
host_id=uid=0(root) gid=0(root) groups=0(root)
host_euid=0
host_cap_eff=000001ffffffffff
host_tun=crw-rw-rw- /dev/net/tun
host_ip_path=/usr/sbin/ip
host_ip=ip utility, iproute2-6.1.0, libbpf 1.3.0
tun_bench_command=scripts/tun-bench.sh
K3 tun_ready true
tun_bench_iface=orblxbn
tun_bench_mbps=8091.299206
tun_bench_result=pass
tun_bench_bytes=142800000
tun_bench_elapsed_s=0.141188698
tun_bench_round_trips=50000
tun_bench_payload_len=1400
tun_bench_packet_len=1428
tun_bench_window=64
tun_bench_min_mbps=100
tun_bench_formula=bits = bytes * 8; mbps = bits / elapsed_s / 1e6
```

## Formula

`bytes` is the number of IPv4 bytes that the bench reads from the TUN device plus the number of IPv4 bytes that the bench writes to the TUN device.
Each round trip adds one read and one write.
The read length is 1428 bytes.
The write length is 1428 bytes.
50000 round trips move 142800000 bytes.

The clock starts immediately before the first UDP send.
The clock stops immediately after the last UDP receive.
`elapsed_s` is that duration in seconds.

The bench uses this formula:

```
bits = bytes * 8
mbps = bits / elapsed_s / 1e6
```

`1e6` is the decimal megabit.
The bench does not use 1024 * 1024.

The bench prints `mbps` to 6 decimal places.
The bench prints `elapsed_s` to 9 decimal places.
Pass means `mbps >= 100`.

## Method

Run this command from the repository root:

```bash
./scripts/tun-bench.sh
```

The script builds `target/release/tun-bench`.
The script runs that binary.
When the current user has no `CAP_NET_ADMIN`, the script runs the binary with `sudo`.

The binary opens one TUN device with `open_linux_device`.
`open_tun` uses the same open path.
The device name is `orblxbn`.
The device address is `10.88.12.1/24`.
The bench binds one UDP socket to `10.88.12.1:47821`.
The bench sends 1400-byte UDP payloads to `10.88.12.2:47821`.
The kernel writes each IPv4 packet to the TUN device.
The bench reads that packet.
The bench encodes the packet as one ADR-0002 DATA frame.
The bench decodes that frame.
The bench swaps the IPv4 addresses and the UDP ports.
The bench writes the IPv4 packet back to the TUN device.
The UDP socket receives the payload.
64 payloads can be in flight.
The bench checks every reply sequence and every reply payload.

The DATA frame bytes stay in the process.
The byte count does not add the DATA frame header again.
The bench sets `rp_filter` to 0 for the run.
The bench restores the previous `rp_filter` value after the run.

## Host

`uname -a` printed this line:

```
Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct 27 12:38:43 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

The host is Linux.
`/dev/net/tun` is present.
The mode is `crw-rw-rw-`.
The bench process is root.
The effective user id is 0.
`CapEff` is `000001ffffffffff`.
Bit 12 of `CapEff` is `CAP_NET_ADMIN`.
The `ip` command is `/usr/sbin/ip`.
The `ip` version line is `ip utility, iproute2-6.1.0, libbpf 1.3.0`.

## Constants

The constants are in `crates/orblx-datapath/src/tun_bench.rs`.

| Name | Value |
| --- | --- |
| `BENCH_PAYLOAD_LEN` | 1400 bytes |
| `BENCH_PACKET_LEN` | 1428 bytes |
| `BENCH_ROUND_TRIPS` | 50000 |
| `BENCH_WINDOW` | 64 |
| `BENCH_LOCAL` | 10.88.12.1 |
| `BENCH_PEER` | 10.88.12.2 |
| `BENCH_NETMASK` | 255.255.255.0 |
| `BENCH_UDP_PORT` | 47821 |
| `BENCH_IFACE` | orblxbn |
| `BENCH_SESSION_ID` | 12 |
| `BENCH_TICKET_HASH` | 16 zero bytes |
| `BENCH_MIN_MBPS` | 100 |
| `BENCH_DEADLINE` | 60 seconds |

The bench does not check a capability ticket.
The DATA frame still carries `BENCH_TICKET_HASH`.

## Skip behavior

The script prints `K3 tun_ready false` and exits 0 when any of these facts is true:

- The host is not Linux.
- `/dev/net/tun` is absent.
- The process has no `CAP_NET_ADMIN` and `sudo -n` is not available.
- The `ip` command is absent.

The `tun-bench` binary uses the same skip.
A process with no `CAP_NET_ADMIN` prints `K3: CAP_NET_ADMIN is absent.` and exits 0.
That exit is not a pass of the 100 Mbps gate.
