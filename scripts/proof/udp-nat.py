#!/usr/bin/env python3
"""UDP NAT for the symmetric-to-symmetric proof.

sequential gives each new UDP flow the next external port from 1024.
portblock gives each new UDP flow a free port in 20000-20063.
shift gives STUN ports 3478 and 3479 the sequential series.
Every other destination starts at 20000 and then adds 4000.
The punch port is not the next STUN port.

The mapping is endpoint-dependent: a new destination port gets a new external port.
A reply to a source that arrived on an external port uses that same external port.
Inbound UDP from an address this host has sent to is accepted on an allocated port.
TCP and ICMP stay on the kernel NAT.
"""

import random
import select
import socket
import struct
import sys

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_IGNORE_OUTGOING = 23
IPPROTO_UDP = 17
BLOCK_BASE = 20000
BLOCK_SIZE = 64


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += int.from_bytes(data[index : index + 2], "big")
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_udp(src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes) -> bytes:
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, IPPROTO_UDP, udp_len)
    udp_sum = checksum(pseudo + udp)
    if udp_sum == 0:
        udp_sum = 0xFFFF
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, udp_sum) + payload
    total = 20 + len(udp)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0,
        0,
        64,
        IPPROTO_UDP,
        0,
        src,
        dst,
    )
    ip_sum = checksum(header)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0,
        0,
        64,
        IPPROTO_UDP,
        ip_sum,
        src,
        dst,
    )
    return header + udp


class Table:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.next_port = 1024
        self.shift_port = 20000
        self.block = list(range(BLOCK_BASE, BLOCK_BASE + BLOCK_SIZE))
        random.shuffle(self.block)
        self.block_at = 0
        self.out: dict[tuple[str, int, str, int], int] = {}
        self.exact: dict[tuple[int, str, int], tuple[str, int]] = {}
        self.owner: dict[int, tuple[str, int]] = {}
        self.contacted: set[str] = set()
        self.reply: dict[tuple[str, int, str, int], int] = {}

    def allocate(self, dst_port: int) -> int:
        if self.mode == "shift" and dst_port not in (3478, 3479):
            port = self.shift_port
            self.shift_port = 20000 if self.shift_port >= 60000 else self.shift_port + 4000
            return port
        if self.mode == "sequential" or self.mode == "shift":
            port = self.next_port
            self.next_port = 1024 if self.next_port >= 65535 else self.next_port + 1
            return port
        for _ in range(BLOCK_SIZE):
            port = self.block[self.block_at % BLOCK_SIZE]
            self.block_at += 1
            if port not in self.owner:
                return port
        port = self.block[self.block_at % BLOCK_SIZE]
        self.block_at += 1
        return port

    def map_out(self, lan_ip: str, lan_port: int, dst_ip: str, dst_port: int) -> int:
        key = (lan_ip, lan_port, dst_ip, dst_port)
        found = self.out.get(key)
        if found is None:
            found = self.reply.get(key)
        if found is None:
            found = self.allocate(dst_port)
            self.out[key] = found
            self.exact[(found, dst_ip, dst_port)] = (lan_ip, lan_port)
            self.owner[found] = (lan_ip, lan_port)
            self.contacted.add(dst_ip)
            print(
                f"alloc {lan_ip}:{lan_port} to {dst_ip}:{dst_port} ext {found}",
                flush=True,
            )
        return found

    def map_in(self, src_ip: str, src_port: int, dst_port: int) -> tuple[str, int] | None:
        found = self.exact.get((dst_port, src_ip, src_port))
        # shift keeps the STUN mappings exact. A punch to the published STUN port
        # is not the flow that the sample predicted, so it does not enter.
        if found is None and self.mode == "shift" and dst_port < 20000:
            return None
        if found is None and src_ip in self.contacted:
            found = self.owner.get(dst_port)
        if found is None:
            return None
        self.reply[(found[0], found[1], src_ip, src_port)] = dst_port
        return found


def parse_udp(frame: bytes) -> tuple[str, int, str, int, bytes] | None:
    if len(frame) < 14 + 20 + 8:
        return None
    if frame[12:14] != b"\x08\x00":
        return None
    header = 14
    ver_ihl = frame[header]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(frame) < header + ihl + 8:
        return None
    if frame[header + 9] != IPPROTO_UDP:
        return None
    frag = int.from_bytes(frame[header + 6 : header + 8], "big")
    if frag & 0x3FFF:
        return None
    total = int.from_bytes(frame[header + 2 : header + 4], "big")
    src_ip = socket.inet_ntoa(frame[header + 12 : header + 16])
    dst_ip = socket.inet_ntoa(frame[header + 16 : header + 20])
    udp_at = header + ihl
    src_port, dst_port, udp_len, _sum = struct.unpack("!HHHH", frame[udp_at : udp_at + 8])
    end = udp_at + max(udp_len, 8)
    if end > header + total:
        end = header + total
    if end > len(frame) or end < udp_at + 8:
        return None
    return src_ip, src_port, dst_ip, dst_port, frame[udp_at + 8 : end]


def open_sniff(iface: str) -> socket.socket:
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    raw.bind((iface, 0))
    raw.setblocking(False)
    try:
        raw.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
    except OSError as err:
        print(f"router nat could not ignore outgoing frames. {err}", flush=True)
        raise
    return raw


def main() -> int:
    if len(sys.argv) != 6:
        print("udp-nat.py MODE WAN_IP LAN_IF WAN_IF NODE_IP", file=sys.stderr)
        return 2
    mode, wan_ip, lan_if, wan_if, node_ip = sys.argv[1:]
    if mode not in ("sequential", "portblock", "shift"):
        print(f"The UDP NAT mode {mode} is not valid.", file=sys.stderr)
        return 2
    table = Table(mode)
    lan = open_sniff(lan_if)
    wan = open_sniff(wan_if)
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print(f"router nat ready {mode}", flush=True)
    while True:
        ready, _, _ = select.select([lan, wan], [], [], 1.0)
        for sock in ready:
            try:
                frame = sock.recv(65535)
            except BlockingIOError:
                continue
            parsed = parse_udp(frame)
            if parsed is None:
                continue
            src_ip, src_port, dst_ip, dst_port, payload = parsed
            if sock is lan and src_ip == node_ip:
                ext = table.map_out(src_ip, src_port, dst_ip, dst_port)
                packet = build_udp(wan_ip, ext, dst_ip, dst_port, payload)
                try:
                    sender.sendto(packet, (dst_ip, dst_port))
                except OSError as err:
                    print(f"router nat send failed. {err}", flush=True)
            elif sock is wan and dst_ip == wan_ip:
                mapped = table.map_in(src_ip, src_port, dst_port)
                if mapped is None:
                    continue
                packet = build_udp(src_ip, src_port, mapped[0], mapped[1], payload)
                try:
                    sender.sendto(packet, (mapped[0], mapped[1]))
                except OSError as err:
                    print(f"router nat return failed. {err}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
