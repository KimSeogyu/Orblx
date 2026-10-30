#!/usr/bin/env python3
"""Small TCP and UDP probes for the datapath ACL proof (W24).

listen-tcp IP PORT LOG    accept TCP, log each connection and its byte count, reply "ok".
listen-udp IP PORT LOG    log each datagram and echo it back.
tcp IP PORT TIMEOUT       connect, send one line, print the result.
udp IP PORT TIMEOUT       send one datagram, wait for the echo, print the result.
spray IP FIRST LAST       send one UDP datagram to each port from FIRST to LAST.
listen-stamp IP PORT LOG  log the receive time (Unix ms) of each datagram. No reply.
stream IP PORT SECS MS [TAG]  send one UDP datagram each MS ms for SECS s. Print the count.
                          TAG starts each payload (W25 HA proof).
listen-echo IP PORT       echo each line on each TCP connection (W25-10).
tcp-hold IP PORT SECS     keep one TCP connection, send a line each 100 ms, wait 1 s
                          for the echo, and connect again after a loss. Print the
                          events with the Unix ms time (W25-10).
"""
import socket
import sys
import threading
import time

PROBE = b"orblx-acl-probe\n"


def log_line(path, text):
    with open(path, "a", encoding="utf-8") as out:
        out.write(text + "\n")


def listen_tcp(ip, port, path):
    open(path, "a", encoding="utf-8").close()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(16)

    def serve(conn, peer):
        total = 0
        conn.settimeout(5)
        try:
            data = conn.recv(4096)
            total += len(data)
            if data:
                conn.sendall(b"ok\n")
        except OSError:
            pass
        finally:
            conn.close()
        log_line(path, "accept %s bytes %d" % (peer[0], total))

    while True:
        conn, peer = server.accept()
        threading.Thread(target=serve, args=(conn, peer), daemon=True).start()


def listen_udp(ip, port, path):
    open(path, "a", encoding="utf-8").close()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    while True:
        data, peer = sock.recvfrom(65535)
        log_line(path, "datagram %s bytes %d" % (peer[0], len(data)))
        sock.sendto(data, peer)


def tcp(ip, port, timeout):
    try:
        conn = socket.create_connection((ip, port), timeout)
    except socket.timeout:
        print("tcp %s:%d timeout" % (ip, port))
        return
    except ConnectionRefusedError:
        print("tcp %s:%d reset" % (ip, port))
        return
    except OSError as err:
        print("tcp %s:%d fail %s" % (ip, port, type(err).__name__))
        return
    try:
        conn.settimeout(timeout)
        conn.sendall(PROBE)
        reply = conn.recv(16).decode(errors="replace").strip()
        print("tcp %s:%d connected reply %s" % (ip, port, reply or "none"))
    except OSError as err:
        print("tcp %s:%d connected fail %s" % (ip, port, type(err).__name__))
    finally:
        conn.close()


def udp(ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(PROBE, (ip, port))
    try:
        data, _ = sock.recvfrom(4096)
        print("udp %s:%d reply %s" % (ip, port, "yes" if data == PROBE else "other"))
    except OSError:
        print("udp %s:%d reply none" % (ip, port))


def spray(ip, first, last):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for port in range(first, last + 1):
        sock.sendto(PROBE, (ip, port))
    print("spray %s ports %d-%d sent %d" % (ip, first, last, last - first + 1))


def listen_stamp(ip, port, path):
    open(path, "a", encoding="utf-8").close()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))
    while True:
        data, peer = sock.recvfrom(65535)
        log_line(path, "rx_ms %d %s %s" % (int(time.time() * 1000), peer[0], data.decode(errors="replace")))


def stream(ip, port, secs, every_ms, tag=""):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end = time.time() + secs
    sent = 0
    prefix = (tag + " ").encode() if tag else b""
    while time.time() < end:
        try:
            sock.sendto(prefix + b"seq %d" % sent, (ip, port))
        except OSError:
            # A route change can fail one send. The stream goes on.
            pass
        sent += 1
        time.sleep(every_ms / 1000.0)
    print("stream %s:%d sent %d" % (ip, port, sent))


def listen_echo(ip, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((ip, port))
    server.listen(16)

    def serve(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            return
        finally:
            conn.close()

    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


def now_ms():
    return int(time.time() * 1000)


def tcp_hold(ip, port, secs):
    end = time.time() + secs
    conn = None
    number = 0
    seq = 0
    lost_at = None
    while time.time() < end:
        if conn is None:
            try:
                conn = socket.create_connection((ip, port), 1.0)
                conn.settimeout(1.0)
                number += 1
                print("event connect %d at_ms %d" % (number, now_ms()), flush=True)
                if lost_at is not None:
                    print("event reconnect %d at_ms %d" % (number, now_ms()), flush=True)
            except OSError as err:
                print("event connect_fail %s at_ms %d" % (type(err).__name__, now_ms()), flush=True)
                time.sleep(0.1)
                continue
        line = b"hold %d\n" % seq
        seq += 1
        try:
            conn.sendall(line)
            got = b""
            while not got.endswith(b"\n"):
                part = conn.recv(64)
                if not part:
                    raise ConnectionResetError()
                got += part
            if got != line:
                raise ValueError()
        except (OSError, ValueError) as err:
            if lost_at is None:
                lost_at = now_ms()
            print("event lost %d %s at_ms %d" % (number, type(err).__name__, now_ms()), flush=True)
            try:
                conn.close()
            except OSError:
                pass
            conn = None
            continue
        time.sleep(0.1)
    print("event end connections %d lines %d at_ms %d" % (number, seq, now_ms()), flush=True)


def main():
    cmd = sys.argv[1]
    ip = sys.argv[2]
    if cmd == "listen-tcp":
        listen_tcp(ip, int(sys.argv[3]), sys.argv[4])
    elif cmd == "listen-udp":
        listen_udp(ip, int(sys.argv[3]), sys.argv[4])
    elif cmd == "tcp":
        tcp(ip, int(sys.argv[3]), float(sys.argv[4]))
    elif cmd == "udp":
        udp(ip, int(sys.argv[3]), float(sys.argv[4]))
    elif cmd == "spray":
        spray(ip, int(sys.argv[3]), int(sys.argv[4]))
    elif cmd == "listen-stamp":
        listen_stamp(ip, int(sys.argv[3]), sys.argv[4])
    elif cmd == "stream":
        tag = sys.argv[6] if len(sys.argv) > 6 else ""
        stream(ip, int(sys.argv[3]), float(sys.argv[4]), float(sys.argv[5]), tag)
    elif cmd == "listen-echo":
        listen_echo(ip, int(sys.argv[3]))
    elif cmd == "tcp-hold":
        tcp_hold(ip, int(sys.argv[3]), float(sys.argv[4]))
    else:
        raise SystemExit("unknown command")


if __name__ == "__main__":
    main()
