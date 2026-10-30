#!/usr/bin/env python3
"""Small TCP and UDP probes for the datapath ACL proof (W24).

listen-tcp IP PORT LOG    accept TCP, log each connection and its byte count, reply "ok".
listen-udp IP PORT LOG    log each datagram and echo it back.
tcp IP PORT TIMEOUT       connect, send one line, print the result.
udp IP PORT TIMEOUT       send one datagram, wait for the echo, print the result.
spray IP FIRST LAST       send one UDP datagram to each port from FIRST to LAST.
"""
import socket
import sys
import threading

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
    else:
        raise SystemExit("unknown command")


if __name__ == "__main__":
    main()
