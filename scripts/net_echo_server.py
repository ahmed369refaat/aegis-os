#!/usr/bin/env python3
"""P1-1: the PLAIN TCP + UDP echo servers for the boot lane's live
netstack proof — the peer the ring-3 TCP/IP stack connects to through
slirp (10.0.2.2 IS this host's loopback under user networking).

Usage: net_echo_server.py TCP_PORT UDP_PORT [LOGFILE]

- TCP: every accepted connection echoes each chunk verbatim.
- UDP: every datagram is echoed back to its source from the same
  socket (the source port is part of the peer address the stack's
  connected datagram socket matches on).

When LOGFILE is given, every accept/recv/close is appended to it —
the lane's diagnostic for "did the guest's SYN ever arrive" (the
tls_echo_server.py discipline, without the TLS).
"""

import socket
import sys
import threading


def log(logfile: str | None, msg: str) -> None:
    if logfile:
        with open(logfile, "a") as f:
            f.write(msg + "\n")


def tcp_server(port: int, logfile: str | None) -> None:
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(4)
        log(logfile, f"tcp listening on {port}")
        while True:
            conn, addr = srv.accept()
            log(logfile, f"tcp accept from {addr}")
            with conn:
                while True:
                    data = conn.recv(2048)
                    if not data:
                        break
                    log(logfile, f"tcp recv {len(data)} bytes")
                    conn.sendall(data)
            log(logfile, "tcp closed")


def udp_server(port: int, logfile: str | None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
        srv.bind(("127.0.0.1", port))
        log(logfile, f"udp listening on {port}")
        while True:
            data, addr = srv.recvfrom(2048)
            log(logfile, f"udp recv {len(data)} bytes from {addr}")
            srv.sendto(data, addr)


def main() -> None:
    tcp_port = int(sys.argv[1])
    udp_port = int(sys.argv[2])
    logfile = sys.argv[3] if len(sys.argv) > 3 else None
    t = threading.Thread(target=tcp_server, args=(tcp_port, logfile), daemon=True)
    t.start()
    udp_server(udp_port, logfile)


if __name__ == "__main__":
    main()
