#!/usr/bin/env python3
"""K27: the TLS 1.3 echo server for the fixture generator and the
boot lane — a REAL OpenSSL handshake (Python's ssl module, OpenSSL
3.5.7 underneath) with an Ed25519 certificate, then a deterministic
encrypted echo: every received chunk comes back as b"PONG:" + chunk.

Usage: tls_echo_server.py PORT KEY_PEM CERT_PEM [LOGFILE]
When LOGFILE is given, every accept/recv/close is appended to it —
the lane's diagnostic for "did the guest's SYN ever arrive".
"""

import socket
import ssl
import sys


def log(logfile: str | None, msg: str) -> None:
    if logfile:
        with open(logfile, "a") as f:
            f.write(msg + "\n")


def main() -> None:
    port = int(sys.argv[1])
    key, cert = sys.argv[2], sys.argv[3]
    logfile = sys.argv[4] if len(sys.argv) > 4 else None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    # K28: answer the client's ALPN offer ("echo/1") — the negotiated
    # protocol rides EncryptedExtensions back
    ctx.set_alpn_protocols(["echo/1"])
    # the CLIENT's list decides: our Rust client offers only
    # TLS_CHACHA20_POLY1305_SHA256, so that is what negotiates
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(4)
        log(logfile, f"listening on {port}")
        while True:
            conn, addr = srv.accept()
            log(logfile, f"accept from {addr}")
            with ctx.wrap_socket(conn, server_side=True) as tls:
                log(logfile, f"handshake ok: {tls.cipher()}")
                while True:
                    data = tls.recv(2048)
                    if not data:
                        break
                    log(logfile, f"recv {len(data)} bytes")
                    tls.sendall(b"PONG:" + data)
                tls.unwrap()
            log(logfile, "closed")


if __name__ == "__main__":
    main()
