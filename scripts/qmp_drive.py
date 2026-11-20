#!/usr/bin/env python3
"""Marker-driven QMP driver for the q35 boot lane: waits for the
kernel's "armed" marker, injects a keypress (the PS/2 round trip),
then captures the screen (the GFX proof)."""
import json
import socket
import sys
import time

LOG = sys.argv[1]
SOCK = "/tmp/qmp.sock"


def wait_marker(pat, timeout=180):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(LOG, "r", errors="replace") as f:
                if pat in f.read():
                    return True
        except FileNotFoundError:
            pass
        time.sleep(0.5)
    return False


# The pattern is drawn BEFORE the keyboard arms; capture the screen
# as soon as the GFX marker appears (the kernel keeps running, but
# QEMU can exit quickly at the end of the boot — grab it early).
if not wait_marker("bands+checker+AEGIS drawn"):
    sys.exit("kernel never drew the pattern")

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(60)
s.connect(SOCK)
f = s.makefile("rwb")


def rx():
    while True:
        line = f.readline()
        if not line:
            raise RuntimeError("qmp closed")
        msg = json.loads(line)
        if "event" in msg:
            continue
        return msg


def cmd(exe, args=None):
    payload = {"execute": exe}
    if args is not None:
        payload["arguments"] = args
    f.write(json.dumps(payload).encode() + b"\n")
    f.flush()
    return rx()


rx()  # greeting
cmd("qmp_capabilities")
cmd("screendump", {"filename": "/tmp/screen.ppm"})
print("qmp-drive: screen captured", flush=True)
if not wait_marker("[KBD] armed"):
    sys.exit("kernel never armed the keyboard poll")
cmd("send-key", {"keys": [{"type": "qcode", "data": "a"}], "hold-time": 300})
s.close()
print("qmp-drive: key sent", flush=True)
