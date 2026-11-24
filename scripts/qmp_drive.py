#!/usr/bin/env python3
"""Marker-driven QMP driver for the boot lanes: waits for the kernel's
"armed" marker, injects a keypress (the PS/2 round trip), then captures
the screen (the GFX proof). Mode "ps2" (K18): the lean PS/2 lane — one
key at the kernel's armed marker, no GFX, no USB window."""
import json
import socket
import sys
import time

LOG = sys.argv[1]
MODE = sys.argv[2] if len(sys.argv) > 2 else "q35"
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


if MODE == "ps2":
    # The PS/2 lane (K18): a lean machine — no VGA to capture, no USB
    # keyboard, no text console. ONE key at the kernel's own armed
    # marker: the IRQ1 chain's proof (the kernel drains the self-test's
    # stale edge first and accepts only the keyboard's vector). The
    # handshake is inline — the rx/cmd helpers below belong to the
    # q35 flow, which this branch never reaches.
    if not wait_marker("[KBD] armed"):
        sys.exit("kernel never armed the keyboard")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(60)
    s.connect(SOCK)
    f = s.makefile("rwb")
    f.readline()  # greeting
    f.write(json.dumps({"execute": "qmp_capabilities"}).encode() + b"\n")
    f.write(
        json.dumps(
            {
                "execute": "send-key",
                "arguments": {
                    "keys": [{"type": "qcode", "data": "a"}],
                    "hold-time": 300,
                },
            }
        ).encode()
        + b"\n"
    )
    f.flush()
    print("qmp-drive: ps2 key sent", flush=True)
    s.close()
    sys.exit(0)


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
print("qmp-drive: key sent", flush=True)
# The USB HID keyboard's own window: the kernel posts the interrupt-IN
# report request and arms; the second key press lands in the report.
if wait_marker("[USBH] HID armed"):
    cmd("send-key", {"keys": [{"type": "qcode", "data": "a"}], "hold-time": 500})
    print("qmp-drive: usb key sent", flush=True)
else:
    print("qmp-drive: no USB HID window (the keyboard device absent?)", flush=True)
# Phase 4 (the text console): the console arms at the END of the
# driver phase — wait for its marker, let the banner settle, and
# capture the text plane for the pixel check.
if not wait_marker("[GFX2] text console"):
    sys.exit("kernel never armed the text console")
time.sleep(1.0)
cmd("screendump", {"filename": "/tmp/screen2.ppm"})
print("qmp-drive: text screen captured", flush=True)
s.close()
