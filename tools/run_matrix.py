#!/usr/bin/env python3
"""Empirical RCE-coverage matrix for PHP2Shell, over local disposable containers.

Reuses devploit/php2shell's calibrated chain (php2shell_calibrate.py) so results
are directly comparable to its published profiles, but writes into a separate
profile directory so the upstream published profiles are preserved.

Every build is tested with the same chain. A build is recorded rce=true ONLY when
the calibrator executed a command in the container and read the proof file back
out of the mounted /out volume -- i.e. actual code execution, not a crash.

All targets are disposable local Docker containers bound to 127.0.0.1.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

LAB = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.join(LAB, "devploit-php2shell")
VENDOR = os.path.join(DEV, "vendor", "php2shell-upstream")
sys.path.insert(0, os.path.join(DEV, "tools"))

import php2shell_matrix as M  # noqa: E402

OUR_PROFILES = os.path.join(LAB, "profiles-ours")
os.makedirs(OUR_PROFILES, exist_ok=True)
M.PROFILES = OUR_PROFILES

# This host's CPython reports sys.executable as the ZCode AppImage binary, so
# spawning [sys.executable, script.py] launches the desktop app instead of the
# script. Resolve a real interpreter by path instead.
PYTHON = shutil.which("python3") or "/usr/bin/python3"
assert os.path.basename(os.path.realpath(PYTHON)).startswith("python"), PYTHON

# key, image, port
BUILDS = [
    # --- published-verified baseline and published boundary cases ---
    ("8.4.26", "php:8.4.26-apache", 8092),   # devploit: verified rce=true
    ("8.5.11", "php:8.5.11-apache", 8093),   # devploit: verified rce=true
    ("8.4.25", "php:8.4.25-apache", 8094),   # devploit: rce=true (aarch64 only)
    ("8.5.10", "php:8.5.10-apache", 8095),   # devploit: rce=true (aarch64 only)
    ("8.3.35", "php:8.3.35-apache", 8091),   # devploit: stages but rce=false
    ("8.2.34", "php:8.2.34-apache", 8090),   # devploit: stages but rce=false
    ("8.1.34", "php:8.1.34-apache", 8102),   # devploit: offsets only, 0 stages
    ("8.0.30", "php:8.0.30-apache", 8101),   # devploit: offsets only, 0 stages
    ("7.4.33", "php:7.4.33-apache", 8100),   # devploit: offsets only, 0 stages
    # --- exact builds observed on this engagement's targets ---
    ("8.1.17", "php:8.1.17-apache", 8117),   # assessed host A
    ("8.0.20", "php:8.0.20-apache", 8120),   # assessed host C (mod_php)
    ("5.6.40", "php:5.6.40-apache", 8156),   # assessed host B
]


def run_build(build, ns) -> dict:
    """Start a disposable replica and calibrate it, with stdout inherited.

    devploit's own run_build() captures the calibrator's output, which on this
    host is swamped by unrelated desktop-app noise; inheriting stdout keeps the
    chain's own progress lines visible.
    """
    label = f"{build['key']}-bookworm-amd64"
    name = f"p2s-matrix-{build['key'].replace('.', '')}"
    outdir = M.prepare_lab_out(os.path.join(M.LAB, "out", build["key"]))
    proof = os.path.join(outdir, "p1")

    print(f"\n=== {label} ({build['image']}) ===", flush=True)
    M.docker("rm", "-f", name)
    run = M.docker(
        "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{build['port']}:80",
        "-v", f"{M.LAB}/webroot:/var/www/html:ro",
        "-v", f"{M.LAB}/php.ini:/usr/local/etc/php/conf.d/zz-matrix.ini:ro",
        "-v", f"{M.LAB}/apache.conf:/etc/apache2/conf-enabled/zz-matrix.conf:ro",
        "-v", f"{outdir}:/out",
        build["image"], timeout=900,
    )
    if run.returncode != 0:
        print("[!] docker run failed:", run.stderr.strip()[:300], flush=True)
        return {"label": label, "status": "docker-failed", "rce": False}

    url = f"http://127.0.0.1:{build['port']}/index.php"
    if not M.wait_http(url):
        print("[!] replica did not answer", flush=True)
        M.docker("rm", "-f", name)
        return {"label": label, "status": "no-http", "rce": False}

    cmd = [PYTHON, os.path.join(M.HERE, "php2shell_calibrate.py"),
           "--target", url, "--container", name,
           "--repo-dir", ns.repo_dir,
           "--proof-file", proof,
           "--distro", "bookworm-amd64",
           "--arch", "amd64",
           "--out-dir", OUR_PROFILES,
           "--stage2-t", "406"]
    print("[*] calibrating", flush=True)
    logpath = os.path.join(LAB, "logs", f"{build['key']}.log")
    os.makedirs(os.path.dirname(logpath), exist_ok=True)
    rc = None
    with open(logpath, "w", encoding="utf-8", errors="replace") as logf:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    bufsize=1)
            for line in proc.stdout:
                logf.write(line)
                logf.flush()
                print(line, end="", flush=True)
            rc = proc.wait(timeout=ns.timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            print("[!] calibration timeout", flush=True)
    if rc not in (0, None):
        print(f"[!] calibrator exited {rc}", flush=True)
    M.docker("rm", "-f", name)

    profile = os.path.join(OUR_PROFILES, f"{build['key']}-bookworm-amd64.json")
    status, rce = "no-profile", False
    if os.path.isfile(profile):
        try:
            data = json.load(open(profile, encoding="utf-8"))
            rce = bool(data.get("rce"))
            status = "rce" if rce else "leaks-only"
        except ValueError:
            status = "bad-profile"
    return {"label": label, "status": status, "rce": rce, "profile": profile}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="comma separated build keys")
    ap.add_argument("--repo-dir", default=VENDOR,
                    help="upstream exploit checkout (bootstrapped vendor copy)")
    ap.add_argument("--timeout", type=float, default=1200.0)
    ap.add_argument("--full-search", action="store_true")
    args = ap.parse_args()

    wanted = {x.strip() for x in args.only.split(",")} if args.only else None
    builds = [
        {"key": k, "image": i, "port": p}
        for k, i, p in BUILDS
        if wanted is None or k in wanted
    ]

    # devploit's run_build() expects the full argparse namespace from its main().
    ns = argparse.Namespace(
        repo_dir=args.repo_dir,
        full_search=args.full_search,
        keep=False,
        timeout=args.timeout,
        only=args.only,
    )

    results = []
    report = os.path.join(LAB, "matrix-report.json")
    if os.path.isfile(report):
        results = json.load(open(report, encoding="utf-8"))

    for build in builds:
        t0 = time.time()
        print(f"\n################ {build['key']} ({build['image']}) ################",
              flush=True)
        r = run_build(build, ns)
        r["elapsed_s"] = round(time.time() - t0, 1)
        print(f"==> {build['key']}: {r.get('status')}  ({r['elapsed_s']}s)", flush=True)
        results = [x for x in results if x.get("label", "").split("-")[0] != build["key"]]
        results.append(r)
        json.dump(results, open(report, "w", encoding="utf-8"), indent=2)

    print("\n================ COVERAGE ================")
    print("%-10s %-14s %-6s %s" % ("build", "status", "rce", "profile"))
    for r in sorted(results, key=lambda x: x.get("label", "")):
        print("%-10s %-14s %-6s %s" % (
            r.get("label", "?").split("-")[0], r.get("status", "?"),
            r.get("rce"), r.get("profile", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
