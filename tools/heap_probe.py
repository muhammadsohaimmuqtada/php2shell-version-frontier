#!/usr/bin/env python3
"""Read the Zend MM state at php_session_send_cookie() for one request shape.

The official php:*-apache images ship libphp.so with a symbol table but no
DWARF, so gdb cannot walk the heap structures by name.  This tool reads them
by offset, using the layout of Zend/zend_alloc.c for the target PHP version:

  _zend_mm_heap  (8.1.x, ZEND_MM_STAT/LIMIT/CUSTOM/STORAGE all enabled)
      0  int   use_custom_heap
      8  ptr   storage
     16  size  size
     24  size  peak
     32  ptr   free_slot[30]
    272  size  real_size
    280  size  real_peak
    288  size  limit
    296  int   overflow
    304  ptr   huge_list
    312  ptr   main_chunk
    320  ptr   cached_chunks
    ...
  _zend_mm_chunk
      0  ptr   heap
      8  ptr   next
     16  ptr   prev
     24  u32   free_pages
     28  u32   free_tail
     32  u32   num
    456  map   free_map (64B)
    520  map[] map[512]

  _php_ps_globals (8.1.x): id at 16, mod_data at 96, use_cookies at 329,
  send_cookie at 352.

The interesting question is whether the 121-byte allocation of
php_url_encode() can be served at all: it needs a free bin-128 slot
(heap->free_slot[11]) or a fresh page (a chunk with free_pages > 0, and a
chunk may only be mapped while real_size + 2MB <= limit).

Local disposable containers only.
"""
from __future__ import annotations

import argparse
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

GDB_SCRIPT = r"""
set pagination off
set confirm off
set breakpoint pending on
python
import gdb

HEAP_FREE_SLOT = 32
HEAP_REAL_SIZE = 272
HEAP_LIMIT = 288
HEAP_MAIN_CHUNK = 312
CHUNK_NEXT = 8
CHUNK_FREE_PAGES = 24
PS_ID = 16
PS_MOD_DATA = 96
PS_USE_COOKIES = 329
PS_SEND_COOKIE = 352


def _rd(addr, n):
    inf = gdb.selected_inferior()
    return int.from_bytes(inf.read_memory(addr, n).tobytes(), 'little')


def u64(a):
    return _rd(a, 8)


def u32(a):
    return _rd(a, 4)


def u8(a):
    return _rd(a, 1)


def free_chain_len(head, limit=400):
    n = 0
    p = head
    while p and n < limit:
        n += 1
        p = u64(p)
    return n


class SendCookieBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("php_url_encode")

    def stop(self):
        try:
            heap = int(gdb.parse_and_eval("(unsigned long)zend_mm_get_heap()"))
            real = u64(heap + HEAP_REAL_SIZE)
            limit = u64(heap + HEAP_LIMIT)
            fs11 = u64(heap + HEAP_FREE_SLOT + 11 * 8)
            fs7 = u64(heap + HEAP_FREE_SLOT + 7 * 8)
            chunk = u64(heap + HEAP_MAIN_CHUNK)
            chunks = []
            total = 0
            c = chunk
            for _ in range(32):
                fp = u32(c + CHUNK_FREE_PAGES)
                chunks.append("%#x:%d" % (c, fp))
                total += fp
                nxt = u64(c + CHUNK_NEXT)
                if nxt == chunk:
                    break
                c = nxt
            ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
            sid = u64(ps + PS_ID)
            sc = u8(ps + PS_SEND_COOKIE)
            uc = u8(ps + PS_USE_COOKIES)
            slen = u64(sid + 16) if sid else -1
            md = u64(ps + PS_MOD_DATA)
            base = sid & ~0x1FFFFF if sid else 0
            gdb.write("SEND_COOKIE heap=%#x real=%d limit=%d fs11=%#x/%d "
                      "fs7=%#x/%d freepages=%d chunks=%s id=%#x len=%d "
                      "send_cookie=%d use_cookies=%d mod_data=%#x "
                      "chunkbase=%#x idpage=%d idoff=%#x\n"
                      % (heap, real, limit, fs11, free_chain_len(fs11),
                         fs7, free_chain_len(fs7), total, " ".join(chunks),
                         sid, slen, sc, uc, md, base,
                         (sid - base) // 4096 if sid else -1,
                         (sid - base) & 0xFFF if sid else 0))
        except Exception as e:
            gdb.write("SEND_COOKIE_ERR %r\n" % (e,))
        gdb.flush()
        return False


class SafeErrBP(gdb.Breakpoint):
    def __init__(self):
        super().__init__("zend_mm_safe_error")

    def stop(self):
        try:
            heap = int(gdb.parse_and_eval("(unsigned long)zend_mm_get_heap()"))
            ps = int(gdb.parse_and_eval("(unsigned long)&ps_globals"))
            gdb.write("MM_SAFE_ERROR real=%d limit=%d send_cookie=%d\n"
                      % (u64(heap + HEAP_REAL_SIZE), u64(heap + HEAP_LIMIT),
                         u8(ps + PS_SEND_COOKIE)))
        except Exception as e:
            gdb.write("MM_SAFE_ERROR_ERR %r\n" % (e,))
        gdb.execute("bt 8")
        gdb.flush()
        return False


SendCookieBP()
SafeErrBP()
end
continue
"""


def patch_a(port: int, out_path: str) -> str:
    src = open(os.path.join(VENDOR, "tools", "send_a_oom5.py"),
               encoding="utf-8").read()
    src = src.replace("127.0.0.1:8088", f"127.0.0.1:{port}")
    src = src.replace("('127.0.0.1', 8088)", f"('127.0.0.1', {port})")
    src = src.replace("'/tmp/a_oom4.resp'", repr(out_path))
    src = src.replace("'A' * 99 + '.txt'", "'a.txt'")
    path = os.path.join("/tmp", f"probe_a_{port}.py")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    return path


def worker_pid(name: str) -> int | None:
    r = subprocess.run(["docker", "top", name, "-eo", "pid,ppid,comm"],
                       capture_output=True, text=True)
    pids = [int(l.split()[0]) for l in r.stdout.splitlines()[1:]
            if l.split() and l.split()[-1] == "apache2"]
    return pids[-1] if pids else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--a", default="0 62 235 15000 208 0 4000 103")
    ap.add_argument("--warm-len", type=int, default=0)
    ap.add_argument("--w64-len", type=int, default=0)
    ap.add_argument("--ini", default="php-off.ini")
    ap.add_argument("--keep", action="store_true")
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

    with open("/tmp/heap_probe.gdb", "w", encoding="utf-8") as fh:
        fh.write(GDB_SCRIPT)
    log = "/tmp/heap_probe_out.log"
    open(log, "w").close()
    wp = worker_pid(args.name)
    if not wp:
        raise SystemExit("no worker pid")
    subprocess.Popen(["sudo", "-n", "gdb", "-p", str(wp), "-batch",
                      "-x", "/tmp/heap_probe.gdb"],
                     stdout=open(log, "wb"), stderr=subprocess.STDOUT)
    time.sleep(8)

    a_tool = patch_a(args.port, "/tmp/probe_a.resp")
    env = dict(os.environ)
    env.update({"WARM_LEN": str(args.warm_len), "W64_LEN": str(args.w64_len),
                "W64_N": "1" if args.w64_len else "0"})
    params = args.a.split()
    try:
        subprocess.run([PYTHON, a_tool] + params, env=env,
                       capture_output=True, timeout=240)
    except subprocess.TimeoutExpired:
        print("request timed out")
    time.sleep(1.5)

    text = open(log, encoding="utf-8", errors="replace").read()
    for line in text.splitlines():
        if "SEND_COOKIE" in line or "MM_SAFE_ERROR" in line or "#" in line[:4]:
            print(line)
    if not args.keep:
        M.docker("rm", "-f", args.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
