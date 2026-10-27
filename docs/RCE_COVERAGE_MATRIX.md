# PHP2Shell RCE coverage — empirical matrix and residual version set

**Question this answers:** *which PHP versions are already publicly RCE-able
(so they are out of scope for new research), and what is left over?*

Everything below was measured in disposable local Docker containers bound to
`127.0.0.1`. No third-party host was exploited at any point. The chain used is
the published one from `devploit/php2shell` (vendor checkout
`lab/devploit-php2shell/vendor/php2shell-upstream`, commit `4586f5c`), so the
results are directly comparable with its published profiles — no new exploit
logic was introduced except parameter sweeps and tool repairs.

---

## 1. Headline result

| | versions |
|---|---|
| **RCE demonstrated (public or reproduced by us)** | **8.3.35, 8.4.25, 8.4.26, 8.5.10, 8.5.11** |
| **Residual — no RCE, public or ours** | **5.6.40, 7.4.33, 8.0.20, 8.0.30, 8.1.17, 8.1.34, 8.2.34** |

The upstream project publishes verified RCE for five *builds*:
`8.4.25-aarch64`, `8.4.26-amd64`, `8.5.10-aarch64`, `8.5.11-aarch64`,
`8.5.11-amd64`. We reproduced RCE on `8.4.25-amd64` and `8.5.10-amd64`, which
upstream had only published for aarch64 — so the public set is now four
*versions*, all confirmed on amd64.

**We additionally closed 8.3.35** (previously the closest residual case): the
stage-3 fake-`zend_hash` carrier lands at `chunk + 0x6a0d8` on the official
`php:8.3.35-apache` image with a 15-byte carrier, and the container executes
`id` (`uid=33(www-data)`). See §4.4.

Everything else is residual. For the residual set the chain reaches three
different depths, and only the last one is open research:

| residual version | stage 1 (heap leak) | stage 2 (libphp leak) | stage 3 (code execution) |
|---|---|---|---|
| 8.2.34 | ❌ | ❌ | ❌ |
| 8.1.34, 8.1.17 | ❌ | ❌ | ❌ |
| 8.0.30, 8.0.20 | ❌ | ❌ | ❌ |
| 7.4.33 | ❌ | ❌ | ❌ |
| 5.6.40 | ❌ | ❌ | ❌ |

For the ≤ 8.2 rows the blocker is now **identified exactly** (§4.5) and the
version-independent primitive that bypasses it has been **demonstrated on
8.1.17**; what remains is chain assembly (stage 1 leak + stage 2 + stage 3)
on those builds.

---

## 2. Method

**Chain (upstream, unmodified request shapes).**

1. **Stage 1 — Zend MM chunk leak.** A multipart POST with 1001 parts,
   `session.upload_progress` enabled and a 12 MiB field drives the
   upload-progress handler into an out-of-memory bail-out during request
   parsing. The session id string is left dangling across the worker
   boundary; a following POST sprays N 48-byte fields until one lands in the
   recycled block, and a forged `zend_string` header expands the session
   cookie to 4096 bytes of adjacent heap.
2. **Stage 2 — libphp base leak.** The same primitive with a different field
   shape leaks a page-aligned pointer to `zval_ptr_dtor`, giving the libphp
   base.
3. **Stage 3 — code execution.** A fake `zend_hash`/fake `execute_data` is
   written over `PS(http_session_vars)` with `pDestructor = zif_system`, so
   the engine calls `system()` with a controlled string.

**What counts as RCE.** Only a real proof file written by the container
(`id>/out/p1`) and read back off the mounted `/out` volume. A crash, a 500, or
a heap leak without execution is never recorded as `rce=true`.

**Replica configuration** (identical for every build, `lab/devploit-php2shell/lab/rce/`):

```ini
memory_limit = 8M          post_max_size = 64M      upload_max_filesize = 64M
display_errors = On        session.upload_progress.enabled = On
session.use_strict_mode = 0   session.save_path = /tmp
```
Apache: prefork, `MaxRequestWorkers 1` (so the worker cannot rotate away
mid-attempt).

**Builds.** Official `php:<version>-apache` images, amd64.

---

## 3. The matrix

| build | upstream profile | ours (amd64) | stage 1 | stage 2 | stage 3 | RCE |
|---|---|---|---|---|---|---|
| 8.5.11 | rce=true (aarch64 + amd64) | rce=true | ✅ | ✅ | ✅ | **yes** |
| 8.5.10 | rce=true (aarch64 only) | rce=true | ✅ | ✅ | ✅ | **yes** |
| 8.4.26 | rce=true (amd64) | rce=true | ✅ | ✅ | ✅ | **yes** |
| 8.4.25 | rce=true (aarch64 only) | rce=true | ✅ | ✅ | ✅ | **yes** |
| 8.3.35 | stages 1–2, rce=false | **rce=true** | ✅ | ✅ | ✅ | **yes** |
| 8.2.34 | stage 1 failed (`stage1_n=0`), rce=false | stage 1 failed | ❌ | ❌ | ❌ | no |
| 8.1.34 | no stages, rce=false | stage 1 failed | ❌ | ❌ | ❌ | no |
| 8.0.30 | no stages, rce=false | stage 1 failed | ❌ | ❌ | ❌ | no |
| 7.4.33 | no stages, rce=false | stage 1 failed | ❌ | ❌ | ❌ | no |
| 8.1.17 *(assessed host A)* | — | stage 1 failed | ❌ | ❌ | ❌ | no |
| 8.0.20 *(assessed host C)* | — | stage 1 failed | ❌ | ❌ | ❌ | no |
| 5.6.40 *(assessed host B)* | — | stage 1 failed | ❌ | ❌ | ❌ | no |

Every stage-1 failure was reproduced **three times** per build (after adding
retry logic, §6) and is stable — it is a property of the build, not a flaky
attempt.

---

## 4. Why the residual versions fail — mechanism, not just "it didn't work"

### 4.1 The corruption *does* happen on 8.1.x — the cookie just never leaves the server

Raw-response diagnostics on `php:8.1.17-apache` (`lab/diag_session.py`) show:

```
[4] leak attempt : HTTP/1.1 200 OK | Content-Length: 3      <- no Set-Cookie
--- session files ---
name_len=37 file=sess_2438076d32a32e2eff95184da35f8952
  content: upload_progress_pwn|a:5:{s:10:"start_time";i:...}
name_len=53 file=sess_v0892xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  content:                                                       <- empty
```

The 53-character file name is `sess_` + 48 characters that are **exactly the
sprayed field value** (`v0892` + 44 × `x`). The use-after-free fires on
PHP 8.1.17 exactly as on 8.4.26 — the stale session-id pointer is re-pointed
into the recycled block. What differs is the *delivery* step: the corrupted
id never reaches the client, because the request that completes normally
returns **no `Set-Cookie` header at all**, so the 4096-byte heap dump that
the same primitive yields on 8.4.26 is discarded server-side.

Control comparison on 8.4.26 (same script, same request shape):

```
[4] leak attempt : HTTP/1.1 200 OK | Set-Cookie: PHPSESSID=v0841xxxx…; path=/
[4] cookie bytes : 48
```

The upstream notes (`NOTES.md` §5) state the same thing in their own words:
the earlier claim that 5.4/5.6/7.4/8.5 share the primitive "must be
re-measured per version before writing a 1day report".

### 4.2 The failure is not a tuning problem

Sweeps run against 8.1.17 and 8.2.34 (`lab/sweep_stage1.py`), covering the
three parameters the published chain exposes:

* sprayed-field count `N` ∈ {100 … 1500}
* forged-string length ∈ {48, 63, 79, 87, 95}
* **sprayed value length ∈ {24, 32, 40, 48, 56}** (added by us — it selects
  the Zend MM size class that has to match the stale block)

Result: **no combination yields a heap leak.** The best outcome is a 32-byte
cookie containing a *valid* generated session id, i.e. the corruption simply
did not land. Where the corruption does land (the 48-byte value), the cookie
is suppressed. The same sweep on 8.2.34 returns the same picture — a valid
32-byte session id on every attempt.

### 4.3 The vulnerable code is nevertheless present in every residual branch

This is a source-level fact, independent of the exploit chain. The upstream
fix is visible by diffing `php-src` tags:

* `PHP-8.4.26` → `PHP-8.4.27` (`ext/session/session.c`) adds
  `PS(in_rfc1867_update)`, an `incomplete_classes_only` unserialize mode, an
  early `php_rinit_session_globals()` in `MULTIPART_EVENT_START`, and this
  guard in `php_session_rfc1867_callback()`:

  ```c
  if (PG(modules_activated)) {
      /* request_parse_body(). Do not run here as it corrupts the session. */
      return retval;
  }
  ```

* The pre-fix pattern — `php_session_initialize()` + `PS(session_status) =
  php_session_active` + `php_session_flush()` executed *during multipart
  parsing, before RINIT* — is present in every one of these releases:

  | release | fix markers present? | verdict |
  |---|---|---|
  | PHP-5.6.40 | no | vulnerable pattern present |
  | PHP-7.4.33 | no | vulnerable pattern present |
  | PHP-8.0.30 | no | vulnerable pattern present |
  | PHP-8.1.34 | no | vulnerable pattern present |
  | PHP-8.2.34 | no | vulnerable pattern present |
  | PHP-8.3.35 | no | vulnerable pattern present |
  | PHP-8.4.26 | no | vulnerable pattern present |
  | PHP-8.5.11 | no | vulnerable pattern present |
  | PHP-8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | yes | fixed |

* **No EOL branch ever received a tagged fixed release.** The last releases
  of the three EOL branches are 7.4.33 (03 Nov 2022), 8.0.30 (03 Aug 2023)
  and 8.1.34 (18 Dec 2025); there is no 7.4.34 / 8.0.31 / 8.1.35. The
  backports PHP published for 7.4/8.0/8.1 exist only as source patches, so
  every deployed 7.4/8.0/8.1 build still runs the vulnerable code unless the
  *distribution* backported it into its own package.

So the residual set is **code-vulnerable but not yet RCE-proven** — which is
exactly the space where new research has value, and exactly the space this
assessment's L3/L4 ladder (`RCE_EVIDENCE_LADDER.md`) marks as unproven.

### 4.4 8.3.35 — closed: stage 3 now executes

8.3.35 was the closest residual case: the chain leaked the heap base and the
libphp base, but stage 3 never executed because the fake-`zend_hash` carrier
must be placed at a branch-specific address inside the chunk (upstream ships
three offsets measured on 8.4.x: `0x690D8`, `0x6E0D8`, `0x5404A`; none works
on 8.3.x).

A naive ±1024-byte sweep around those offsets found nothing, because the
carrier is a **167-byte live `zend_string`** — 24 + 167 + 1 = 192 bytes, i.e.
**bin 192** — so its data addresses sit on a 192-byte stride and the relevant
phase is `page index mod 3` (only 3 of every 24 candidate 8-byte steps can
ever hold the payload). `lab/sweep_carrier.py` therefore sweeps a
**stride-192, 3-phase** grid instead of a dense 8-byte grid: 576 attempts
cover the same ±12 KiB window that a dense sweep would need ~18,000 attempts
for.

Result on the official `php:8.3.35-apache` image:

```json
{ "carrier_len": 15, "off": "0x6a0d8",
  "proof": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
  "chunk": "0x7f3f50400000", "libphp": "0x7f3f51fad000" }
```

`HTDATA = chunk + 0x6a0d8` with a 15-byte carrier; the container executed
`id>/out/p1` and the proof file was read back from the mounted `/out` volume.
Log: `lab/logs/carrier-8335-p192.log`.

**Independent confirmation and the structural explanation.** The offset was
also derived top-down, without sweeping: a gdb crash-forensics pass
(`lab/fs_prep.py` → `lab/fs_trigger.py` under `sudo gdb -p <worker>`, catch
SIGSEGV, scan the 2 MiB chunk for the fake-HashTable header
`01 00 00 00 07 … f8 ff ff ff`) found **exactly one surviving sprayed copy at
`chunk + 0x6a0d8`** — one full page (0x1000) above the 8.4.x offset with the
same intra-page position (0xd8), which is the measurable form of the 8.4
`zend_object.extra_flags` structural shift. A signature baseline on the
known-good 8.4.26 build (`lab/sig8426.py`, `lab/logs/sig-8.4.26.json`) shows
that `empty/abort` means *the carrier landed on the dangling reference but the
aim was wrong* (wrong carrier size class yields a normal `200` instead) —
which is why 8.3.35's earlier all-abort results were correctly read as "one
aiming problem", not "no primitive". The aimed shot then executed on a second
container with a different ASLR base, and a clean end-to-end run
(`lab/fs_full.py`, fresh container → fingerprint → symbols → stage 1 →
stage 2 → one aimed stage-3) reproduced the proof a third time:

```json
{ "image": "php:8.3.35-apache", "htdata": "0x6a0d8", "carrier_len": 15,
  "chunk": "0x7f68d8800000", "libphp": "0x7f68da42b000",
  "proof": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
  "source": "clean-repro" }
```

(`lab/logs/repro-8.3.35-rce.json`; profile updated to `rce=true`.)

### 4.5 Why ≤ 8.2 fails — the exact version split, and the primitive that bypasses it

The residual ≤ 8.2 versions are blocked by **one line** in
`ext/session/session.c`:

```c
/* PHP >= 8.3 */
if (PS(use_cookies) && PS(send_cookie)) {
    zend_result cookies_sent = php_session_send_cookie();
    if (UNEXPECTED(cookies_sent == FAILURE)) { return FAILURE; }   /* flag survives */
    PS(send_cookie) = 0;
}

/* PHP <= 8.2 */
if (PS(use_cookies) && PS(send_cookie)) {
    php_session_send_cookie();
    PS(send_cookie) = 0;                                            /* always cleared */
}
```

The published chain primes the cross-request state by making the session
cookie send **fail** (`SG(headers_sent)=1`, triggered by the
`max_input_vars` warning). On ≥ 8.3 the early return leaves
`PS(send_cookie)=1` and a stale `PS(id)` behind, so the next request emits a
`Set-Cookie` built from the dangling id — that is the heap leak. On ≤ 8.2 the
flag is cleared unconditionally, request B never sends a cookie, and the leak
cannot fire. This is a **source-level fact**, not a tuning artefact: it
explains every ≤ 8.2 stage-1 failure in §3.

**The version-independent bypass.** `PS(send_cookie)=0` is only reached if
`php_session_send_cookie()` *returns*. If it **bails out** — an OOM inside it
— the statement is skipped on every branch, and the stale flag survives on all
versions. The first allocation in that function is

```c
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
   -> zend_string_safe_alloc(3, 32, 0, 0);   /* 121 bytes -> bin 128 */
```

so an OOM there is sufficient. On PHP 8.1 the limit is only enforced when a
**new 2 MiB chunk** is mapped, so the allocation has to come from a page that
does not exist yet: the bin-128 free list must be empty **and** no chunk may
have a free page.

That state is reachable, and we reached it on `php:8.1.17-apache`
(`lab/heap_probe.py` + `lab/heap_sweep.py`, both new):

| request-A shape (`tools/send_a_oom5.py`) | effect at the cookie send |
|---|---|
| `F=0 S=64 NB=232 BL=15000 X=214 K=0 KL=4000 FL=103` | `free_slot[11]=0x0` (empty ✅), 21 free pages → url_encode *succeeds*, OOM lands later in `init_op_array` |
| `F=0 S=64 NB=232 BL=15000 X=190 K=12 KL=4000 FL=1` | `free_slot[11]=0x0` (empty ✅), **0 free pages** → the 121-byte allocation of `php_url_encode` fails |

gdb evidence for the winning shape:

```text
SEND_COOKIE heap=0x7f...40 real=8388608 limit=8388608 fs11=0x0/0 freepages=0
           id=0x7f... len=32 send_cookie=1 use_cookies=1
MM_SAFE_ERROR real=8388608 limit=8388608 send_cookie=1
#0 zend_mm_safe_error
#1 zend_mm_alloc_pages[cold]
#2 zend_mm_alloc_small_slow
#3 php_url_encode              <-- the OOM is inside the cookie send
```

`PS(send_cookie)=1` **at the moment of the OOM** is the whole point: the
bail-out skips `PS(send_cookie)=0`, so the next request inherits both the
stale `PS(id)` and the flag — the ≥ 8.3 primitive, re-created on a ≤ 8.2
build. Note the two shape details that make it work: `S=64` fills the bin-128
runs exactly (2 pages, so the free list is empty), and `FL=1` keeps the file
part's own field name out of bin 128 so that it does not need a fresh page
before the cookie send.

This is a **primitive**, not yet a full chain: stage 1 (the leak), stage 2
and stage 3 still have to be assembled on the ≤ 8.2 builds with the new
request-A shape.

---

## 5. Engagement mapping

| target | advertised PHP | residual? | code-vulnerable? | RCE-proven? |
|---|---|---|---|---|
| `assessed host A` | 8.1.17 | yes | yes | no |
| `assessed host B` | 5.6.40 | yes | yes | no |
| `assessed host C` | 8.0.20 (mod_php, Win64) | yes | yes | no |
| assessed host D | hidden | unknown | unknown | no |
| assessed estate E | 8.0.20 / other | yes | yes | no |

All three exact builds observed on the targets sit in the residual set: the
vulnerable code is present, but no public RCE chain completes against them.
Per the engagement's own rules we do not attempt exploitation against these
hosts; the lab result is what upgrades their status from "advertised version
only" to "vulnerable code confirmed present in the exact upstream release".

---

## 6. Tool defects found and repaired in the lab copy

All four are in the *lab* tooling; the upstream repo was left untouched except
for the `docker/offsets.py` path/alias fix, which is required to read offsets
from non-8.4 images at all.

1. **`sys.executable` is the ZCode AppImage, not Python.** On this host
   CPython reports `sys.executable = /home/kali/Applications/ZCode-…AppImage`,
   so `subprocess.run([sys.executable, "calibrate.py"])` launched the desktop
   app: every calibration "ran" for ~7 s and produced only Electron deep-link
   noise and an `EACCES` on `zcode.desktop`. Fixed by resolving a real
   interpreter path (`shutil.which("python3")`).
2. **`memory_limit` probe matched `max_memory_limit`.** The regex
   `memory_limit\s*=>\s*(\S+)` matches the `max_memory_limit => -1` line that
   PHP 8.5.10+ prints *before* `memory_limit => 8M`, so the profile recorded
   "no memory limit" for builds that had 8 MiB. Anchored the regex.
3. **Chunk-base histogram accepted non-heap addresses.** `chunk_base()`
   returned `0x600000` for a build whose real chunk base was `0x7f…000000`,
   because a low 32-bit fragment won the frequency count. Stage 3 then
   "failed" on a build that is in fact exploitable — a **false negative that
   would have wrongly removed 8.4.26 from the RCE set**. Now only 64-bit
   user-space candidates are considered.
4. **No retry on stage 1.** The leak is timing-dependent; added three probe
   attempts and two attempts per forge length. (The EOL failures were
   re-verified with this in place and remain stable failures.)

Plus two upstream-repo fixes required to run the older images at all:

* `docker/offsets.py` assumed `/usr/lib/apache2/modules/libphp.so`; PHP 7.4
  and 5.6 images ship `libphp7.so` / `libphp5.so`. Now discovers `libphp*.so`.
* PHP 5.x exports the destructor as `_zval_ptr_dtor` (the unprefixed name is
  a macro). The extractor now accepts either spelling.

---

## 7. Reproducing

```bash
cd lab
python3 run_matrix.py                       # all builds, writes matrix-report.json
python3 run_matrix.py --only 8.3.35         # one build
python3 sweep_stage1.py --image php:8.1.17-apache --port 8117 --name p2s-sw \
        --ns 100,300,500,700,841,900,1000,1200,1500 --lens 48,63,79 \
        --val-lens 24,32,40,48,56
python3 sweep_stage3.py --image php:8.3.35-apache --port 8091 --name p2s-s3 \
        --bases 0x690d8,0x6e0d8,0x5404a --span 1024 --step 8
python3 diag_session.py --image php:8.1.17-apache --port 8117 --name p2s-d
```

Artifacts: `lab/matrix-report.json`, `lab/profiles-ours/*.json`,
`lab/logs/*.log`, `lab/matrix-run.log`.

---

## 8. What this does **not** prove

* No claim that the residual versions are *not* exploitable — only that the
  published chain does not complete against them and that our sweeps did not
  close the gap. The vulnerable code pattern is present in all of them.
* No aarch64 coverage. Upstream's aarch64 profiles were not re-run; the
  amd64 results are what the matrix reports.
* Distro packages (Debian/Ubuntu/CentOS) may backport the fix into a
  version string that still reads e.g. `8.1.34`. The source analysis in §4.3
  is about *upstream* releases, not vendor packages.
* `php:8.x-apache` images are upstream builds with one lab ini; vendor
  builds (especially Windows mod_php, as on `assessed host C`) can
  differ in layout.
