# php2shell version frontier — measured RCE per PHP build (amd64)

Empirical answer to *"which PHP versions can the published php2shell chain
(CVE-2026-109618 / CVE-2026-109619) actually turn into code execution?"* —
measured build-by-build in disposable local containers, with per-version
calibration profiles and the method that closes a new build in one pass.

**Measured frontier (amd64, official `php:<ver>-apache` images, lab ini):**

| build | stage 1 (heap leak) | stage 2 (libphp leak) | stage 3 (code exec) | RCE |
|---|---|---|---|---|
| 8.5.11 | ✅ | ✅ | ✅ | **yes** |
| 8.5.10 | ✅ | ✅ | ✅ | **yes** (upstream had aarch64 only) |
| 8.4.26 | ✅ | ✅ | ✅ | **yes** |
| 8.4.25 | ✅ | ✅ | ✅ | **yes** (upstream had aarch64 only) |
| **8.3.35** | ✅ | ✅ | ✅ | **yes** — **new**: upstream marks it `rce: false, htdata: null` |
| 8.2.34, 8.1.34, 8.0.30, 7.4.33, 5.6.40 | ❌ | ❌ | ❌ | no — leak channel gap, see docs |

Every RCE row is backed by a proof file (`id` output) read out of the
container — a crash or a 500 is never recorded as RCE.

## What is new here

1. **PHP 8.3.35 closed.** The upstream project's own profile for 8.3.35 says
   `rce: false` — leaks calibrated, stage 3 not verified. We measured the
   missing constant: the fake-`HashTable` carrier must be aimed at
   **`HTDATA = chunk + 0x6a0d8`** (carrier length 15). On 8.4.x the same
   structure sits at `0x690d8` — the surviving spray lands exactly one page
   (0x1000) higher on 8.3.35 with the same intra-page offset, which is the
   measurable form of the `zend_object.extra_flags` structural difference
   between the branches.
2. **One-shot derivation instead of sweeping.** `tools/fs_prep.py` +
   `tools/fs_trigger.py` attach gdb to the single Apache worker, fire one
   stage-3 request, catch the SIGSEGV and scan the 2 MiB Zend MM chunk for
   the fake-HashTable header (`01 00 00 00 07 … f8 ff ff ff`). The surviving
   copy's address *is* the HTDATA constant for that build — no blind sweep.
3. **Signature baseline** (`tools/sig8426.py`): on a known-good build,
   `empty/abort` = "carrier landed on the dangling reference, aim wrong";
   a wrong carrier size class yields a normal `200`. This makes a failing
   build's response pattern interpretable before any sweep.
4. **amd64 confirmation for 8.4.25 / 8.5.10** — upstream published these two
   only for aarch64.
5. **Field-grade condition matrix** (docs/FIELD_GRADE.md): the chain was
   measured on a 25-worker server under realistic traffic — published
   transport fails (0/10); with keep-alive connection pinning
   (`tools/ka_target.py`) + the standard retry loop it is **10/10
   (median 5.2 s)**. `display_errors=Off`, PHP-FPM (worker exits code 70 on
   the pre-RINIT OOM), and current distro packages are measured negative
   boundaries with named mechanisms.
5. **Residual-set mechanism** (docs): on ≤ 8.2 branches the corruption fires
   but the leak never leaves the server — `php_session_send_cookie()`
   clears `PS(send_cookie)` unconditionally (a one-line ≥ 8.3 vs ≤ 8.2
   source difference), and an OOM-bypass of that line was demonstrated on
   8.1.17 under gdb. Chain assembly on those branches remains open research.

## Layout

```
profiles/   per-build calibration profiles (amd64, lab ini) — 8.3.35 now rce=true
tools/      calibration, sweeps, gdb crash forensics, clean end-to-end repro
docs/       full method + findings + evidence ladder (target-agnostic)
logs/       proof records: 8.3.35 repro JSON, 8.4.26 signature baseline, matrix report
```

## Rebuilding the environment

The exploit module is **not** vendored here — clone the upstream project it
derives from and point the tools at it (they import
`php2shell_calibrate`/`php2shell_matrix` from the devploit checkout, which
wraps the upstream `exploit.py`):

```bash
git clone https://github.com/9bie/php2shell-bypass-aslr-exp vendor/php2shell-upstream
```

Lab config (single-worker prefork, `memory_limit=8M`,
`session.upload_progress=On`, `display_errors=On`) and webroot come from the
upstream repo's `docker/` directory. Everything runs against containers on
`127.0.0.1` only.

One-shot 8.3.35 reproduction:

```bash
python3 tools/fs_full.py          # fresh container -> leak -> leak -> aimed stage-3 -> proof
```

## Scope and responsible use

- This is **1day** research: the vulnerability and the exploit chain are
  public; the additions are the version-specific stage-3 calibration, the
  forensics method that derives it, and the measured per-version frontier.
- Verified against **stock official Docker images with the documented lab
  ini** on amd64. Distro packages, other SAPIs, other architectures, and
  production php.ini settings shift heap layout — recalibrate, don't assume.
- The residual (≤ 8.2) versions are **code-vulnerable but not
  chain-complete**: "no working public chain" is a measurement, not a safety
  guarantee. Patch to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or move off EOL
  branches.
- Use only against systems you own or are explicitly authorized to test.

## Credits

- Chain and mechanism: [`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp)
- `display_errors=0` analysis and request shapes: the upstream project's docs.
- Version frontier, 8.3.35 stage-3 calibration, forensics tooling, amd64
  confirmations, residual-set source analysis: this work.

MIT licensed (see `LICENSE`); upstream remains under its own license.
