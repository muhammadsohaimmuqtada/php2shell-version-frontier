# Field-grade measurements — does the lab RCE survive real-world conditions?

**Question this answers:** *was the five-version RCE frontier a lab artifact, or
does it hold on realistic deployments?* Everything below was measured, not
estimated. All exploitation ran against local containers only; the third-party
measurement (§5) is non-destructive fingerprinting (1 GET + 1 small POST per
host, no OOM, no crash tests).

---

## 1. Headline

| question | lab answer (before) | measured field answer (now) |
|---|---|---|
| Does the chain work on a multi-worker server? | untested (1-worker lab) | **published chain: 0/10. With two transport fixes: 10/10 under realistic traffic (median 5.2 s)** |
| Does it work with `display_errors=Off`? | untested (On required by published chain) | **no — blocked at stage-1 B-alignment, for everyone, including upstream** |
| Does it work on PHP-FPM? | untested (mod_php only) | **structurally impossible on official fpm images: the OOM'd worker exits (code 70) instead of surviving** |
| Do distro packages ship the vulnerable code? | assumed "maybe unpatched" | **all three measured distro stacks are patched** (Ubuntu backport, Debian 8.2.35, Alpine 8.3.36) |
| How fast is the patch-lag window closing in the wild? | unknown | **8 of 15 corpus hosts on exploitable versions already upgraded within days; 2 remain on 8.3.35** |

Verdict: the frontier is **real but conditional**. It holds on mod_php/prefork
deployments with the documented config class, under realistic traffic, when two
transport requirements are met (§2). It fails closed on hardened configs,
FPM, and patched distros — and each failure now has a named, measured cause.

---

## 2. Multi-worker reliability (the make-or-break question)

Setup: `php:8.3.35-apache`, `MaxRequestWorkers 25`, `KeepAlive On`, full chain
(stage 1 → 2 → 3, proof = command execution), 10 repetitions per scenario
(`lab/mw_test.py`, results `lab/logs/mw-*.json`).

| scenario | full-chain RCE | stage-1 leak | notes |
|---|---|---|---|
| 25 workers, published chain (`Connection: close`) | **0/10** | 3/10 | spray request rarely lands on the OOM-aborted worker; stage 2 never fired |
| 25 workers + keep-alive pinning, idle | **10/10** (median 2.6 s) | 10/10 | one pinned connection = same worker for A and B |
| 25 workers + pinning + 4 churn clients (~400 conn/s) | **0/10** | 10/10 | leaks reliable; stage 3 loses the fresh-worker race every time |
| 25 workers + pinning + 8 keep-alive clients (~160 req/s, realistic) | **4/10** single attempt | 10/10 | the realistic-traffic baseline |
| same + the exploit's standard 5 stage-3 attempts | **10/10** (median 5.2 s) | 10/10 | retry loop compounds the per-attempt win probability |
| 25 workers + pinning + 1 churn client @5 conn/s | 0/10 (1 attempt), 0/10 (5 attempts) | 10/10 | connection churn poisons stage 3 even at low rates |

**Mechanism (named).** Stage 3 requires a worker whose heap has served no
request since fork ("virgin worker"): on a dirty worker the payload's groom
lands wrong and request 2 returns a clean `200` instead of the crash signature
(verified by instrumented diagnosis, `lab/diag_mw.py`). `rotate()` creates a
virgin worker by killing the current one; the race is *who connects to the
respawned worker first*. Under connection-churn traffic, background connections
always win; under keep-alive traffic (real browsers, CDNs, health checks)
existing connections stay bound to their workers and the chain's reconnect wins.

**Field recipe (copyable).** On mod_php/prefork targets:
1. run the whole chain on **one HTTP/1.1 keep-alive connection** (`lab/ka_target.py`);
2. keep the exploit's standard **5× stage-3 retry loop**;
3. expect reliability proportional to the server's *new-connection rate*, not
   its request rate — keep-alive-dominant traffic = high reliability;
   connection-churn traffic needs pool-pinning (hold workers on idle
   keep-alive connections) and remains the weaker case (measured 0/10 even
   with pinning, because queued background connections claim the fresh worker).

---

## 3. `display_errors=Off` — the honest gap

Measured on `php:8.3.35-apache` with `display_errors=Off`
(`lab/de0_test.py`, `lab/logs/de0-8335.json`):

* Off is confirmed (no error output rendered).
* Upstream's display_errors-independent A-primitive (their
  `NO_DISPLAY_ERRORS.md` §4.4, tuned on 8.4.26: OOM inside
  `php_session_send_cookie` so `PS(send_cookie)` survives) **does not transfer
  to 8.3.35**: request B returned a valid 32-byte session id — no leak.
  Every count in the shape is 8.4.26-heap-specific and shifts with the
  `zend_object.extra_flags` structural delta.
* Upstream's own research log **ends unsolved** on the next problem — the
  stage-1 B forged-string page-alignment (their §5.3, "not hitting") — even on
  8.4.26 where their A works.

**Status: the display_errors=Off chain is open research for everyone.** The
blocker is decomposed and named: (a) per-build A-shape recalibration
(method exists: gdb at `php_session_reset_id`, measure `real_size == limit`,
`free_slot[bin] == NULL`, zero free pages); (b) the B-alignment problem,
unsolved upstream. Our amd64 8.4.26 build is the first candidate for finishing
(b), since its A already works.

---

## 4. PHP-FPM — structural blocker, plus the offsets method

* **The chain cannot work on the official `php:8.3.35-fpm` image**: a
  pre-RINIT memory exhaustion during multipart parse makes the FPM child
  **exit (code 70, `fpm` log line `child exited with code 70`)** instead of
  surviving like a mod_php worker. The cross-request dangling state stage 1
  depends on can never accumulate. Causality verified: 12 MiB *form field*
  (memory-resident) → fatal + child exit; 12 MiB *file upload* (disk-streamed)
  → clean 200, no exit (`lab/fpm_diag.py`, compose in `lab/fpm-lab/`).
  This is a worker-lifecycle fact of the FPM SAPI, not a heap-layout
  mismatch — recalibration cannot fix it.
* For future FPM work (if a build where the child survives appears):
  `zif_system` is **not exported** by the stripped `php-fpm` binary, but it is
  recoverable deterministically from the internal-function table: find the
  `"system"` string vaddr, locate the `R_X86_64_RELATIVE` relocation whose
  addend equals it (the entry's name field), and read the next relocation —
  the handler pointer. On `php:8.3.35-fpm`: `zif_system = 0x489540`,
  `zval_ptr_dtor = 0x57c110` (dynamic export).

---

## 5. Distro packages and the patch-lag window (third-party, non-destructive)

**Distro stacks (local containers, no third-party contact):**

| stack | package | PHP banner | fix status |
|---|---|---|---|
| Ubuntu 24.04 LTS | `php8.3 8.3.6-0ubuntu0.24.04.13` | 8.3.6 | **patched** — backport `CVE-2026-109618_109619.patch` (source-verified: `PS(in_rfc1867_update)` + `PG(modules_activated)` guard present) |
| Debian 12 bookworm | `php8.2 8.2.35-1~deb12u1` | 8.2.35 | **patched** — exactly the upstream fixed release |
| Alpine latest | `php83-8.3.36-r0` | 8.3.36 | **patched** — exact upstream fixed release |

Implication: the exploitable population is hosts on **upstream tarball /
Docker official image / php.net Windows builds**, or distro hosts that have
not applied security updates — not current distro packages.

**In-the-wild patch lag (15 corpus hosts recorded on exploitable versions,
re-probed days later — 1 GET + 1 small POST each, no OOM/crash):**

| re-probe result | count |
|---|---|
| already upgraded to a fixed release (8.3.36 / 8.4.27 / 8.5.12) | **8** |
| still confirmed on an exploitable version (8.3.35) | **2** |
| version no longer confirmable (redirects, 4xx, unreachable) | 5 |

Zero hosts rendered PHP errors (no display_errors evidence). Hostnames are
withheld deliberately — they are third parties; the measurement is the point.
The exploitable window is real but **measurably short**: the majority of
exposed hosts in this small sample patched within days.

---

## 6. What this does and does not claim

* **Does:** the five-version frontier survives its first realistic-condition
  stress test; the multi-worker failure mode and its fix are measured; the
  FPM and display_errors=Off boundaries are structural and named; distro
  packages are patched; the wild patch-lag window is measured.
* **Does not:** no third-party host was exploited or crashed; no HTTPS/L7-WAF
  interference was tested (all lab runs were plain HTTP); Windows mod_php and
  LiteSpeed SAPIs remain uncalibrated; the display_errors=Off chain remains
  open research (upstream included).
