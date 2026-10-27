# PHP critical RCE exposure — measurement and findings

**CVE-2026-109618** (RCE via OOM corruption) and **CVE-2026-109619** (RCE via
stale global state). Disclosed 2026-10-21. Fixed in **8.2.35 / 8.3.36 /
8.4.27 / 8.5.12**. PHP ≤ 8.1 has no upstream fix; 8.2 goes EOL 2026-12-31.

Measurements below were produced 2026-10-22/23 with the tooling in
`php2shell-tools/`.

---

## Headline numbers

### Domain frame (website-weighted) — 60,000 Tranco top-1M domains

53,744 domains resolved → 42,588 unique IPs (shared-hosting multiplier 1.262).

| | count | share |
|---|---:|---|
| Domains exposing a PHP signal | 738 | 1.37% of resolved domains |
| … with a readable version | 519 | 70.3% of PHP domains |
| **Vulnerable** | **375** | **79.4% of classified** |
| Fixed | 97 | 20.6% of classified |
| Unknown (version present, branch ambiguous) | 47 | — |

Of the 375 vulnerable, **319 (85.1%) are on branches that will never receive
an upstream fix**:

| Branch | Vulnerable | Fixed | Upstream fix? |
|---|---:|---:|---|
| 5.4 / 5.5 / 5.6 | 33 / 14 / 60 | 0 | **none — EOL** |
| 7.0 / 7.1 / 7.2 / 7.3 / 7.4 | 11 / 12 / 29 / 25 / 93 | 0 | **none — EOL** |
| 8.0 / 8.1 | 18 / 24 | 0 | **none — EOL** |
| 8.2 | 19 | 35 | yes, 8.2.35 (EOL 2026-12-31) |
| 8.3 | 27 | 33 | yes, 8.3.36 |
| 8.4 | 5 | 13 | yes, 8.4.27 |
| 8.5 | 5 | 15 | yes, 8.5.12 |
| 8.6 | 0 | 1 | postdates the patch |

**Only 56 of 375 vulnerable sites (15%) are on a branch that could still be
patched.** The other 85% are permanently exposed regardless of how urgently
anyone upgrades.

### IP frame — random IPv4, calibrated

| concurrency | reachable rate on 80/443 |
|---|---|
| 200 | 1.19% |
| 250 | 1.17% (over 40k pairs) |
| 800 | 0.60% |
| 3000 | 0.10% |

1.2% of random IPv4 address:port pairs answer on 80 or 443, and ~2.3% of
those responders run PHP.

### Synthesis with the published industry figure

Unit 42 (Cortex Xpanse telemetry) published **22.6M exposed PHP instances**
on 2026-10-21, without disclosing methodology. Combining that population with
the version distribution measured here:

* **≈ 11.5M–18M vulnerable PHP instances.** Lower bound treats the 219
  versionless sites as not-vulnerable (375/738 = 50.8%); upper bound applies
  the classified 79.4% rate to the whole population.
* **≈ 10M–15M of those have no upstream fix available, ever.**

Treat these as an order-of-magnitude range, not a precise count. The 22.6M
figure is version-level with undisclosed methodology; this report's 79.4% is
measured on a popularity-weighted sample of established sites and therefore
skews *older* than the general corpus (Cisco Talos estimates ~50% of the PHP
corpus will never be patched, against 85% here).

---

## The six findings that actually matter

### 1. "Unpatched level" is not externally observable

Patch releases do not change banners, and distros backport fixes without
bumping the upstream version. `X-Powered-By: PHP/8.3.35` on Ubuntu may carry
the backported fix; `PHP/8.3.36` on a hand-built box may not.

The header does carry the **full patch version** (`PHP/8.3.35`, not just
`8.3`) — confirmed from `main/SAPI.h`:
`#define SAPI_PHP_VERSION_HEADER "X-Powered-By: PHP/" PHP_VERSION` — and
`expose_php` defaults to `On` in *both* php.ini-production and
php.ini-development for 8.2–8.5. So advertised patch level is reachable, but
it is advertised patch level, not actual patch level.

**Consequence:** every index count is a count of *advertised upstream
version*. Say so, or the number is wrong.

### 2. Active probing cannot distinguish patched from vulnerable PHP

Assetnote reproduced the **same empty HTTP 500** on *patched* PHP 8.4.27 with
`memory_limit` 2M–32M, and on patched 8.3.36 at 128M with
`max_multipart_body_parts >= 2785`. A bare 500 is not a vulnerability signal.

Cloudflare reached the same conclusion independently, and it is why they built
**response-side transaction detection** for this: "Request data alone does not
always provide enough evidence to distinguish an exploit from legitimate
traffic."

### 3. The high-fidelity detector is log-based, not HTTP-based

`Allowed memory size of N bytes exhausted` together with **`in Unknown on
line 0`** — CrowdStrike's marker for an OOM that fired *before any application
code ran*. Reproduced locally against PHP 8.4.24:

```
PHP Fatal error:  Allowed memory size of 33554432 bytes exhausted
(tried to allocate 20480 bytes) in Unknown on line 0
```

Critically, this lands in the **server error log**. The HTTP response is an
empty 500. An HTTP-only probe can see the differential but can never reach a
confident verdict — my probe deliberately reports `SUSPICIOUS`, never
`LIKELY_VULNERABLE`, on an empty 500.

### 4. The amplifier, verified

Reproduced end-to-end locally:

* `Transfer-Encoding: chunked`, no `Content-Length` — PHP compares
  `post_max_size` against the *declared* length, so chunked requests bypass it.
* Many RFC1867 parts, **empty filename**, **63-level nested field name**.
  Empty-filename parts are not counted against `max_file_uploads` but still
  allocate all six `$_FILES` entries plus the nested array hierarchy.

| parts | result (PHP 8.4.24, memory_limit 32M, max_file_uploads 20) |
|---|---|
| 1 | `$_FILES=1`, peak 2 MiB |
| 100 | `$_FILES=100` — **limit bypassed**, peak 16 MiB |
| 400 | startup-phase OOM, `in Unknown on line 0` |

Two traps found the hard way: a nested name ending in a numeric index
(`a[a][a]0`) is parsed as an array index and the whole variable is discarded —
use a unique *leaf* (`f0[a][a]...`); and depth 64 exceeds
`max_input_nesting_level`.

### 5. Reachability is narrower than "PHP"

* **mod_php** — confirmed exploitable, fires before any application code
  runs, returns HTTP 200.
* **PHP-FPM** — confirmed RCE for CVE-2026-109619; suspected for
  CVE-2026-109618. Observable is worker restart, not memory corruption.
* **FrankenPHP** — likely susceptible. **LSAPI** — suspected, unvalidated.

CrowdStrike's additional reachability condition: **`memory_limit < 4 ×
post_max_size`**. Shipped defaults (8M / 128M) do not satisfy it, but
`post_max_size=64M` with `memory_limit=128M` does — and `post_max_size` is
settable per directory in `.htaccess`, so one site on shared hosting can make
itself reachable alone.

### 6. Scanner calibration is not optional

Connection loss under high concurrency silently under-counts, and the error is
proportional to concurrency, not to the target population:

| concurrency | reachable rate | error |
|---|---|---|
| 200–250 | ~1.18% | baseline |
| 800 | 0.60% | −49% |
| 3000 | 0.10% | **−91%** |

A full 500,000-address scan run at concurrency 3000 reported a 0.197%
response rate — roughly a **6× under-count** — and would have produced a
correspondingly wrong prevalence number. Validate against a raw-socket
baseline on the identical sample before publishing any rate.

---

## What is actually exploitable — the measured RCE frontier

Version strings tell you whether the *code* is vulnerable. They tell you
nothing about whether anyone can turn it into code execution. That gap was
measured directly, in disposable local containers, with the published
`devploit/php2shell` chain (method and artifacts in `RCE_COVERAGE_MATRIX.md`).

| build | stage 1 (heap leak) | stage 2 (libphp leak) | stage 3 (code execution) | RCE |
|---|---|---|---|---|
| 8.3.35, 8.4.25, 8.4.26, 8.5.10, 8.5.11 | ✅ | ✅ | ✅ | **yes** |
| 8.2.34, 8.1.34, 8.0.30, 7.4.33 | ❌ | ❌ | ❌ | no |
| 8.1.17, 8.0.20, 5.6.40 *(builds seen on this engagement's targets)* | ❌ | ❌ | ❌ | no |

RCE was recorded only when the container executed a command and the proof
file was read back out of the container.

Three results matter for the exposure numbers above:

1. **The RCE frontier is five versions wide.** `8.3.35`, `8.4.25`, `8.4.26`,
   `8.5.10`, `8.5.11` — `8.4.25` / `8.5.10` had only been published for
   aarch64 and we reproduced code execution on amd64, and `8.3.35` (the last
   8.3 release) had no public stage-3 offset at all: the fake-`zend_hash`
   carrier must be aimed at `chunk + 0x6a0d8` on that build, measured by gdb
   crash forensics and confirmed by three independent containers
   (`lab/logs/repro-8.3.35-rce.json`, `RCE_COVERAGE_MATRIX.md` §4.4).
   Everything else is unproven.
2. **"Unpatched" and "exploitable" are different questions.** The vulnerable
   `ext/session/session.c` pattern (session decode/encode executed during
   multipart parsing, before RINIT) is present in upstream 5.6.40, 7.4.33,
   8.0.30, 8.1.34, 8.2.34, 8.3.35, 8.4.26 and 8.5.11, and is removed only in
   8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. The residual versions are therefore
   code-vulnerable but not RCE-proven — a research gap, not a safety margin.
3. **No EOL branch ever received a fixed release.** 7.4.33, 8.0.30 and
   8.1.34 are the last releases of their branches and all carry the
   vulnerable code; the backports PHP published for those branches exist only
   as source patches. Only a *distribution* backport protects a deployed
   7.4/8.0/8.1 host, and that is invisible in the version banner.

A corollary for the remediation section: upgrading is the only complete
answer, and on 7.4/8.0/8.1 "upgrade" means a vendor rebuild, not a version
bump.

---

## Why an index, not a scan, is the right primary method

Precise patch-level counts come from pre-collected indexes. The query
dialects have traps that silently return nonsense if you get them wrong:

* **LeakIX** — terms are OR'd by default; every term needs a `+` prefix or
  the query returns the entire PHP corpus. Version comparison is
  **lexicographic**, not numeric: `>8.3.35` also matches `8.3.4`, and
  `8.3.40` does not exist. Enumerate exact patch versions.
* **Shodan** — there is no `http.x_powered_by` filter and no `http.server`
  filter (only `http.server_hash`, a fingerprint). Use
  `http.component:"PHP"`. No regex, no version ranges; `version:` is an exact
  keyword match. Use `/shodan/host/count` — it does not consume query credits.
  If Shodan has fingerprinted the CVEs itself, `vulns:CVE-2026-109618` is
  the closest thing to a direct answer.
* **Netlas** — the only free index with correct numeric ranges:
  `tag.php.version:[8.3.0 TO 8.3.35]`. Free tier: 50 requests/day.
* **Censys** — regex is a paid feature (Starter+). Free tier has no regex,
  no `software.*` context data, 100 credits/month.
* **FOFA** — base64-encode the whole query; free tier is non-commercial.
* **PublicWWW** — headers indexed as source text, but HTML is bot-protected.

`php_index_queries.py` encodes all of these with the traps already handled.

---

## Detection to deploy now

| Source | Artifact | Cost |
|---|---|---|
| Corelight | `github.com/corelight/php2shell-detect` — Zeek package + Suricata SIDs 3000650/3000651/3000652 | free, MIT/Apache |
| Cisco Talos | Snort SIDs 67359, 67360, 67375 | free Community Ruleset |
| Cloudflare | 7 rules free managed ruleset, 7 paid | free with WAF |
| Unit 42 | threat IDs 543004, 97622–97625 | commercial |
| OpenAI | `github.com/openai/php2shell-checker` — version-only, no probes | free |
| Nuclei | `http/cves/2026/CVE-2026-109618.yaml` | free (**tagged intrusive**) |

Highest-signal request marker: the literal string **`PHP_SESSION_UPLOAD_PROGRESS`**
in a multipart POST body — rare in benign traffic.

---

## Remediation

Upgrade to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 and restart every worker. There
are no complete mitigations.

Partial exposure reduction while you upgrade:

* `memory_limit=-1` enforced via `php_admin_value` in the FPM pool or Apache
  config — not via `ini_set()` or `.user.ini`. **Do not** use `RLIMIT_AS` /
  `RLIMIT_DATA`: mmap failure re-enters the vulnerable `longjmp()` path.
* Low `post_max_size`, plus frontend limits on decoded request size, field
  count, multipart part count, per-part header count and nesting depth —
  covering requests with no usable `Content-Length`.
* `session.upload_progress.enabled=0`; on PHP 8.5 also
  `fatal_error_backtraces=0`. Applied in `php.ini` or the pool, then restart
  every worker.
* A cgroup `memory.max` boundary, per worker rather than per container.
* `pm.max_requests=1` where performance allows — limits cross-request worker
  reuse, which is the CVE-2026-109619 mechanism.

Changing `error_reporting`, `display_errors` or `log_errors`, or using `@`,
provides no protection.

---

## Files

```
php2shell-tools/
  php_verdict.py         version parsing + patch-level verdict (19/19 tests pass)
  php_scan.py            non-invasive IP-frame scanner
  php_domain_scan.py     domain-frame scanner (DoH resolver)
  php_probe.py           authorized-scope behavioural verification
  php_index_queries.py   patch-level counts from search indexes
  README.md              usage, query dialects, mitigation reference
results/
  domains.jsonl          53,744 domain records with PHP banners and verdicts
  domains.summary.json   domain-frame aggregate
  ipframe_500kaddresses.summary.json   IP-frame aggregate
RCE_COVERAGE_MATRIX.md   measured RCE frontier + residual version set (lab)
RCE_EVIDENCE_LADDER.md   L0-L4 evidence ladder used to grade every target
lab/
  run_matrix.py          RCE matrix driver (disposable local containers)
  sweep_stage1.py        stage-1 parameter sweeps (N, forge length, value length)
  sweep_stage3.py        stage-3 heap-offset sweep (code execution search)
  diag_session.py        raw HTTP/session diagnostics for one build
  matrix-report.json     per-build verdicts
  profiles-ours/         calibration profiles written by this engagement
  logs/                  per-build calibration logs
```

`results/domains.jsonl` lists third-party hostnames with their publicly
advertised PHP versions. The data is public banner information and is
reproducible with the tooling above, but acting on any host in it requires
authorization from its owner.

The `lab/` harness runs only against disposable containers bound to
`127.0.0.1`; it is the tool that produced the RCE frontier table above.
