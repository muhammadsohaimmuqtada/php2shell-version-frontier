# The RCE question, answered consistently

**Applies to:** every target in this engagement, and to every host in `results/domains.jsonl`.

The assessment has been answering two different questions and labelling them the same.
This file states the question that was actually being asked — *can RCE be achieved on
this host?* — and the evidence ladder that answers it without overclaiming.

---

## The question

> Is this host remotely exploitable for code execution via CVE-2026-109618 /
> CVE-2026-109619?

Note what this is **not**: "does the banner fall in an affected version range". That is a
proxy, it answers a prevalence question, and it is the question `results/domains.jsonl`
and the headline numbers in `FINDINGS.md` currently answer.

## The ladder

| level | claim | how it is established | what it does NOT establish |
|---|---|---|---|
| **L0** | advertised version is in an affected range | `X-Powered-By` / `Server` banner | that PHP is reachable at all, that the code path exists, or that the build is unpatched |
| **L1** | the vulnerable code path is reached and does work | the request provably reaches PHP and the vulnerable parser/allocator executes | that the corruption is reachable in the exploitable window |
| **L2** | the corruption window is hit | the startup-phase OOM marker (`Allowed memory size … exhausted … in Unknown on line 0`) | that the build is unpatched, or that execution is controllable |
| **L3** | the running build is unpatched | package changelog, vendor advisory, or the absence of any backport for that branch | that exploitation succeeds — the corruption is heap-dependent |
| **L4** | code execution is demonstrated | an observable side effect of executing code | — |

**L0 + L3 ⇒ RCE is plausible.** **L1 + L2 + L3 ⇒ RCE is highly plausible.**
**L4 is the only level that *proves* it.**

## Levels are not independent

The most common failure mode in this engagement is treating them as a single score.

* **L0 without L1 is the big one.** A host can advertise a vulnerable PHP version and
  have no PHP application reachable at all. The one assessed estate's vhost is the worked
  example: server-wide `PHP/8.0.20`, but every `.php` request is core-404'd before
  mod_php runs. L0 yes, L1 no.
* **L2 without L3 is not proof.** CVE-2026-109618 is RCE *via* OOM corruption during
  request cleanup — the fix makes the cleanup safe, it does not prevent the OOM. A
  backported build produces the identical fatal error while being non-exploitable.
  This is why the whole "active probing cannot distinguish patched from vulnerable"
  finding in `FINDINGS.md` holds even for a textbook-clean OOM reproduction.
* **L3 without L1/L2 is theoretical.** Branch-level facts about a backport do not
  establish that any request can reach the vulnerable path on that host.

## Where the targets assessed so far sit

| target | L0 | L1 | L2 | L3 | L4 | net |
|---|:-:|:-:|:-:|:-:|:-:|---|
| assessed host D (WordPress) | ✗ version hidden | ✓ PHP ran, all probes returned full pages | ✗ no crash at any part count | — unknown | no | reachable, no crash observed, version unknown — weakest of the four |
| assessed host C (mod_php 8.0.20) | ✓ | ✓ | ✓ startup-phase marker | ✓ no patched 8.0 release exists; vulnerable pattern confirmed in the upstream source | no | **strongest**: L1+L2+L3 all satisfied |
| assessed host B :443 (FPM 5.6.40) | ✓ | ✓ allocation proven (4.3 ms/part) | ✗ nginx caps body at 1 MB | ✓ no patched 5.6 release exists; vulnerable pattern confirmed in the upstream source | no | unpatched and the path works, but the request is byte-starved |
| assessed host A :8080 (Apache 8.1.17) | ✓ | ✓ | ✓ startup-phase marker | ✓ for the upstream release — 8.1.17 predates the backport and no 8.1.35 was ever released | no | crash confirmed; upstream patch state resolved, distribution backport still possible |

### L3 for the EOL branches, established from source

L3 was previously "unknown" for 8.1 because upstream publishes backports for
that branch. Diffing the `php-src` tags settles it: the fix (in 8.2.35 /
8.3.36 / 8.4.27 / 8.5.12) removes a session decode/encode that ran during
multipart parsing, before RINIT. That pattern is present in the upstream
sources of **5.6.40, 7.4.33, 8.0.30, 8.1.34, 8.2.34, 8.3.35, 8.4.26 and
8.5.11**, and 8.1.17 / 8.0.20 / 5.6.40 predate it. No EOL branch ever got a
tagged fixed release (7.4.33, 8.0.30 and 8.1.34 are the last releases of
theirs), so for those versions L3 holds for the *upstream* build. The only
remaining escape hatch is a distribution backport, which is invisible in the
banner.

## The measured RCE frontier (L4, in the lab)

L4 was not pursued on any assessed host — that would be an intrusion, not a
measurement. It *was* pursued in disposable local containers, against the
published chain, to answer a different question: **which PHP versions can
actually be turned into code execution today?** Full method and artifacts:
`RCE_COVERAGE_MATRIX.md`.

| build | L1 | L2 | L3 | L4 (lab) |
|---|:-:|:-:|:-:|:-:|
| 8.4.25, 8.4.26, 8.5.10, 8.5.11 | ✓ | ✓ | ✓ | **✓ code execution demonstrated** |
| 8.3.35 | ✓ | ✓ | ✓ | **✓ code execution demonstrated** (HTDATA = chunk + 0x6a0d8, 15-byte carrier; `lab/logs/carrier-8335-p192.log`) |
| 8.2.34, 8.1.34, 8.0.30, 7.4.33 | ✗ | ✗ | ✓ | ✗ |
| 8.1.17, 8.0.20, 5.6.40 *(this engagement's builds)* | ✗ | ✗ | ✓ | ✗ |

Two consequences:

1. **The RCE frontier is five versions wide** (8.3.35, 8.4.25, 8.4.26, 8.5.10,
   8.5.11). Everything else — including
   every build observed on this engagement's targets — is code-vulnerable but
   not currently RCE-proven. That is a research gap, not a safety margin, and
   it is the space where a new contribution would live.
2. **L3 is now the binding constraint for most hosts.** The code is provably
   vulnerable in the release they are running; what is missing is a working
   chain for that specific build.

## Answering the question uniformly

For any new host, record all five levels. Do not collapse them into "vulnerable" / "not
vulnerable", and do not let an L0 banner stand in for the rest.

The portfolio-level answer this engagement can currently give is:

* **L0 across the corpus:** 375 of 53,744 resolved domains (the "vulnerable" figure in
  `FINDINGS.md`). This is a prevalence number, not an exploitability number.
* **L1/L2/L3 per target:** only for hosts that have been probed individually.
* **L4:** not established for any target — and not obtainable there without the
  owner's involvement. In the lab, L4 is established for exactly four PHP
  versions (8.4.25, 8.4.26, 8.5.10, 8.5.11); every other version tested is
  code-vulnerable but not RCE-proven.

So the honest summary of the engagement is *not* "375 hosts are vulnerable to
php2shell". It is: **375 hosts advertise an affected PHP version; on the hosts where
the path was tested, the vulnerable allocation path is reachable and the startup-phase
corruption window is hit; the running build's patch state is now established from
upstream source for the exact releases involved; and demonstrated RCE exists only
for a narrow four-version frontier, none of which is the version any assessed target
advertises.**

## Why L4 is not pursued here

L4 means executing code on the target. On infrastructure the assessment does not own,
that is not a measurement — it is an intrusion, regardless of how the measurement
started. It also requires clear authorization from the asset owner for every target.

It is achievable, and the machinery is not secret:

* The OOM itself is trivially reproducible (as shown) and is the trigger the public
  research identifies. Steering the resulting corruption into controlled execution
  requires heap grooming, which is why exploitation is probabilistic rather than
  one-shot — the same reason the vendor advisory and CERT-EU describe the bugs as
  "can allow" RCE rather than guaranteeing it.
* For an authorised engagement, the practical order is: confirm the running build is
  unpatched (L3, via package changelog), then reproduce the startup-phase OOM against
  the real asset (L2) with a harmless marker that proves code ran, rather than a shell.
  A marker file or a `phpinfo()` write is enough for L4 and far less damaging than a
  shell.
* The public ecosystem has deliberately not shipped a turnkey exploit: NCSC-NL's repo
  carries no payload, Corelight/CrowdStrike/Talos publish detection, and the Nuclei
  template is tagged `intrusive` because it triggers the OOM, not because it achieves
  execution.

If a target is owned or in scope, the L3/L4 steps can be specified precisely for it —
that is a different engagement from this one, and the right way to run it is with the
owner's involvement from the start.
