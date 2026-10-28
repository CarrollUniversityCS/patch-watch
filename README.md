# patch-watch

Passive, non-intrusive measurement of how quickly Wisconsin's nonfederal .gov websites
patched PHP2Shell (CVE-2026-109618 / CVE-2026-109619, fixed upstream October 21, 2026):
a census of the state's .gov entities, an archived "before" from Common Crawl, a 2024
benchmark, and optional neighbouring-state comparisons. One ordinary homepage GET per
domain per snapshot. Tribal nations' sites are not measured. Research by Jack Forden,
Carroll University.

**Opt out: email jforden@carrollu.edu with your domain; it is removed within 24 hours,
no questions asked.** (Public notice: `docs/project_page.md`, published as the README at
https://github.com/JForden/JForden.)

**Status: Gate A is closed. No live request has ever been sent from this repo.** Every
live-style number it has produced came from the loopback mock rig in
`tests/mock_server.py`. The IRB determined on 2026-10-23 that this is not human-subjects
research (`docs/IRB_DETERMINATION.md`). The design is pre-registered in
`docs/analysis_plan.md`, **frozen as v1.0 on 2026-10-23** before any data was collected.
From then on, any change to it or to the code that decides results is logged in its §12.

## The questions

`docs/analysis_plan.md` §1, in brief:
- How much of the population discloses a rankable PHP version (`VISIBILITY = V / P`)?
- What share was exposed before disclosure?
- How fast did entities exposed when first seen reach a fixed release?
- How much of that is one hosting provider's upgrade?
- How does it compare with the 2024 benchmark and with neighbouring states?

Absence of a version header does **not** mean a site is patched. Many hardened or proxied
sites hide it, and distros can backport a fix without changing the version string.

## Layout

| Path | What it holds |
| --- | --- |
| `src/config.py` | Every knob and every hard limit, including `LIVE_REQUESTS_ENABLED`. |
| `src/versions.py` | The fixed-version tables, as `PatchEvent`s: PHP2Shell (8.5.12, 8.4.27, 8.3.36, 8.2.35), the CVE-2024-4577 benchmark, and the not-yet-published CVE-2026-115560 threshold. |
| `src/frame.py` | The national pilot frame from CISA's public .gov list (pilot paused, plan D2). |
| `src/wi_frame.py` | The Wisconsin census frame (plus optional comparison states), from the registry pinned to one commit and hash; tribal and federal rows excluded. |
| `src/baseline_cc.py` | Archived "before" and the 2024 benchmark from Common Crawl. It contacts Common Crawl only, never a .gov host. |
| `src/hosting.py` | Host clusters by IP and ASN, from a local public IP-to-ASN table. |
| `src/analyze.py` | Every pre-registered outcome, sensitivity analysis and suppression rule, written to `reports/analysis_*.md`. |
| `src/fetch.py` | The crawler, and the only place the hard rules are enforced: approved-set containment, budget, redirect policy, no cookies, 64 KB cap, kill switch, request ledger, Gate A. |
| `src/classify.py` | Header/version evidence → one of nine classes (including `NOT_MEASURED`), each with a reason string, against any `PatchEvent`. |
| `src/detect.py` | Version normalisation, change events between snapshots, flapping vs. real upgrades. |
| `src/db.py` | SQLite schema and writes: `domains`, `runs`, `observations`, `request_ledger`, `patch_events`, `meta`. |
| `src/dashboard.py` | The static dashboard: `dashboard/catalog.json` (every vulnerability triaged so far, by measurability tier) plus each live event's patch state, drawn from the committed run reports with the same suppression as `analyze.py`. Writes `dashboard/index.html` from `dashboard/template.html`. A view, not an outcome: domain counts, no network, no database. |
| `src/pipeline.py` | One snapshot end to end: preflight → fetch → classify → store → diff → audit → summary. |
| `scripts/run_snapshot.py` | The wrapper a cron line calls. |
| `scripts/cron.disabled` | The schedule, deliberately commented out (Stage 4 says install it disabled). |
| `tests/` | Loopback and synthetic only, no network (count them with `pytest -q`; 380 at 2026-10-23). `tests/mock_server.py` is the fake web used by all of them; `tests/test_fetch_rules.py` walks hard rules 1-8 and Gate A one enforcement point at a time. |
| `data/` | Frame, sample, database, ledger exports — gitignored. See `data/README.md`. |
| `docs/` | `analysis_plan.md` (the pre-registration), `OPERATIONS.md` (how to run and stop it), `project_page.md` (public opt-out notice, to be published as the GitHub profile README that `PROJECT_URL` and the user agent point at), `IRB_INQUIRY_NOTE.md` and `IRB_DETERMINATION.md`, `HERMES_RUNBOOK.md` (the bounded operator runbook for the live schedule), and `RESEARCH_DIRECTIONS.md` (five candidate follow-on studies and the prior work behind them; not part of the pre-registration). |
| `requirements.txt` | Exact dependency versions. httpx is pinned on purpose (no-cookie guarantee). |
| `blocklist.txt` | Hard rule 5: domains removed from measurement on request. |

## Run it

On Windows, `.venv/bin/python` is `.venv\Scripts\python.exe`.

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -X utf8 -m pytest -q                       # no network, no gate needed

# 1. the Wisconsin frame (downloads the pinned registry from GitHub, checks its hash)
.venv/bin/python -X utf8 src/wi_frame.py build --comparison MN,IL,MI,IA
.venv/bin/python -X utf8 src/wi_frame.py verify

# 2. the archived baseline and 2024 benchmark (Common Crawl only; slow, resumable)
.venv/bin/python -X utf8 src/baseline_cc.py collect --crawls 2026 --region wisconsin
.venv/bin/python -X utf8 src/baseline_cc.py collect --crawls 2024 --region wisconsin
.venv/bin/python -X utf8 src/baseline_cc.py coverage

# 3. rehearse and check guards (loopback only)
.venv/bin/python -X utf8 src/pipeline.py --mock --limit 20 --db data/mock_smoke.db --label SMOKE1
.venv/bin/python -X utf8 src/pipeline.py --mock --preflight-only --sample data/wi_frame.csv

# 4. live (refuses until Gate A opens): two separate runs a day, Wisconsin first
.venv/bin/python -X utf8 scripts/run_snapshot.py --sample data/wi_frame.csv --region wisconsin --label WI_S1
.venv/bin/python -X utf8 scripts/run_snapshot.py --sample data/wi_frame.csv --region comparison --label CMP_S1

# 5. the pre-registered analysis (suppressed; --unsuppressed writes to data/ for the PI)
.venv/bin/python -X utf8 src/analyze.py --label WI_d14
```

```bash
# 6. the dashboard (reads dashboard/catalog.json and reports/run_*.md; no network)
.venv/bin/python -X utf8 src/dashboard.py                 # -> dashboard/index.html
.venv/bin/python -X utf8 src/dashboard.py --unsuppressed  # -> data/, PI only
```

Read `docs/OPERATIONS.md` before running anything live: the gate requires both
`LIVE_REQUESTS_ENABLED` and `PATCHWATCH_GATE_A=APPROVED`. The environment marker alone
cannot enable live traffic.

To stop all traffic immediately: `echo "ABUSE_COMPLAINT" > logs/abuse.flag`. Runs refuse
while that marker exists, before any name is resolved.

## The nine classes

`NO_RESPONSE`, `NO_PHP_EVIDENCE`, `PHP_VERSION_HIDDEN`, `PATCHED_UPSTREAM`,
`VULNERABLE_BY_VERSION`, `EOL_UNFIXED`, `POSSIBLY_BACKPORTED`, `UNPARSEABLE`,
`NOT_MEASURED`. These are exactly `classify.CLASSES`. Versions compare as integer tuples,
never as strings, and every class carries a reason string.

`NOT_MEASURED` was added after the 2026-10-23 audit. It covers three cases:
- we did not ask (blocklist, kill switch, budget);
- the site refused us (401/403/429) with no PHP evidence;
- the site returned a 5xx error with no PHP evidence.

It is out of every denominator, which is what the public notice promises. A response
that came with a transport note (a redirect limit, or a certificate read unverified) is
still classified from its headers.

Hard rule 9 ("if a result is ambiguous, classify it as ambiguous and log why") is
satisfied by the reason and detail fields, not by a ninth label: a distro-suffixed
version below the fixed release becomes `POSSIBLY_BACKPORTED` with
`suffix_ambiguous: true` and the distro family recorded, and a version string that exists
but does not parse becomes `UNPARSEABLE` with the string's shape recorded. Nothing is
guessed at in either case.

## Hard rules, in one line each

1. **Passive only** — a homepage GET and nothing else; no exploits, probes, fuzzing, port scans, logins, or off-list domains.
2. **Budget** — three budget-charged *phases* per domain per day, which is normally one request: `https`, then `https_unverified` only after a certificate-verification failure, then `http_fallback` only if HTTPS never responded (a DNS failure excludes it). Each phase may follow at most 3 same-registrable-domain redirects and those hops are not charged against the phase cap, so the hard ceiling a site can see is 3 x 4 = 12 requests in a day; never cookies; read 64 KB then discard; never store bodies.
3. **Identify yourself** — declared user agent, never a browser impersonation.
4. **Rate limits** — 20 concurrent overall, 1 per resolved IP, 0.1–0.5 s jitter, 10 s/20 s timeouts, back off on 429/503.
5. **Opt-out**: requests to jforden@carrollu.edu, honoured within 24 hours, no verification. `blocklist.txt` is loaded before every run. Tribal nations are excluded by design (`config.EXCLUDED_DOMAIN_TYPE_PREFIXES`).
6. **Kill switch**: halt when more than 10% of a rolling 50 outcomes are 429/5xx (overload) or more than 30% are 401/403 (blocked broadly), on any abuse complaint (the flag is re-read before every domain), or when the ledger cannot be reconciled with rule 2. Fetch order is shuffled per run with a recorded seed.
7. **Data handling** — local only; per-domain results to the PI only; aggregate counts in reports.
8. **Human gate** — no live request to a government domain before "GATE A APPROVED".
9. **No guessing** — ambiguous means ambiguous, with the reason logged.

## Reproducing the numbers

**Wisconsin frame.** The registry is pinned to `cisagov/dotgov-data@718c7ac8`, sha256
`f1bf7313…cddd62`. `src/wi_frame.py` refuses any other bytes, and
`data/wi_frame_meta.json` records the counts, the exclusions and the frame's own hash.
Archived captures keep their WARC filename, offset and length, so any baseline row can be
re-fetched from Common Crawl. The national pilot is described below.

`data/frame_meta.json` records the source URL, access date (`2026-10-22`), byte count and
SHA-256 of the CISA list the frame was built from, plus the seed (`20261022`) and stratum
floor (40) used to draw `data/pilot_sample.csv` (319 domains) from the 15,614-domain
frame. Every run writes a request ledger (`data/ledger_<run_id>.csv`) so a reported count
can be traced back to the requests that produced it.
