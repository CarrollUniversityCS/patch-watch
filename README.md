# patch-watch

Passive, non-intrusive measurement of how quickly nonfederal U.S. government (.gov)
websites patch critical vulnerabilities, starting with PHP2Shell
(CVE-2026-109618 / CVE-2026-109619, fixed upstream October 21, 2026). One ordinary
homepage GET per domain per snapshot. Research by Jack Forden, Carroll University;
opt-out honoured within 24 hours.

**Status: Gate A is closed. No live request has ever been sent from this repo.** Every
number it has produced came from the loopback mock rig in `tests/mock_server.py`.

## The question the pilot answers

Can patch behaviour be observed at all by reading headers a server volunteers, and is
enough of this population observable (`VISIBILITY = domains with a parseable version /
domains with PHP evidence`) to justify a daily study? Absence of a version header does
**not** mean a site is patched — many hardened or proxied sites hide it, and distros can
backport a fix without changing the version string.

## Layout

| Path | What it holds |
| --- | --- |
| `src/config.py` | Every knob and every hard limit, including `LIVE_REQUESTS_ENABLED`. |
| `src/versions.py` | The fixed-version table, single source of truth: 8.5.12, 8.4.27, 8.3.36, 8.2.35. |
| `src/frame.py` | Builds the frame from CISA's public .gov list; drops federal-type domains. |
| `src/fetch.py` | The crawler, and the only place the hard rules are enforced: approved-set containment, budget, redirect policy, no cookies, 64 KB cap, kill switch, request ledger, Gate A. |
| `src/classify.py` | Header/version evidence → one of nine classes, each with a reason string. |
| `src/detect.py` | Version normalisation, change events between snapshots, flapping vs. real upgrades. |
| `src/db.py` | SQLite schema and writes: `domains`, `runs`, `observations`, `request_ledger`, `patch_events`, `meta`. |
| `src/pipeline.py` | One snapshot end to end: preflight → fetch → classify → store → diff → audit → summary. |
| `scripts/run_snapshot.py` | The wrapper a cron line calls. |
| `scripts/cron.disabled` | The schedule, deliberately commented out (Stage 4 says install it disabled). |
| `tests/` | 303 tests, loopback only. `tests/mock_server.py` is the fake web used by all of them; `tests/test_fetch_rules.py` walks hard rules 1-8 and Gate A one enforcement point at a time. |
| `data/` | Frame, sample, database, ledger exports — gitignored. See `data/README.md`. |
| `docs/` | `OPERATIONS.md` (how to run and stop it), `project_page.md` (public opt-out page draft), `IRB_INQUIRY_NOTE.md`. |
| `blocklist.txt` | Hard rule 5: domains removed from measurement on request. |

## Run it

```bash
# the test suite — no network, no gate needed
.venv/Scripts/python.exe -X utf8 -m pytest -q

# a loopback rehearsal snapshot
.venv/Scripts/python.exe -X utf8 src/pipeline.py --mock --limit 20 --db data/mock_smoke.db --label SMOKE1

# check every guard without sending anything
.venv/Scripts/python.exe -X utf8 src/pipeline.py --mock --preflight-only

# live (refuses until Gate A opens)
.venv/Scripts/python.exe -X utf8 scripts/run_snapshot.py --label SNAP_A
```

Read `docs/OPERATIONS.md` before running anything live: the gate condition in code is
`LIVE_REQUESTS_ENABLED or PATCHWATCH_GATE_A=APPROVED`, which is one key, not two.

To stop all traffic immediately: `echo "ABUSE_COMPLAINT" > logs/abuse.flag`. Runs refuse
while that marker exists, before any name is resolved.

## The eight classes

`NO_RESPONSE`, `NO_PHP_EVIDENCE`, `PHP_VERSION_HIDDEN`, `PATCHED_UPSTREAM`,
`VULNERABLE_BY_VERSION`, `EOL_UNFIXED`, `POSSIBLY_BACKPORTED`, `UNPARSEABLE` — these are
exactly `classify.CLASSES`, no more and no fewer. Versions compare as integer tuples,
never as strings, and every class carries a reason string.

Hard rule 9 ("if a result is ambiguous, classify it as ambiguous and log why") is
satisfied by the reason and detail fields, not by a ninth label: a distro-suffixed
version below the fixed release becomes `POSSIBLY_BACKPORTED` with
`suffix_ambiguous: true` and the distro family recorded, and a version string that exists
but does not parse becomes `UNPARSEABLE` with the string's shape recorded. Nothing is
guessed at in either case.

## Hard rules, in one line each

1. **Passive only** — a homepage GET and nothing else; no exploits, probes, fuzzing, port scans, logins, or off-list domains.
2. **Budget** — one GET, at most 3 redirects and only within the same registrable domain, one HTTP fallback, one unverified retry solely to read headers on a cert error; never cookies; read 64 KB then discard; never store bodies.
3. **Identify yourself** — declared user agent, never a browser impersonation.
4. **Rate limits** — 20 concurrent overall, 1 per resolved IP, 0.1–0.5 s jitter, 10 s/20 s timeouts, back off on 429/503.
5. **Opt-out** — load `blocklist.txt` before every run; honour requests within 24 hours.
6. **Kill switch** — halt on >10% bad responses in a rolling 50, on any abuse complaint, or when the ledger cannot be reconciled with rule 2.
7. **Data handling** — local only; per-domain results to the PI only; aggregate counts in reports.
8. **Human gate** — no live request to a government domain before "GATE A APPROVED".
9. **No guessing** — ambiguous means ambiguous, with the reason logged.

## Reproducing the numbers

`data/frame_meta.json` records the source URL, access date (`2026-10-22`), byte count and
SHA-256 of the CISA list the frame was built from, plus the seed (`20261022`) and stratum
floor (40) used to draw `data/pilot_sample.csv` (319 domains) from the 15,614-domain
frame. Every run writes a request ledger (`data/ledger_<run_id>.csv`) so a reported count
can be traced back to the requests that produced it.
