# Status — 2026-10-23, Gate A still closed

Admin note for Jack. Not student-facing, not publishable, no per-domain results in it.

## Where the project stands

Stages 0–5 are complete and internally consistent. Stage 6 (pilot snapshots A and B)
cannot start until Gate A opens. **No live request has ever left this repo**; every number
below came from the loopback rig in `tests/mock_server.py`.

| Item | State |
| --- | --- |
| Frame | 15,614 nonfederal .gov domains from CISA `current-full.csv`, accessed 2026-10-22, SHA-256 recorded in `data/frame_meta.json`; 1,321 federal-type domains excluded |
| Pilot sample | 319 domains, 40 per stratum (Interstate contributes all 39 that exist), seed `20261022` |
| Schema | `domains`, `runs`, `observations`, `request_ledger`, `patch_events`, `meta` — all six present and written by real runs |
| Classes | 8, exactly `classify.CLASSES` |
| Tests | **303 collected and passing, no `--ignore` needed**: `test_detect.py` 144, `test_classify.py` 61, `test_mock_server.py` 57, **`test_fetch_rules.py` 41 (new)**. The fetch file covers hard rules 1-8 and Gate A one at a time against loopback only. The delegated attempt was dropped after two hours without a parseable revision and I wrote these myself; the first defect they caught is item 11 below, the second author (detect) caught item 12 |
| Gate A | closed: `LIVE_REQUESTS_ENABLED=False`, no approved marker set; live runs refuse before creating a database file |
| Docs | `README.md`, `docs/OPERATIONS.md`, `docs/project_page.md`, `docs/IRB_INQUIRY_NOTE.md`, `data/README.md`, `logs/optouts.md`, `scripts/cron.disabled` (commented, per Stage 4) |

## What I changed in `src/` this session, and why

1. **`detect.py: detect_changes()` — ordering bug, real.** History was filtered only by
   `run_id != current`, so re-running detection on an older snapshot compared it
   *forward* against a newer row and emitted reversed events. Now strictly earlier by
   `started_at_utc`. Found by delegated child A, confirmed in source, fixed.
2. **`detect.py: is_flapping()` — windowed.** Whole-sequence alternation missed a backend
   that starts rotating after weeks of steady versions; any alternating 4-reading window
   now counts. Both fixes verified against a real SQLite database.
3. **`fetch.py: fetch_many()` — crash containment.** Plain `asyncio.gather` cancels the
   remaining domains the moment one raises: traffic already sent, no observations, no
   ledger. Now `return_exceptions=True` with a `crawler_error: <Type>` observation per
   failed domain (type only — an exception message can carry a URL, and this field is
   exported). Verified: one exploding domain, two survivors, nothing leaked.
4. **`pipeline.py` — the ledger is committed before anything else.** Moved
   `db.insert_ledger` + `commit` to immediately after the network phase so a bug in
   classification, diffing or reporting cannot destroy the audit trail.
5. **`fetch.py: audit_ledger()` — cap and cross-check.** Cap now comes from
   `config.MAX_SENDS_PER_DOMAIN` instead of a hardcoded literal, and the audit compares
   the ledger's distinct phases against the budget counter that authorised them.
   Fewer phases than charges is normal (DNS failure charges before sending, writes no
   row), so it is not reported as a finding.
6. **Rule 1 logging.** `ApprovedSet.check()` and the off-domain redirect branch now emit
   `REFUSING <phase>: <host> — not on approved list (hard rule 1)`; `pipeline.attach_logging()`
   sends it to `logs/capture.log` as UTF-8. Verified end to end.
7. **`tests/test_mock_server.py::test_delay_path_really_delays` — was flaky, twice fixed.**
   It asserted an absolute wall-clock bound (`fast < 0.4 s`) on a plain round trip to the
   session-scoped mock rig. My *first* fix (reorder the control before the sleep case) made
   it pass 4/4 in isolation and it still failed inside the full suite — see corrections.
   The real cause is that 256 other tests share one Python `ThreadingHTTPServer`, so a TLS
   handshake measured 1.96 s under load. Now the test samples the fast path three times,
   keeps the minimum as a floor, and requires the delay case to cost floor + 0.35 s: it
   asserts the sleep rather than the machine's speed. Two consecutive full-suite runs:
   257 passed, 257 passed.
8. **`fetch.py: Ledger.violations()` — documented, not deleted.** It caps rows at
   `cap × (MAX_REDIRECTS+1)` = 12 and has no production caller. It is *not* the rule-2
   audit (redirect hops are rows inside a phase the budget never charges). Docstring now
   says so, because a future maintainer calling it as an audit would be satisfied by the
   wrong ceiling.
9. **Run logs moved `logs/` → `reports/`** (`write_run_log`, plus `docs/OPERATIONS.md`).
   `.gitignore` drops `logs/*` entirely, so the per-run safety audit — the artifact that
   says "this snapshot sent N requests and violated nothing" — was being written to a
   directory that can never be committed or reviewed. `reports/*` with `!reports/*.md` is
   the tracked location, and the run summary is counts-only (a per-domain result never
   leaves the sqlite file). `ALERT_<run_id>.md` is written beside it whenever the kill
   switch or the audit fires. `config.REPORTS_DIR` also stopped being dead code.
10. **Run-summary wording was misleading and is fixed.** It said "HTTP sends recorded: 60 |
    ledger rows: 78", which reads like a contradiction. `runs.sends` is the count of
    *budget-charged phases* (`obs.sends` = the phase sequence number from `Budget.take()`);
    ledger rows also include same-domain redirect hops, which rule 2 permits inside one
    phase and the budget does not charge. It now says so in those words.
11. **`fetch.py` — we were sending cookies. Real hard-rule-2 defect, found and fixed today.**
    `httpx.AsyncClient(cookies=None)` only starts the jar empty. httpx 0.28.1 runs
    `client.cookies.extract_cookies(response)` after **every** response (confirmed in
    `httpx/_client.py`, `_send_single_request`), and the crawler reuses one client across
    same-domain redirect hops. So a site that answered hop 1 with `Set-Cookie` had that
    cookie echoed back to it on hop 2 — a session-state footprint the code comment at
    `src/fetch.py:397` explicitly denies ("deliberately no Cookie header, ever"). Fixed at
    `src/fetch.py:455`: `client.cookies.clear()` after each response.

    Scope of the exposure, so this is not over-read: it never crossed domains (a client is
    built per domain visit inside `Crawler.fetch()`), and it never replayed an HTTPS cookie
    over the plain-HTTP fallback, because that branch requires `not obs.headers_raw` — no
    response, therefore no cookie. And **nothing live was ever affected**: Gate A has been
    closed for the entire project, so the only server that ever received such a header is
    our own loopback mock. `docs/project_page.md:21` promises "We do not send cookies and we
    do not accept them" — accurate as of today, not accurate an hour ago. The page is
    unpublished, so nothing needs retracting outside this repo.

    The test that catches it is
    `tests/test_fetch_rules.py::test_rule2_no_cookie_state_carries_into_the_next_request`:
    a recorder server sets a cookie, redirects, and records every request header it
    receives. Delete line 455 and that test fails. The deck could not catch this — no mock
    case sets a cookie *and* redirects.
12. **`detect.py` — I introduced a false-positive flapping bug while fixing another bug.**
    My windowed rewrite of `is_flapping()` (correction 5 area) tested every window with
    `all(window[i] == window[i+2] and … for i in range(len(window) - 2))`. For a
    **2-reading window** that generator is empty, `all([])` is True, so with
    `min_length=2` every domain with two or more visible readings was called a flapper —
    including one reporting `8.3.35` twice and never moving. Proven, not reasoned: run the
    committed pre-fix file (`git show HEAD:src/detect.py`) and
    `is_flapping(['8.3.35','8.3.35'], min_length=2)` returns True.
    Latent, because every caller so far passes the default 4. Not harmless: `flapping_domains(min_length=2)`
    would have marked the entire frame as backend variance and driven the Stage 7
    "genuine upgrades" count to zero. `min_length` is now floored at 3 (A,B is a change;
    A,B,A is a flap — 2 readings cannot distinguish them), deliberately not clamped up to 3,
    so a caller that asks for 2 gets "no flap provable" instead of a silently different
    window. Found by the delegated detect-test author, which is the first time this session
    a delegation caught something in *my* code rather than the reverse.
13. **`detect.py` — `now_at_or_above_fixed` was vacuously true.** The flag was
    `fixed is None or cv >= fixed`, so on any branch with no published fix (8.1.x, 7.4.x,
    unknown future branches) an upgrade emitted "no official fix exists" *and* "now at or
    above the fixed version" in the same `detail_json`. A Stage 7/8 table reading those two
    flags together would have counted EOL-branch point releases as security fixes. Now
    `fixed is not None and cv >= fixed`. No production consumer existed yet (grep: the only
    reference outside tests is `src/detect.py:216`), so nothing published is affected.

## Corrections, stated loudly

- **The abuse flag works.** I earlier reported that a run went ahead despite
  `PATCHWATCH_ABUSE_FLAG`. That was my harness: I passed a git-bash `/c/...` path, which
  Windows Python read as `C:\c\...`, so the file genuinely did not exist where the code
  looked. With the default `logs/abuse.flag`, the run is refused, the database file is
  never created, and nothing is sent. My report was wrong; the code was fine.
- **The "5xx not counted by the kill switch" report was false.** `KillSwitch.bad()` counts
  `status >= 500` (`src/fetch.py:181-188`). A delegated child's headline finding,
  unverified at the time I repeated it.
- **I inferred a `refused_off_domain` ledger row that does not exist** and built an audit
  concern on top of it. Off-domain redirects are refused before `approved.check()` and
  recorded in `redirect_chain` / `redirect_off_domain`. Retracted.
- **I declared the timing flake fixed on inadequate evidence.** After reordering the
  control request I ran the single test four times, saw 4/4 pass, and wrote "flake fixed".
  It wasn't: the next full-suite run failed the same assertion. Isolated runs don't
  reproduce the condition that breaks it, because the cause is contention on the
  session-scoped rig from the other 256 tests. The fix above is the second one and is
  verified in suite context, not in isolation.
- **Several of my own numbers were wrong and are now fixed in the docs:** "1,934 unique
  domains / 1,978-row full dataset" (no such file exists — the frame is 15,614 and the
  sample is 319), "nine classes including `AMBIGUOUS`" (there are eight; ambiguity lives in
  the reason/detail fields, e.g. `suffix_ambiguous`), "300+ tests" (257).
- **My `pipeline.py` docstring said Gate A needs the config flag *and* the env var. It
  needs either.** Docstring corrected to match the code.
- **"`300+ tests`" was wrong twice over.** It was 257 when I fixed it this morning and it is
  **303** now; the number in this document is the suite at the time of writing, so re-count
  rather than quoting it.
- **I wrote a bug while fixing one** — see item 12. The windowed `is_flapping()` rewrite I
  made to catch late-onset flapping introduced a vacuous-true at `min_length=2`. My own
  257-test baseline did not catch it because no test passed a `min_length` below 4, which is
  the argument for the parametrised degenerate-window cases now in the file.

### Delegation triage, both directions
Two hours of delegated test-writing produced three things worth keeping and six claims worth
recording as checked. Kept: item 11 (cookie state, mine to fix), item 12 (`min_length=2`),
item 13 (vacuous flag). Checked and **not** treated as defects, with reasons now written into
the source where a reader would wonder:

- `detect_changes(..., limit=13)` vs `flapping_domains(..., limit=50)` is *not* an
  inconsistency bug: the A→B→A rule reads only the two readings before the current one, so 13
  is already generous; 50 exists because a flap window wants a longer history. Documented in
  the `detect_changes()` docstring.
- Same-second `started_at_utc` values would make the strictly-earlier filter drop a row and a
  snapshot look like a first sighting. True, unreachable at one snapshot a day, and now the
  documented reason backfills must not reuse a run id.
- `flapping_domains(run_id=…)` judging on full history is not an "as of" promise broken — the
  docstring makes no such promise; it now says explicitly that `detect_changes()` is the
  point-in-time function.
- The `history` must exclude the current reading contract is real and pinned by
  `test_history_must_exclude_the_current_reading_or_a_flip_degrades_to_a_decrease`.
- The delegated `tests/test_fetch_rules.py` (task 2) was interrupted at 56 calls and produced
  nothing usable; its reported line-37 SyntaxError refers to a file I had already deleted and
  rewritten. Verified after: 41 tests collect from `32b2e62`, working tree was clean.

## Two things that need your decision before Gate B

1. **Gate A is one key, not two.** `assert_live_allowed()` raises only if
   `LIVE_REQUESTS_ENABLED` is False **and** `PATCHWATCH_GATE_A` is not exactly `APPROVED`.
   So one stray `export PATCHWATCH_GATE_A=APPROVED` in a shell profile opens live traffic,
   with no code change and no second confirmation. `tests/test_fetch_rules.py:1103-1137`
   pins this behaviour deliberately, so it is arguably the intended design (the env marker
   *is* the encoding of your approval message). If you want two independent keys, change
   `or` to `and` in `src/fetch.py:93` and update those tests — my recommendation is to do
   that for the first live week.
2. **The public page's request promise vs the code.** Your brief drafts the page text as
   "one ordinary homepage request per domain, at most 2 per day during the pilot". The
   crawler allows three budget-charged phases (https, one unverified retry after a cert
   error, one plain-HTTP fallback), plus up to three same-domain redirect hops inside a
   phase. I wrote `docs/project_page.md` to say three, because publishing "at most 2" while
   the code can do 3 is a promise we break on record. Either tighten
   `MAX_SENDS_PER_DOMAIN` to 2, or keep 3 on the page. Related: the user agent currently
   points at `https://github.com/JForden/JForden`, a GitHub profile, not a project page —
   and Gate A's stated meaning is that the project page is already live.

## Open

- ~~**The untested module is the safety-critical one.**~~ **Closed 2026-10-23.**
  `src/fetch.py` — approved-set containment, the request budget, the redirect policy, the
  no-cookie rule, the 64 KB cap, the blocklist, the kill switch, the per-IP limit, the
  ledger audit and Gate A — now has 41 rule-by-rule tests of its own
  (`tests/test_fetch_rules.py`), and the first defect they caught was a real one: item 11,
  cookie state riding across redirect hops. The delegated file was dropped (two hours,
  never parseable, same bad idiom twice) and I wrote these against the source myself.
  What loopback still cannot test is the next bullet, and that gap is honest, not hidden.
- Nothing in this repo has been exercised against a real government web server, including
  the kill switch's rolling 10%-of-50 window, the per-IP limit across genuinely distinct
  IPs (mock mode serialises everything onto `127.0.0.1`), and the change detector under
  real header churn. That is what the pilot is for; it is also why the pilot's answer to
  its own research question (`VISIBILITY = V / P`) is still unknown.

## Reproduce this state

```bash
cd C:/Users/jforden/Desktop/repos/patch-watch
.venv/Scripts/python.exe -X utf8 -m pytest -q                      # 303 passed, no --ignore
.venv/Scripts/python.exe -X utf8 scripts/run_snapshot.py --mock --limit 60 --db data/validate.db --label VALIDATE
echo "ABUSE_COMPLAINT stop now" > logs/abuse.flag
.venv/Scripts/python.exe -X utf8 scripts/run_snapshot.py --mock --limit 5 --db data/halt.db --label HALT   # refused
rm logs/abuse.flag
```

Last mock validation runs (loopback only): 60 domains → 60 budget-charged phases across 78
ledger rows, all eight classes represented (12 patched / 12 vulnerable-by-version / 6 each
of the rest), `audit_problems: []`, `kill_switch: null`, exit 0. A second 25-domain run with
`--mock-rotate 1` → 31 ledger rows, 2 `NO_RESPONSE` from the dead-port case, "No violations
found" in `reports/run_R20261023T154116Z_RECHECK.md`. After the cookie fix, a fresh
25-domain loopback run (`--label C1`, `reports/run_RC20261023T18COOKIE.md`) gave 25
budget-charged phases across 31 ledger rows, all eight classes represented,
`audit_problems: []`, `kill_switch: null`, exit 0.

Full-suite stability: `303 passed` (43.3 s) after the two `detect.py` fixes, on top of
`298 passed` twice back to back (48.8 s, 48.1 s) before them. Before the fetch-rule file
existed the count was 257; the `--ignore` flag is no longer needed by anything, and
`tests/test_fetch_rules.py` is in this commit. Breakdown: `test_detect.py` 144,
`test_classify.py` 61, `test_mock_server.py` 57, `test_fetch_rules.py` 41.
