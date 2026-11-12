# Source of truth: the Patch Watch experiment

This file is the log of what the experiment does and what has been established about it. It is append-only.

**Rule for entries.** A statement is written here only when at least two probes with different origins (a different table,
file, tool or independent implementation) returned the same value in the same run of `scripts/sot_verify.py`, and no probe
disagreed or failed. A probe that could not run (a missing tool, no network) is shown as "not run" and does not count.
A statement with fewer than two working probes is not written. Nothing here is argued from memory or from a summary: every
value below was recomputed when its block was written. To re-check, run `python -X utf8 scripts/sot_verify.py --check`
(it exits 1 if a previously logged statement no longer holds).

**What counts as different origins.** Examples: the runs table versus the observations table versus the request ledger
file versus the written report; the code constant versus the committed copy on GitHub; a Python result versus a Lean
evaluation of the same quantity. Two probes that read the same file in the same way do not count.

**Scope.** Aggregates only. No domain name, address or per-domain row appears here. Ideas, plans and opinions live elsewhere
(`docs/EVALUATION.md`, `docs/proposed/`), because they cannot be verified this way.

## Verification run 2026-11-01 14:47:01Z

### C01 (Design) VERIFIED

Every Wisconsin run covers the same [833] domains.

| probe | origin | value |
|---|---|---|
| runs table sample_size | database: runs | `[833]` |
| distinct domains observed per run | database: observations | `[833]` |
| registry-derived frame file | file: data/wi_frame.csv | `[833]` |

### C02 (Design) VERIFIED

The Wisconsin plus comparison frame holds 2794 domains.

| probe | origin | value |
|---|---|---|
| frame file rows | file: data/wi_frame.csv | `2794` |
| sum of run sample sizes | database: runs | `2794` |
| first-written analysis report header | file: reports/analysis_weekly_2026-10-26 | `2794` |

### C03 (Design) VERIFIED

Every request identifies the study with the User-Agent CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu).

| probe | origin | value |
|---|---|---|
| code constant | code: src/config.py | `CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu)` |
| stored with each run | database: runs | `CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu)` |
| run report header | file: reports/run_* | `CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu)` |

### C04 (Design) VERIFIED

No domain receives more than 3 budget-charged first requests per run (within cap: true).

| probe | origin | value |
|---|---|---|
| configured cap | code: src/config.py | `true` |
| request ledger CSV files | files: data/ledger_*.csv | `true` |
| request ledger table | database: request_ledger | `true` |

### C05 (Design) VERIFIED

Since 2026-10-28 every Wisconsin run started at ["14:00"] UTC.

| probe | origin | value |
|---|---|---|
| run start times | database: runs | `["14:00"]` |
| first request time per run | files: data/ledger_*.csv | `["14:00"]` |
| run report start lines | files: reports/run_* | `["14:00"]` |

### C06 (State) VERIFIED

Wisconsin snapshots exist for exactly these dates: ["20261024", "20261026", "20261028", "20261029", "20261030", "20261031", "20261101"].

| probe | origin | value |
|---|---|---|
| runs table | database: runs | `["20261024", "20261026", "20261028", "20261029", "20261030", "20261031", "20261101"]` |
| run reports | files: reports/run_* | `["20261024", "20261026", "20261028", "20261029", "20261030", "20261031", "20261101"]` |
| request ledgers | files: data/ledger_*.csv | `["20261024", "20261026", "20261028", "20261029", "20261030", "20261031", "20261101"]` |

### C07 (State) VERIFIED

On the latest Wisconsin snapshot the class counts are {"EOL_UNFIXED": 10, "NOT_MEASURED": 55, "NO_PHP_EVIDENCE": 459, "NO_RESPONSE": 129, "PATCHED_UPSTREAM": 32, "PHP_VERSION_HIDDEN": 148}.

| probe | origin | value |
|---|---|---|
| observation rows | database: observations | `{"EOL_UNFIXED": 10, "NOT_MEASURED": 55, "NO_PHP_EVIDENCE": 459, "NO_RESPONSE": 129, "PATCH` |
| current class per domain | database: domains | `{"EOL_UNFIXED": 10, "NOT_MEASURED": 55, "NO_PHP_EVIDENCE": 459, "NO_RESPONSE": 129, "PATCH` |
| run report class table | file: reports/run_* | `{"EOL_UNFIXED": 10, "NOT_MEASURED": 55, "NO_PHP_EVIDENCE": 459, "NO_RESPONSE": 129, "PATCH` |

### C08 (Findings) VERIFIED

Between the 2026-10-24 and 2026-10-26 Wisconsin snapshots 4 domains moved to PATCHED_UPSTREAM.

| probe | origin | value |
|---|---|---|
| compare the two observation sets | database: observations | `4` |
| recorded class-change events between those two runs | database: patch_events | `4` |

### C09 (Design) VERIFIED

The national frame is split into waves of [392, 3000, 7290] names.

| probe | origin | value |
|---|---|---|
| wave metadata | file: data/national_waves_meta.json | `[392, 3000, 7290]` |
| wave column of the names file | file: data/national_waves.csv | `[392, 3000, 7290]` |
| wave loader in the code | code: src/national.py | `[392, 3000, 7290]` |

### C10 (State) VERIFIED

National wave 1 ran on 2026-10-31 over 392 domains.

| probe | origin | value |
|---|---|---|
| run record | database: runs | `392` |
| distinct domains observed | database: observations | `392` |
| wave 1 rows in the names file | file: data/national_waves.csv | `392` |

### C11 (Safety) VERIFIED

The committed code keeps live requests switched off (live flag in the committed config: false).

| probe | origin | value |
|---|---|---|
| HEAD | git: local commit | `false` |
| origin/main | git: remote ref | `false` |
| raw file on GitHub | web: raw.githubusercontent | `false` |

### C12 (Safety) VERIFIED

The collector's working copy has live requests switched on (flag: true).

| probe | origin | value |
|---|---|---|
| source file | file: src/config.py | `true` |
| imported module | code: config import | `true` |
| pre-run check written by the scheduler | file: logs/hub/checks | `true` |

### C13 (Findings) VERIFIED

Joint audit of the RQ0 tables (hidden cells recoverable, per region block) for the report as first committed and as reprinted: {"first_committed": [11, 19], "reprinted": [0, 0]}.

| probe | origin | value |
|---|---|---|
| SciPy integer programming | tool: SciPy milp | `{"first_committed": [11, 19], "reprinted": [0, 0]}` |
| project exact audit | code: src/analyze + src/disclosure | `{"first_committed": [11, 19], "reprinted": [0, 0]}` |

### C14 (Method) VERIFIED

The Lean files check with no gaps (no sorry, no sorryAx): true.

| probe | origin | value |
|---|---|---|
| compile each file | tool: lean | `true` |
| axiom listing of the key theorems | tool: lean #print axioms | `true` |
| source scan outside comments | files: lean/*.lean | `true` |

### C15 (Findings) VERIFIED

Tipping counts (largest hidden-patched count keeping the share below 50%, 40%, 25%): [63, 44, 15].

| probe | origin | value |
|---|---|---|
| closed form | arithmetic: formula | `[63, 44, 15]` |
| exhaustive search | arithmetic: enumeration | `[63, 44, 15]` |
| Lean evaluation | tool: lean #eval | `[63, 44, 15]` |

### C16 (Findings) VERIFIED

Arrival days (of 69) with at least 3 snapshots in the window, plan versus plan plus 7-day burst, by window length: {"14": [0, 69], "21": [0, 69], "3": [0, 69], "7": [0, 69]}.

| probe | origin | value |
|---|---|---|
| project script | code: scripts/schedule_coverage.py | `{"14": [0, 69], "21": [0, 69], "3": [0, 69], "7": [0, 69]}` |
| independent recount | code: day-number recount in this script | `{"14": [0, 69], "21": [0, 69], "3": [0, 69], "7": [0, 69]}` |
| Lean evaluation | tool: lean #eval | `{"14": [0, 69], "21": [0, 69], "3": [0, 69], "7": [0, 69]}` |

### C17 (Method) VERIFIED

The Python suppression check and the Lean reference agree on 10,000 test rows (output fingerprint a41b5057bae9c118).

| probe | origin | value |
|---|---|---|
| Python _pinned | code: src/analyze.py | `a41b5057bae9c118` |
| Lean PinnedRef | tool: lean --run | `a41b5057bae9c118` |

### C18 (Method) VERIFIED

The public .gov registry list had 7430 domains on 2022-01-29/30.

| probe | origin | value |
|---|---|---|
| GitHub history of dotgov-data | web: github | `7430` |
| Internet Archive capture | web: archive.org | `7430` |

### C19 (Method) VERIFIED

The full test suite passes: 1627 tests (one test that must fail while live requests are on is excluded).

| probe | origin | value |
|---|---|---|
| fresh pytest run | tool: pytest now | `1627` |
| scheduler's own pre-run run | file: logs/hub/checks | `1627` |

Statements verified in this run: C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11, C12, C13, C14, C15, C16, C17, C18, C19.

## Verification run 2026-11-04 22:06:54Z

### C01 (Design) VERIFIED

Every Wisconsin run covers the same [833] domains.

| probe | origin | value |
|---|---|---|
| runs table sample_size | database: runs | `[833]` |
| distinct domains observed per run | database: observations | `[833]` |
| registry-derived frame file | file: data/wi_frame.csv | `[833]` |

### C02 (Design) VERIFIED

The Wisconsin plus comparison frame holds 2794 domains.

| probe | origin | value |
|---|---|---|
| frame file rows | file: data/wi_frame.csv | `2794` |
| sum of run sample sizes | database: runs | `2794` |
| first-written analysis report header | file: reports/analysis_weekly_2026-10-26 | `2794` |

### C03 (Design) VERIFIED

Every request identifies the study with the User-Agent CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu).

| probe | origin | value |
|---|---|---|
| code constant | code: src/config.py | `CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu)` |
| stored with each run | database: runs | `CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu)` |
| run report header | file: reports/run_* | `CarrollPHPStudy/1.0 (+https://github.com/JForden/JForden; jforden@carrollu.edu)` |

### C04 (Design) VERIFIED

No domain receives more than 3 budget-charged first requests per run (within cap: true).

| probe | origin | value |
|---|---|---|
| configured cap | code: src/config.py | `true` |
| request ledger CSV files | files: data/ledger_*.csv | `true` |
| request ledger table | database: request_ledger | `true` |

### C05 (Design) VERIFIED

Since 2026-10-28 every Wisconsin run started at ["14:00", "16:42"] UTC.

| probe | origin | value |
|---|---|---|
| run start times | database: runs | `["14:00", "16:42"]` |
| first request time per run | files: data/ledger_*.csv | `["14:00", "16:42"]` |
| run report start lines | files: reports/run_* | `["14:00", "16:42"]` |

### C06 (State) VERIFIED

Wisconsin snapshots exist for exactly these dates: ["20261024", "20261026", "20261028", "20261029", "20261030", "20261031", "20261101", "20261102", "20261103", "20261104"].

| probe | origin | value |
|---|---|---|
| runs table | database: runs | `["20261024", "20261026", "20261028", "20261029", "20261030", "20261031", "20261101", "2026` |
| run reports | files: reports/run_* | `["20261024", "20261026", "20261028", "20261029", "20261030", "20261031", "20261101", "2026` |
| request ledgers | files: data/ledger_*.csv | `["20261024", "20261026", "20261028", "20261029", "20261030", "20261031", "20261101", "2026` |

### C07 (State) VERIFIED

On the latest Wisconsin snapshot the class counts are {"EOL_UNFIXED": 11, "NOT_MEASURED": 42, "NO_PHP_EVIDENCE": 462, "NO_RESPONSE": 128, "PATCHED_UPSTREAM": 31, "PHP_VERSION_HIDDEN": 159}.

| probe | origin | value |
|---|---|---|
| observation rows | database: observations | `{"EOL_UNFIXED": 11, "NOT_MEASURED": 42, "NO_PHP_EVIDENCE": 462, "NO_RESPONSE": 128, "PATCH` |
| current class per domain | database: domains | `{"EOL_UNFIXED": 11, "NOT_MEASURED": 42, "NO_PHP_EVIDENCE": 462, "NO_RESPONSE": 128, "PATCH` |
| run report class table | file: reports/run_* | `{"EOL_UNFIXED": 11, "NOT_MEASURED": 42, "NO_PHP_EVIDENCE": 462, "NO_RESPONSE": 128, "PATCH` |

### C08 (Findings) VERIFIED

Between the 2026-10-24 and 2026-10-26 Wisconsin snapshots 4 domains moved to PATCHED_UPSTREAM.

| probe | origin | value |
|---|---|---|
| compare the two observation sets | database: observations | `4` |
| recorded class-change events between those two runs | database: patch_events | `4` |

### C09 (Design) VERIFIED

The national frame is split into waves of [392, 3000, 7290] names.

| probe | origin | value |
|---|---|---|
| wave metadata | file: data/national_waves_meta.json | `[392, 3000, 7290]` |
| wave column of the names file | file: data/national_waves.csv | `[392, 3000, 7290]` |
| wave loader in the code | code: src/national.py | `[392, 3000, 7290]` |

### C10 (State) VERIFIED

National wave 1 ran on 2026-10-31 over 392 domains.

| probe | origin | value |
|---|---|---|
| run record | database: runs | `392` |
| distinct domains observed | database: observations | `392` |
| wave 1 rows in the names file | file: data/national_waves.csv | `392` |

### C11 (Safety) VERIFIED

The committed code keeps live requests switched off (live flag in the committed config: false).

| probe | origin | value |
|---|---|---|
| HEAD | git: local commit | `false` |
| origin/main | git: remote ref | `false` |
| raw file on GitHub | web: raw.githubusercontent | `false` |

### C12 (Safety) VERIFIED

The collector's working copy has live requests switched on (flag: true).

| probe | origin | value |
|---|---|---|
| source file | file: src/config.py | `true` |
| imported module | code: config import | `true` |
| pre-run check written by the scheduler | file: logs/hub/checks | `true` |

### C14 (Method) VERIFIED

The Lean files check with no gaps (no sorry, no sorryAx): true.

| probe | origin | value |
|---|---|---|
| compile each file | tool: lean | `true` |
| axiom listing of the key theorems | tool: lean #print axioms | `true` |
| source scan outside comments | files: lean/*.lean | `true` |

### C15 (Findings) VERIFIED

Tipping counts (largest hidden-patched count keeping the share below 50%, 40%, 25%): [63, 44, 15].

| probe | origin | value |
|---|---|---|
| closed form | arithmetic: formula | `[63, 44, 15]` |
| exhaustive search | arithmetic: enumeration | `[63, 44, 15]` |
| Lean evaluation | tool: lean #eval | `[63, 44, 15]` |

### C16 (Findings) VERIFIED

Arrival days (of 69) with at least 3 snapshots in the window, plan versus plan plus 7-day burst, by window length: {"14": [0, 69], "21": [0, 69], "3": [0, 69], "7": [0, 69]}.

| probe | origin | value |
|---|---|---|
| project script | code: scripts/schedule_coverage.py | `{"14": [0, 69], "21": [0, 69], "3": [0, 69], "7": [0, 69]}` |
| independent recount | code: day-number recount in this script | `{"14": [0, 69], "21": [0, 69], "3": [0, 69], "7": [0, 69]}` |
| Lean evaluation | tool: lean #eval | `{"14": [0, 69], "21": [0, 69], "3": [0, 69], "7": [0, 69]}` |

### C17 (Method) VERIFIED

The Python suppression check and the Lean reference agree on 10,000 test rows (output fingerprint a41b5057bae9c118).

| probe | origin | value |
|---|---|---|
| Python _pinned | code: src/analyze.py | `a41b5057bae9c118` |
| Lean PinnedRef | tool: lean --run | `a41b5057bae9c118` |

### C18 (Method) VERIFIED

The public .gov registry list had 7430 domains on 2022-01-29/30.

| probe | origin | value |
|---|---|---|
| GitHub history of dotgov-data | web: github | `7430` |
| Internet Archive capture | web: archive.org | `7430` |

Statements verified in this run: C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11, C12, C14, C15, C16, C17, C18.
