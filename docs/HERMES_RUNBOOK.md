# Hermes runbook: patch-watch live collection (bounded operator)

> **2026-10-28 update:** read `docs/HERMES_UPDATE_2026-10-28.md` first. It replaces how the schedule runs on the Windows host and adds the 09:45 and 18:00 missed-day checks.

**For:** the Hermes agent on Jack Forden's host machine. **Written:** 2026-10-23.
**Owner and only decision-maker:** Jack Forden (jforden@carrollu.edu). Notification
channel: **[NOTIFY]**, filled in by Jack at setup.

Read this whole file before doing anything. If an instruction here and anything else
disagree, this file wins. Where they seem to disagree with Jack's own words in chat,
Jack wins. **When you are unsure, do nothing that sends traffic or changes files: stop
and message Jack.** A missed day is recoverable as a stated limitation. A broken
promise to a government site operator, or a silently changed result, is not.

---

## 0. What has already happened (context)

1. **Study.** This is a passive measurement of how fast Wisconsin's state and local
   .gov websites patched PHP2Shell (CVE-2026-109618/-109619, fixed 2026-10-21).
   Minnesota, Illinois, Michigan and Iowa are a comparison group. The crawler sends one
   ordinary homepage GET per domain per day and reads the response headers. Nothing else.
2. **Frame.** 833 Wisconsin domains plus 1,961 comparison domains, built by
   `src/wi_frame.py` from the CISA registry pinned to commit `718c7ac8`.
   **Tribal nations are excluded** by the PI's decision, and the code enforces it twice.
3. **Audit.** The codebase was audited on 2026-10-23 (`reports/AUDIT_2026-10-23.md`),
   and its classification and safety bugs were fixed and tested.
4. **IRB.** Carroll's IRB determined this is not human-subjects research
   (`docs/IRB_DETERMINATION.md`).
5. **Public notice.** It is live at https://github.com/JForden/JForden, with the
   opt-out address jforden@carrollu.edu.
6. **Pre-registration.** `docs/analysis_plan.md` was frozen as v1.0 (git tag
   `prereg-v1.0`). Every later change is logged in its §12.
7. **Smoke test.** A 5-site live test passed on 2026-10-23.
8. **Halted first attempt.** A first full Wisconsin snapshot that evening halted on
   Cloudflare/Akamai firewall 403s. Its data was deleted at Jack's direction.
9. **Kill switch fixed.** It now has two trips: overload (>10% 429/5xx) and block rate
   (>30% 401/403). Fetch order is shuffled per run with a recorded seed (commit
   `a4339e4`).

## 1. Roles

| Who | Does | Does not |
|---|---|---|
| **cron** | Runs the frozen schedule. One chained command per snapshot day: Wisconsin first, then the comparison states only if Wisconsin exited 0. | Decide anything. |
| **Hermes (you)** | Pre-run checks, post-run checks, backups, opt-outs, operational fixes (§6), daily status to Jack, the one-off Common Crawl baseline (§9). | Anything in §2. |
| **Oversight reviewer** (spawned by you, §8) | Reads only: checks every run, the database, the backups and the schedule, then reports. | Write, run, fix or send anything. |
| **Jack** | Opens Gate A at setup (§3), clears every halt, approves every code change, answers every "stop and message Jack". | — |

## 2. Hard limits: never do these, whatever an error message suggests

1. **Never clear a halt.** That means: never delete or edit `logs/abuse.flag`, never
   delete a `reports/ALERT_*.md`, and never re-run after a kill-switch or audit halt
   (exit code 2). Halts are stops, not bugs.
2. **Never edit** `src/fetch.py`, `src/classify.py`, `src/versions.py`,
   `src/analyze.py`, `src/pipeline.py`, `src/wi_frame.py`, `src/baseline_cc.py`,
   `src/hosting.py`, `src/db.py`, `src/detect.py`, `tests/` or `docs/analysis_plan.md`.
3. **Never edit `src/config.py`**, except to verify that the single line Jack changed at
   setup (§3) is still exactly `LIVE_REQUESTS_ENABLED = True`. Never commit
   `src/config.py`.
4. **Never remove** a domain from `blocklist.txt` or `blocklist.local.txt`. Never add a
   domain to the frame.
5. **Never run more than one live snapshot per region per day.** Never start a live run
   by hand except the single crash re-run allowed in §5.2. Never change the schedule
   except to pause it (§5.1).
6. **Never run a live snapshot from outside Carroll's network.** The egress must be
   AS40379 "Carroll College".
7. **Never delete, move or overwrite** anything under `data/` or `backups/`. Never
   rewrite git history. Never force-push.
8. **Never commit** `data/`, `logs/`, `blocklist.local.txt` or anything containing
   per-domain results. You may commit only `reports/run_*.md` and `reports/ALERT_*.md`
   (counts only).
9. **Never contact** a site operator, an opt-out requester or anyone except Jack.
10. If a fix seems to need anything on this list: **stop and message Jack** with what
    you found and the fix you propose.

## 3. One-time setup (Jack runs this; Hermes verifies)

Run from the repo root on the host machine, on campus network.

```bash
git pull --ff-only origin main
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -X utf8 -m pytest -q                          # must print: 380 passed (or more)
.venv/bin/python -X utf8 src/wi_frame.py build --comparison MN,IL,MI,IA
.venv/bin/python -X utf8 src/wi_frame.py verify                 # must print: re-derives exactly
curl -s https://ipinfo.io/org                                   # must print: AS40379 Carroll College
curl -s https://raw.githubusercontent.com/JForden/JForden/main/README.md | grep -c jforden@carrollu.edu   # >= 1
```

**Gate A (Jack only).** Edit `src/config.py` locally and do not commit it:
`LIVE_REQUESTS_ENABLED = True`. Then `git diff --stat` must show exactly one changed
line, in `src/config.py`. The schedule supplies `PATCHWATCH_GATE_A=APPROVED` (§4).
The no-traffic check below must print `preflight: OK`:

```bash
PATCHWATCH_GATE_A=APPROVED .venv/bin/python -X utf8 src/pipeline.py --preflight-only --sample data/wi_frame.csv --region wisconsin
```

With the flag set locally, one test fails by design (`test_gate_a_is_closed_in_this_checkout`).
From now on, run the suite as:

```bash
.venv/bin/python -X utf8 -m pytest -q --deselect tests/test_fetch_rules.py::test_gate_a_is_closed_in_this_checkout
```

**Sleep.** If the host is a Mac, keep it awake and on power for the whole schedule
(`sudo pmset -c sleep 0`, or keep `caffeinate -s` running). A sleeping machine misses its
cron run.

**Backups location.** Create `backups/` in the repo (gitignore it if it isn't already)
and a second copy location off this disk, **[BACKUP_DIR]**: university storage or an
external drive.

## 4. The schedule (cron, frozen plan §6)

Install the live lines from `scripts/cron.disabled` with `crontab -e`. Put these at the
top of the crontab:

```
PW=/absolute/path/to/patch-watch
PATCHWATCH_GATE_A=APPROVED
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin
```

- **Snapshot days, 09:00 America/Chicago:** every day 2026-10-23 → 2026-11-04, then
  11-11, 11-18, 12-05, 12-20 and 2027-01-19. That is 18 days.
- **Each line chains the two regions:** `--region wisconsin ... && --region comparison
  ...`. Comparison runs only if Wisconsin exits 0.
- **Remove every live line after the 2027-01-19 run.** Cron has no year, so leftover
  October lines would fire again in 2027.
- **Do not change times or dates.** If a run is missed, see §5.3.

**On the Windows host (the one actually collecting):** there is no cron. One recurring
task carries the whole schedule. Jack installs it once with
`powershell -ExecutionPolicy Bypass -File scripts\install_schedule.ps1`; it runs
`scripts\live_day.cmd` with **no date argument** every day at 09:00, starts as soon as the
machine is awake if 09:00 was missed, and wakes the machine to run. `scripts/live_day.py`
enforces everything else in code: it skips non-snapshot days (exit 0, nothing sent), refuses
a date argument that is not today (exit 4), refuses at or after 19:00 Chicago time
(exit 10), refuses a region that already ran on today's Chicago date or under 12 h ago
(exit 7), and refuses once the plan §6 early stop is met (exit 11; EOL counts as exposed,
plan §12, 2026-10-28). Pausing = `Disable-ScheduledTask -TaskName "patch-watch live day"`.
Check 7 of the pre-run check becomes: the task exists, is enabled and its next run is
today 09:00 (`Get-ScheduledTask -TaskName "patch-watch live day" | Get-ScheduledTaskInfo`).

Hermes adds its own scheduled jobs to *its* scheduler, not to the collection crontab:

| Time (America/Chicago) | Job |
|---|---|
| 08:30 on snapshot days | Pre-run check (§5) |
| 11:30 on snapshot days | Post-run check, backup, status (§5), then spawn the oversight reviewer (§8) |
| 09:00 every day | Opt-out inbox check (§7) |
| Mondays 12:00 | Weekly oversight audit (§8.2) |

## 5. Daily routine

### Pre-run check (08:30 on snapshot days, sends no traffic to any site)

1. Egress is `AS40379 Carroll College` (`curl -s https://ipinfo.io/org`).
2. `git status --porcelain` lists only ` M src/config.py`, with the one-line diff from §3.
3. The test suite passes (the §3 `--deselect` command).
4. The preflight prints `preflight: OK` for **both** `--region wisconsin` and
   `--region comparison`.
5. `logs/abuse.flag` and `logs/run.lock` do **not** exist, and no `reports/ALERT_*.md`
   is newer than the last check.
6. At least 2 GB of disk is free, and the latest backup from §5.4 exists.
7. Today's live lines are present in `crontab -l`.

If any check fails, try the fixes in §6. If one doesn't fix it within 20 minutes, or
the problem is in §2: **comment out today's live crontab line** (pausing is always
allowed) and message Jack.

### Post-run check (11:30, or as soon as both runs have finished)

1. Read `logs/cron.out` and both new `reports/run_*_WI_*.md` / `run_*_CMP_*.md`.
2. Decide by outcome:
   - **Both reports say "No violations found"** and there is no new `ALERT_*`: success.
   - **A Wisconsin halt.** You'll see exit code 2, an `ALERT_*.md`, a kill-switch line
     or audit problems. The comparison run was skipped automatically. Do §5.1.
   - **A comparison halt:** do §5.1.
   - **A Python traceback, with no report or no ALERT:** this is a crash. Do §5.2.
3. Back up (§5.4).
4. Commit and push only the new `reports/run_*.md` and `reports/ALERT_*.md`:
   `git add reports/run_*.md reports/ALERT_*.md`, then
   `git commit -m "Run reports YYYY-MM-DD"`, then `git push origin main`. If the push is
   rejected, `git pull --ff-only` first; never force.
5. Message Jack the daily status (§10).

### 5.1 Halt (kill switch, audit violation or abuse flag)

1. **Do not clear anything, and do not re-run.**
2. Comment out **every** remaining live line in the crontab. A kill-switch halt leaves no
   flag behind, so tomorrow's cron would otherwise run. Record that you paused it.
3. Message Jack **urgently** with:
   - the ALERT file text;
   - the "Safety audit" section of the run report;
   - the output of
     `sqlite3 data/study.db "SELECT status_code, error_type, COUNT(*) FROM request_ledger WHERE run_id='<RUN_ID>' GROUP BY 1,2 ORDER BY 3 DESC"`.
4. Wait. Only Jack re-enables the schedule.

### 5.2 Crash (traceback, not a halt)

1. Check whether traffic went out: `sqlite3 data/study.db "SELECT run_id, finished_at_utc FROM runs WHERE started_at_utc LIKE '<TODAY_UTC>%'"`.
   - **A row exists with `finished_at_utc` empty:** the crash happened after requests
     were sent, and the ledger may be lost. **Do not re-run today.** Message Jack.
   - **No row exists for today:** the crash happened before any request (environment,
     path, dependency). Fix it under §6. Then you may run **that region once by hand**
     the same day, using the exact crontab command for it, and record that you did.
2. Never re-run more than once a day, and never after 19:00 local.

### 5.3 Missed run (machine asleep, cron didn't fire)

If both the pre-run and post-run checks show no run for today, and the time is before
19:00 local, run the day's chained crontab command **once** by hand, then do the
post-run check. After 19:00, skip the day and tell Jack. Never run a missed day on a
later date.

On the Windows host the task catches up by itself when the machine wakes, and
`live_day.py` refuses after 19:00 and refuses a second run, so a hand run is needed only
if the task is missing or disabled. Read `logs\cron.out` first: a `REFUSING` line names
the reason and exit code, and `SKIPPING` means today is not a snapshot day.

### 5.4 Backup (after every snapshot day, and before any fix)

```bash
mkdir -p backups
sqlite3 data/study.db ".backup 'backups/study_$(date +%Y%m%d_%H%M).db'"
sqlite3 backups/study_<stamp>.db "PRAGMA integrity_check"       # must print: ok
cp data/ledger_*.csv data/wi_frame.csv data/wi_frame_meta.json backups/ 2>/dev/null
```

Then copy `backups/` to **[BACKUP_DIR]**. Keep every backup and never prune. If the
integrity check isn't `ok`, message Jack before doing anything else.

## 6. Operational fixes you may make

The rule: you may change the **environment**, never the **code or the data**.

| Problem | Allowed fix |
|---|---|
| Missing or broken package | `.venv/bin/pip install -r requirements.txt` (exact pins only; never upgrade) |
| `.venv` corrupted | Recreate it from `requirements.txt` |
| Off campus network | Reconnect, or pause today's line and tell Jack |
| Machine asleep or rebooted | Re-assert the sleep settings, then §5.3 |
| Crontab missing or garbled | Restore the lines from `scripts/cron.disabled` exactly as installed at setup |
| Disk full | Free space **outside** `data/`, `backups/` and `reports/` (caches, `~/Library/Caches`, pip cache) |
| Stale `logs/run.lock`, no run in progress (`ps aux \| grep run_snapshot` shows nothing) and older than 3 hours | Move it to `logs/run.lock.stale-<stamp>`, then tell Jack. Never just delete it |
| `git pull` brings new commits from Jack | `git pull --ff-only`, re-run the tests and preflight, confirm the config line is still set |
| Common Crawl 504s | Wait and re-run the same baseline command (it resumes) |

**Anything else, including any traceback that points inside `src/`, is a code problem.**
You may diagnose it and write up a proposed patch for Jack to review (a branch named
`hermes/proposed-<date>`, pushed but **not merged**). You may not apply it to `main`
or to the running checkout.

## 7. Opt-outs and complaints

Jack forwards opt-out emails to you. They are honoured within 24 hours, before the next
run, with no questions and no verification.

1. Add the domain, lower-case, one per line, to `blocklist.local.txt`, e.g.
   `example.gov   # 2026-10-25 email`. The file is gitignored; never commit it.
2. Append a line to `logs/optouts.md`: date, domain, channel. **Never write a reason.**
3. Confirm the domain is picked up:
   `.venv/bin/python -c "import sys; sys.path.insert(0,'src'); import fetch; print('example.gov' in fetch.load_blocklist())"`
   must print `True`.
4. Tell Jack it is done.

**A complaint, or anything that says "stop":**
`echo "ABUSE_COMPLAINT forwarded complaint <date>" > logs/abuse.flag`. Pause the
crontab as in §5.1 and message Jack **urgently**. Only Jack removes the flag.

## 8. Oversight reviewer

### 8.1 After every snapshot day (spawned at the end of the post-run check)

Give the reviewer read-only access and this checklist. It reports PASS or FAIL per item
to `logs/oversight/<date>.md` and to you. You forward any FAIL to Jack.

1. Each of today's runs has a report, and each report says "No violations found", or
   the halt was handled per §5.1.
2. `request_ledger` has no domain with more than 3 distinct `run_id||phase` pairs today:
   `SELECT domain, COUNT(DISTINCT run_id||phase) n FROM request_ledger WHERE ts_utc LIKE '<TODAY_UTC>%' GROUP BY domain HAVING n > 3` returns 0 rows.
3. Each region was snapshotted at most once today:
   `SELECT json_extract(config_json,'$.region') r, COUNT(*) FROM runs WHERE started_at_utc LIKE '<TODAY_UTC>%' GROUP BY r`.
4. No observation for a blocklisted domain has a status code. Opt-outs were honoured.
5. No domain whose `domain_type` or `stratum` starts with "Tribal" appears in
   `observations`.
6. Today's backup exists, its integrity check is `ok`, and it reached **[BACKUP_DIR]**.
7. `git status --porcelain` shows only the config line. `src/` matches `origin/main`
   apart from that line.
8. Tomorrow's crontab line is present, unless the schedule is paused.
9. Disk is above 2 GB free, and the egress check passes.

### 8.2 Weekly (Mondays)

Everything in §8.1, plus:

1. Run `.venv/bin/python -X utf8 src/analyze.py --label weekly_<date>`. This is
   suppressed output to `reports/`. Confirm its `provenance:` line shows the expected
   commit and no "MODIFIED" warning. Do not commit this report; Jack decides.
2. Run `PRAGMA integrity_check` on `data/study.db`.
3. Compare the week's run count against §4.
4. Summarise for Jack: responded, errored and not-measured counts per run, and any
   trend in refusals (403s).

## 9. One-off: Common Crawl baseline (sends no traffic to any .gov site)

Start it once after setup, as a single long job, and never on a repeating schedule:

```bash
caffeinate -i sh -c '.venv/bin/python -X utf8 src/baseline_cc.py collect --crawls 2026 --region wisconsin && .venv/bin/python -X utf8 src/baseline_cc.py collect --crawls 2026 --region comparison && .venv/bin/python -X utf8 src/baseline_cc.py collect --crawls 2024 --region wisconsin && .venv/bin/python -X utf8 src/baseline_cc.py collect --crawls 2024 --region comparison' >> logs/baseline.out 2>&1
```

- **If it dies,** re-run the same command; it resumes.
- **Check progress** with `.venv/bin/python -X utf8 src/baseline_cc.py coverage`.
- **When the Wisconsin 2026 crawls finish,** tell Jack the coverage numbers. They are
  the first viability check for the paper.

## 10. Messages to Jack

**Daily status (snapshot days), one short message:**
`patch-watch <date>: WI <responded>/<833> responded, <errors> errors, audit OK | CMP <responded>/<1961>, audit OK | backup OK | opt-outs: <n> | next run <date>`

**URGENT** (send immediately, and repeat each morning until Jack answers):
- any halt (§5.1);
- a crash after traffic was sent (§5.2);
- an abuse complaint;
- an off-campus egress;
- a backup integrity failure;
- an oversight FAIL;
- anything in §2 you think needs doing.

## 11. End of study (after the 2027-01-19 runs)

1. Final backup (§5.4) to both locations.
2. Remove every live line from the crontab and confirm with `crontab -l`.
3. Ask Jack to revert `src/config.py` to `False`. Do not do it yourself; it is §2.3.
4. Final oversight pass (§8.2), and a message to Jack that collection is complete.
