@echo off
rem ─────────────────────────────────────────────────────────────────────────────────────
rem patch-watch live snapshot day - the Windows equivalent of one live crontab line.
rem
rem This file is the ONLY place the schedule supplies PATCHWATCH_GATE_A=APPROVED, which is
rem where runbook section 4 puts it (the crontab environment block). It lives here and not
rem in live_day.py on purpose: Gate A is config.py's committed flag AND this marker, so a
rem hand-run of the Python wrapper must not be able to authorise live traffic by itself.
rem
rem live_day.py does the refusing (wrong day / halted / already ran) and runs wisconsin,
rem then comparison only if wisconsin exited 0. Output goes to logs\cron.out, the file the
rem section 5 post-run check reads, matching the cron line's ">> logs\cron.out 2>&1".
rem
rem Usage:  live_day.cmd 20261024        (the local date this task was created to capture)
rem ─────────────────────────────────────────────────────────────────────────────────────
setlocal
set "PATCHWATCH_GATE_A=APPROVED"
rem ---------------------------------------------------------------------------
rem PI decision 2026-10-26: the COMPARISON arm is HELD after the 2026-10-24 halt
rem (Cloudflare 5xx clusters, not an overload storm). Wisconsin-only for now.
rem To resume both arms, delete the PATCHWATCH_REGIONS line below or set it to
rem   wisconsin,comparison   -- an unparseable value makes live_day.py refuse the
rem whole day (exit 9) rather than quietly capture a narrower snapshot.
rem NEVER edit or remove PATCHWATCH_GATE_A above: it is section 4's runbook line, and
rem src/pipeline.py refuses to send any request without it. NOTE (checked 2026-10-26):
rem no automated test guards this file -- the only protection is the runbook and
rem profile_docs/patch-watch/OPERATOR_JOBS.md. Verify by hand after any edit.
rem ---------------------------------------------------------------------------
set "PATCHWATCH_REGIONS=wisconsin"
cd /d "%~dp0.." || exit /b 9
".venv\Scripts\python.exe" -X utf8 "scripts\live_day.py" %1 >> "logs\cron.out" 2>&1
exit /b %errorlevel%
