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
rem Usage:  live_day.cmd                 (today; one recurring daily task, see
rem                                        scripts\install_schedule.ps1)
rem         live_day.cmd 20261029        (optional; must equal today's Chicago date)
rem ─────────────────────────────────────────────────────────────────────────────────────
setlocal
title patch-watch LIVE snapshot (Wisconsin) - do not close
echo =====================================================================
echo  patch-watch: daily live study snapshot, Wisconsin. Started %DATE% %TIME%
echo  This window can stay quiet for several minutes while a run works.
echo  Do NOT close it or press Ctrl+C: that stops the run and loses its record.
echo  Full log: logs\cron.out in the patch-watch folder.
echo  If nothing is due, it closes again within a few seconds.
echo =====================================================================
echo.
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
set "PW_RC=%errorlevel%"
echo Finished at %TIME% with exit code %PW_RC%. This window closes now.
exit /b %PW_RC%
