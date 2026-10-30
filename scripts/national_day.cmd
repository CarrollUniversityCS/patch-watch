@echo off
rem ─────────────────────────────────────────────────────────────────────────────────────
rem patch-watch national extension, one live snapshot day (sibling of live_day.cmd).
rem
rem This file is the ONLY place the national task supplies PATCHWATCH_GATE_A=APPROVED, for the
rem same reason as live_day.cmd: Gate A is config.py's flag AND this marker, so a hand-run of
rem the Python wrapper cannot authorise live traffic. national_day.py does the refusing:
rem no released wave, no notice confirmation, Wisconsin not done today, wrong day, halted.
rem The PI releases a wave by writing 1, 2 or 3 into data\national_active_wave.txt.
rem Output goes to logs\cron.out with the other scheduled runs.
rem ─────────────────────────────────────────────────────────────────────────────────────
setlocal
set "PATCHWATCH_GATE_A=APPROVED"
cd /d "%~dp0.." || exit /b 9
".venv\Scripts\python.exe" -X utf8 "scripts\national_day.py" >> "logs\cron.out" 2>&1
exit /b %errorlevel%
