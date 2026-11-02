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
title patch-watch LIVE snapshot (national) - do not close
echo =====================================================================
echo  patch-watch: national extension check, runs only after Wisconsin. Started %DATE% %TIME%
echo  This window can stay quiet for several minutes while a run works.
echo  Do NOT close it or press Ctrl+C: that stops the run and loses its record.
echo  Full log: logs\cron.out in the patch-watch folder.
echo  If nothing is due, it closes again within a few seconds.
echo =====================================================================
echo.
set "PATCHWATCH_GATE_A=APPROVED"
cd /d "%~dp0.." || exit /b 9
".venv\Scripts\python.exe" -X utf8 "scripts\national_day.py" >> "logs\cron.out" 2>&1
set "PW_RC=%errorlevel%"
echo Finished at %TIME% with exit code %PW_RC%. This window closes now.
exit /b %PW_RC%
