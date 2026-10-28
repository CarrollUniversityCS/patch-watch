@echo off
rem ─────────────────────────────────────────────────────────────────────────────────────
rem patch-watch one-off Common Crawl baseline (runbook section 9), Windows translation of
rem the caffeinate-wrapped command there. This machine does not sleep (PI statement,
rem 2026-10-23), so the macOS sleep inhibitor is simply dropped; the four chained collect
rem invocations are otherwise exactly as section 9 writes them, in the same order.
rem
rem Sends NO traffic to any .gov site. src/baseline_cc.py talks to exactly two hosts and
rem raises PermissionError on any other (ALLOWED_HOSTS / check_host), so the only egress
rem here is index.commoncrawl.org and data.commoncrawl.org.
rem
rem Run ONCE, never on a repeating schedule (section 9). If it dies, re-run this same file:
rem it resumes from its own cache. Progress: python src/baseline_cc.py coverage
rem ─────────────────────────────────────────────────────────────────────────────────────
setlocal
cd /d "%~dp0.." || exit /b 9
set "PY=.venv\Scripts\python.exe"
set "LOG=logs\baseline.out"
if not exist "logs" mkdir logs
echo baseline_run: started %date% %time% >> "%LOG%"

rem --- health gate (added 2026-10-23, after a global Common Crawl 504 outage) -----------
rem Section 6 says: on Common Crawl 504s, WAIT and re-run (it resumes). Waiting politely
rem means not walking the 4->120 s retry ladder once per domain while CC is down. So: ONE
rem control request to index.commoncrawl.org. Healthy (200/404) -> continue. Anything else
rem -> log, re-arm this task for 07:30 tomorrow (until 2026-12-01), exit without a pass.
rem This touches no .gov site and edits nothing under src\ or tests\.
rem Two probes, not one: Common Crawl flaps on a minutes scale (HTTP 200 at 10:19, HTTP 504
rem at 11:42 on 2026-10-26), so one unlucky probe must not cost the whole pass. -u keeps the
rem log honest about ordering. 2026-10-25's pass died 4 s in with no output at all; the
rem echo markers below exist so the next time, the log names the step that died.
set "CC_TRY=0"
:probe_try
set /a CC_TRY+=1
"%PY%" -X utf8 -u -c "import sys; sys.path.insert(0,'src'); import httpx, config; r=httpx.get('https://index.commoncrawl.org/CC-MAIN-2026-34-index?url=example.com/&output=json', timeout=60.0, headers={'User-Agent': config.USER_AGENT}); print('health probe (try %CC_TRY% of 2): HTTP', r.status_code); sys.exit(0 if r.status_code in (200, 404) else 2)" >> "%LOG%" 2>&1
if not errorlevel 1 goto gate_ok
if %CC_TRY% LSS 2 (
  echo baseline_run: probe %CC_TRY% unhealthy, retrying once in 90 s %date% %time% >> "%LOG%"
  powershell.exe -NoProfile -Command "Start-Sleep -Seconds 90" >> "%LOG%" 2>&1
  goto probe_try
)
echo baseline_run: Common Crawl unhealthy, no pass attempted %date% %time% >> "%LOG%"
powershell.exe -NoProfile -Command "if ((Get-Date) -lt (Get-Date '12/01/2026')) { $d=(Get-Date).Date.AddDays(1).AddHours(7).AddMinutes(30); Set-ScheduledTask -TaskName PW_BASELINE_CC -Trigger (New-ScheduledTaskTrigger -Once -At $d) | Out-Null; Write-Output ('baseline_run: re-armed PW_BASELINE_CC for ' + $d) } else { Write-Output 'baseline_run: past the 2026-12-01 re-arm window; not re-arming' }" >> "%LOG%" 2>&1
exit /b 0
:gate_ok

rem Markers added 2026-10-26: the 2026-10-25 07:30 run exited 1 four seconds after the
rem health probe printed 200, with NO output at all, and it is not reproducible by hand.
rem These lines make the next occurrence name the step that died instead of going silent.
echo baseline_run: gate passed, entering collect phase %date% %time% >> "%LOG%"
"%PY%" -X utf8 -u src\baseline_cc.py collect --crawls 2026 --region wisconsin  >> "%LOG%" 2>&1
echo baseline_run: wisconsin-2026 returned errorlevel %ERRORLEVEL% %date% %time% >> "%LOG%"
if errorlevel 1 ( echo baseline_run: FAILED wisconsin-2026 %date% %time% >> "%LOG%" & exit /b 1 )

"%PY%" -X utf8 -u src\baseline_cc.py collect --crawls 2026 --region comparison >> "%LOG%" 2>&1
if errorlevel 1 ( echo baseline_run: FAILED comparison-2026 %date% %time% >> "%LOG%" & exit /b 1 )

"%PY%" -X utf8 -u src\baseline_cc.py collect --crawls 2024 --region wisconsin  >> "%LOG%" 2>&1
if errorlevel 1 ( echo baseline_run: FAILED wisconsin-2024 %date% %time% >> "%LOG%" & exit /b 1 )

"%PY%" -X utf8 -u src\baseline_cc.py collect --crawls 2024 --region comparison >> "%LOG%" 2>&1
if errorlevel 1 ( echo baseline_run: FAILED comparison-2024 %date% %time% >> "%LOG%" & exit /b 1 )

echo baseline_run: all four collects complete %date% %time% >> "%LOG%"
exit /b 0
