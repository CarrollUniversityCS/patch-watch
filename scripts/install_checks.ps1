# patch-watch: install the standalone daily checks and the hub refresh as Windows tasks.
#
# Why this file exists. The 08:30 / 09:45 / 11:30 / 18:00 checks used to be Hermes agent
# jobs. They are mechanical, so they now run scripts\pw_checks.py directly, with no model
# in the loop. Each run writes logs\hub\checks\<date>_<check>.json and rebuilds the local
# status page logs\hub\index.html. A sixth task rebuilds that page every 10 minutes.
# Hermes keeps the opt-out inbox and the weekly oversight audit.
#
# Run it from the repo root, in a normal PowerShell window:
#     powershell -ExecutionPolicy Bypass -File scripts\install_checks.ps1
# Remove them:
#     Get-ScheduledTask -TaskName 'patch-watch check*','patch-watch hub refresh' | Unregister-ScheduledTask -Confirm:$false
#
# This installs nothing that sends traffic. The only live task stays "patch-watch live day"
# (scripts\install_schedule.ps1); the started/lastchance checks may start THAT task once on
# a day it never fired, and the post-run check disables it on a halt.

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Py = Join-Path $Repo ".venv\Scripts\pythonw.exe"
$Script = Join-Path $Repo "scripts\pw_checks.py"
foreach ($p in $Py, $Script) { if (-not (Test-Path $p)) { throw "not found: $p" } }

function Register-Check($Name, $Arg, $Trigger, [switch]$Wake) {
    $action = New-ScheduledTaskAction -Execute $Py -Argument "-X utf8 `"$Script`" $Arg" -WorkingDirectory $Repo
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
                -MultipleInstances IgnoreNew -WakeToRun:$Wake
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $Trigger -Settings $settings `
        -Description "patch-watch: scripts/pw_checks.py $Arg (status in logs/hub/index.html)" -Force | Out-Null
    Write-Host "Installed '$Name'"
}

Register-Check "patch-watch check 0830 pre-run"     "prerun"     (New-ScheduledTaskTrigger -Daily -At 8:30am)
Register-Check "patch-watch check 0945 did-it-start" "started"    (New-ScheduledTaskTrigger -Daily -At 9:45am)
Register-Check "patch-watch check 1130 post-run"    "postrun"    (New-ScheduledTaskTrigger -Daily -At 11:30am)
Register-Check "patch-watch check 1800 last-chance" "lastchance" (New-ScheduledTaskTrigger -Daily -At 6:00pm) -Wake

$every = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddMinutes(5) `
         -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 120)
Register-Check "patch-watch hub refresh" "build" $every

Get-ScheduledTask -TaskName 'patch-watch*' | ForEach-Object {
    $i = $_ | Get-ScheduledTaskInfo
    "{0,-38} {1,-9} next {2}" -f $_.TaskName, $_.State, $i.NextRunTime
}
