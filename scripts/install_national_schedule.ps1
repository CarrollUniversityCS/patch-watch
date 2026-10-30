# patch-watch: install the recurring Windows task for the national extension (waves of other states).
#
# It runs scripts\national_day.cmd every day at 10:00, an hour after the Wisconsin task, so the primary arm
# always goes first. national_day.py decides: it refuses unless the PI released a wave
# (data\national_active_wave.txt), confirmed the public notice (logs\notice_live.txt), and Wisconsin completed
# today. Installing this task sends nothing by itself.
#
# Run it yourself (Jack) from the repo root, in a normal PowerShell window:
#     powershell -ExecutionPolicy Bypass -File scripts\install_national_schedule.ps1
# Pause it:   Disable-ScheduledTask -TaskName "patch-watch national day"
# Remove it after the 2027-01-19 run:
#             Unregister-ScheduledTask -TaskName "patch-watch national day" -Confirm:$false

$ErrorActionPreference = "Stop"
$TaskName = "patch-watch national day"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Cmd = Join-Path $Repo "scripts\national_day.cmd"
if (-not (Test-Path $Cmd)) { throw "not found: $Cmd" }

$action   = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$Cmd`"" -WorkingDirectory $Repo
$trigger  = New-ScheduledTaskTrigger -Daily -At 10:00am
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Hours 6) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Description "patch-watch: one national-extension snapshot per scheduled day (scripts/national_day.py decides)" -Force | Out-Null

Write-Host "Installed '$TaskName': daily 10:00, refuses until a wave is released."
Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo | Format-List NextRunTime, LastRunTime, LastTaskResult
