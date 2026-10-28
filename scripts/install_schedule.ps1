# patch-watch: install the ONE recurring Windows task that carries the live schedule.
#
# Why this file exists. Snapshot days were being lost: the task passed a fixed date to
# live_day.cmd (so a recurring task refused every later day), and a machine asleep at
# 09:00 simply missed the day. This task runs live_day.cmd with no argument every day at
# 09:00, catches up as soon as the machine is awake if 09:00 was missed, and wakes the
# machine to run. live_day.py decides whether today is a snapshot day, refuses after 19:00
# and refuses a second run, so this task cannot add traffic the plan does not allow.
#
# Run it yourself (Jack) from the repo root, in a normal PowerShell window:
#     powershell -ExecutionPolicy Bypass -File scripts\install_schedule.ps1
# Check it:   Get-ScheduledTask -TaskName "patch-watch live day" | Get-ScheduledTaskInfo
# Pause it:   Disable-ScheduledTask -TaskName "patch-watch live day"
# Remove it after the 2027-01-19 run:
#             Unregister-ScheduledTask -TaskName "patch-watch live day" -Confirm:$false
#
# Gate A is not set here. live_day.cmd supplies PATCHWATCH_GATE_A, and src/config.py's
# LIVE_REQUESTS_ENABLED must also be True in your working tree.

$ErrorActionPreference = "Stop"
$TaskName = "patch-watch live day"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Cmd = Join-Path $Repo "scripts\live_day.cmd"
if (-not (Test-Path $Cmd)) { throw "not found: $Cmd" }

# Remove any older dated tasks pointing at live_day.cmd, so two tasks never race.
Get-ScheduledTask | Where-Object {
    $_.TaskName -ne $TaskName -and ($_.Actions | Where-Object { "$($_.Execute) $($_.Arguments)" -like "*live_day.cmd*" })
} | ForEach-Object {
    Write-Host "Removing old task: $($_.TaskName)"
    Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false
}

$action   = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c `"$Cmd`"" -WorkingDirectory $Repo
$trigger  = New-ScheduledTaskTrigger -Daily -At 9:00am
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -WakeToRun `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Hours 4) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Description "patch-watch: one live snapshot per scheduled day (scripts/live_day.py decides)" -Force | Out-Null

Write-Host "Installed '$TaskName': daily 09:00, catch-up when awake, wakes the machine."
Write-Host "The machine clock must be America/Chicago for 09:00 to mean 09:00 Central;"
Write-Host "live_day.py itself always uses America/Chicago for the calendar day and the 19:00 cut-off."
Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo | Format-List NextRunTime, LastRunTime, LastTaskResult
