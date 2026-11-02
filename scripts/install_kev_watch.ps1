# Run it yourself (Jack). Installs nothing that sends traffic to any study site.
# Remove them:
#     Get-ScheduledTask -TaskName 'patch-watch kev watch*','patch-watch check 0645 kev' | Unregister-ScheduledTask -Confirm:$false

param([switch]$DryRun)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Py = Join-Path $Repo ".venv\Scripts\pythonw.exe"
$Watcher = Join-Path $Repo "scripts\kev_watch.py"
$Checks = Join-Path $Repo "scripts\pw_checks.py"

if ($DryRun) {
    Write-Host "Would register 'patch-watch kev watch am' daily at 6:15am: $Watcher"
    Write-Host "Would register 'patch-watch kev watch pm' daily at 5:30pm: $Watcher"
    Write-Host "Would register 'patch-watch check 0645 kev' daily at 6:45am: $Checks kevwatch"
    return
}

foreach ($p in $Py, $Watcher, $Checks) {
    if (-not (Test-Path $p)) { throw "not found: $p" }
}

function Register-Check($Name, $ScriptPath, $Argument, $At) {
    $args = "-X utf8 `"$ScriptPath`" $Argument"
    $action = New-ScheduledTaskAction -Execute $Py -Argument $args -WorkingDirectory $Repo
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
                -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -Settings $settings `
        -Description "patch-watch: $ScriptPath $Argument" -Force | Out-Null
    Write-Host "Installed '$Name'"
}

Register-Check "patch-watch kev watch am" $Watcher "" "6:15am"
Register-Check "patch-watch kev watch pm" $Watcher "" "5:30pm"
Register-Check "patch-watch check 0645 kev" $Checks "kevwatch" "6:45am"
