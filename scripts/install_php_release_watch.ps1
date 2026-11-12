# Run it yourself (Jack). Installs nothing that sends traffic to any study site: the watcher reads php.net's public
# release list and the check reads local files.
#
#   .\scripts\install_php_release_watch.ps1 -DryRun                      # show what would be registered
#   .\scripts\install_php_release_watch.ps1                              # register the three daily tasks
#   .\scripts\install_php_release_watch.ps1 -ReleaseWindow 2026-11-18,2026-11-19,2026-11-20
#                                                                         # also read php.net hourly on those days
#
# Remove them:
#     Get-ScheduledTask -TaskName 'patch-watch php release watch*','patch-watch check 0705 phpwatch' | Unregister-ScheduledTask -Confirm:$false

param([switch]$DryRun, [string[]]$ReleaseWindow = @())

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Py = Join-Path $Repo ".venv\Scripts\pythonw.exe"
$Watcher = Join-Path $Repo "scripts\php_release_watch.py"
$Checks = Join-Path $Repo "scripts\pw_checks.py"

# "-File" hands a comma list over as one string, so split it here.
$ReleaseWindow = @($ReleaseWindow | ForEach-Object { $_ -split ",\s*" } | Where-Object { $_ })
foreach ($d in $ReleaseWindow) {
    if ($d -notmatch '^\d{4}-\d{2}-\d{2}$') { throw "-ReleaseWindow takes dates like 2026-11-18, not '$d'" }
}

if ($DryRun) {
    Write-Host "Would register 'patch-watch php release watch am' daily at 6:50am: $Watcher, then $Checks phpwatch"
    Write-Host "Would register 'patch-watch php release watch pm' daily at 4:50pm: $Watcher, then $Checks phpwatch"
    Write-Host "Would register 'patch-watch check 0705 phpwatch' daily at 7:05am: $Checks phpwatch"
    foreach ($d in $ReleaseWindow) {
        Write-Host "Would read php.net, then run the phpwatch check, hourly from 9:05am for 12 hours on ${d} ('patch-watch php release watch window')"
    }
    return
}

foreach ($p in $Py, $Watcher, $Checks) {
    if (-not (Test-Path $p)) { throw "not found: $p" }
}

function New-Settings {
    New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -MultipleInstances IgnoreNew
}

function Register-Check($Name, $ScriptPath, $Argument, $At) {
    $args = "-X utf8 `"$ScriptPath`" $Argument"
    $action = New-ScheduledTaskAction -Execute $Py -Argument $args -WorkingDirectory $Repo
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -Settings (New-Settings) `
        -Description "patch-watch: $ScriptPath $Argument" -Force | Out-Null
    Write-Host "Installed '$Name'"
}

# Each watcher task has TWO actions that run in order: read php.net, then run the phpwatch check on what was just read. A new
# release therefore raises its alert and toast within a minute of being seen, not at the next morning's check.
function New-WatchActions {
    $read = New-ScheduledTaskAction -Execute $Py -Argument "-X utf8 `"$Watcher`"" -WorkingDirectory $Repo
    $check = New-ScheduledTaskAction -Execute $Py -Argument "-X utf8 `"$Checks`" phpwatch" -WorkingDirectory $Repo
    return @($read, $check)
}

function Register-Watch($Name, $At) {
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    Register-ScheduledTask -TaskName $Name -Action (New-WatchActions) -Trigger $trigger -Settings (New-Settings) `
        -Description "patch-watch: read php.net, then run the phpwatch check" -Force | Out-Null
    Write-Host "Installed '$Name'"
}

Register-Watch "patch-watch php release watch am" "6:50am"
Register-Watch "patch-watch php release watch pm" "4:50pm"
Register-Check "patch-watch check 0705 phpwatch" $Checks "phpwatch" "7:05am"

if ($ReleaseWindow.Count -gt 0) {
    $triggers = @()
    foreach ($d in $ReleaseWindow) {
        $at = [datetime]::ParseExact("$d 09:05", "yyyy-MM-dd HH:mm", $null)
        $triggers += New-ScheduledTaskTrigger -Once -At $at -RepetitionInterval (New-TimeSpan -Hours 1) `
            -RepetitionDuration (New-TimeSpan -Hours 12)
    }
    Register-ScheduledTask -TaskName "patch-watch php release watch window" -Action (New-WatchActions) -Trigger $triggers `
        -Settings (New-Settings) -Description "patch-watch: hourly php.net read and phpwatch check on expected release days" -Force | Out-Null
    Write-Host "Installed 'patch-watch php release watch window' for: $($ReleaseWindow -join ', ')"
}
