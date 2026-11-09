# Register the "LockWatch scan" task in Task Scheduler (docs/design.md section 7).
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1                 daily at 9:00 (a missed run starts at next logon)
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -At 13:30
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -Data D:\lw     data folder (default: data_dir in the config)
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -Unregister     remove the task
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -Assess         the "LockWatch assess" task instead
#       (daily at 9:30, runs "assess --new": Claude Code checks vulnerabilities found after the last assess, section 7.4;
#        it does nothing unless auto_assess is true in the config). -Assess -Unregister removes it.
#
# Keep this file ASCII only. Windows PowerShell 5.1 reads a file without BOM as the ANSI code page
# (cp932 on Japanese Windows), so non-ASCII text breaks the parser. pwsh (7) is not always installed.
#
# The task runs scripts\lockwatch-launch.py with a base interpreter's pythonw.exe found by
# scripts\find-pythonw.ps1 (Python 3.11 or later; no .venv needed), so no console window opens.
# (.venv\Scripts\pythonw.exe made by uv 0.11 is a console launcher and opens one.) Check the result in <data>\last-run.log and the task's
# "Last Run Result": 0 = done, 1 = LockWatch bug, 2 = usage (e.g. no targets.json), 3 = already running,
# 4 = osv-scanner failed, 5 = Claude Code missing or failed (assess task only).
param(
    [string]$At = "",
    [string]$Data = "",
    [string]$Name = "",
    [switch]$Assess,
    [switch]$Unregister
)
$ErrorActionPreference = "Stop"

if (-not $Name) { if ($Assess) { $Name = "LockWatch assess" } else { $Name = "LockWatch scan" } }
if (-not $At) { if ($Assess) { $At = "09:30" } else { $At = "09:00" } }

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    Write-Host "Removed: $Name"
    return
}

$repo = Split-Path -Parent $PSScriptRoot
# A base interpreter's pythonw.exe (no .venv needed). find-pythonw.ps1 prints the reason when none is found.
$pythonw = & (Join-Path $PSScriptRoot "find-pythonw.ps1")
if ($LASTEXITCODE -ne 0 -or -not $pythonw) {
    throw "No Python to run the task (see the message above)."
}
$launcher = Join-Path $repo "scripts\lockwatch-launch.py"
if ($Assess) {
    if (-not (Get-Command claude.exe -ErrorAction SilentlyContinue)) {
        Write-Warning "claude.exe (Claude Code, native build) is not on PATH. The task will end with code 5."
    }
} elseif (-not (Get-Command osv-scanner -ErrorAction SilentlyContinue)) {
    Write-Warning "osv-scanner is not on PATH (fine if osv_scanner is set in the config)."
}

$arguments = "`"$launcher`" --log"
if ($Data) { $arguments += " --data `"$Data`"" }
if ($Assess) { $arguments += " assess --new" } else { $arguments += " scan" }
# Claude Code takes up to 30 minutes per repository, and assess --new asks for at most auto_assess_max_repos of them.
if ($Assess) { $limit = New-TimeSpan -Hours 2 } else { $limit = New-TimeSpan -Hours 1 }

$action = New-ScheduledTaskAction -Execute $pythonw -Argument $arguments -WorkingDirectory $repo
$daily = New-ScheduledTaskTrigger -Daily -At $At
# Priority 7 = below normal. Run a missed start when available. Skip when there is no network.
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 7 -ExecutionTimeLimit $limit
# Run only while the user is logged on (no stored password).
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

$desc = "Scan lock files with osv-scanner and write the vulnerability list ($repo)"
if ($Assess) { $desc = "Let Claude Code check vulnerabilities found after the last assess ($repo)" }
Register-ScheduledTask -TaskName $Name -Action $action -Trigger $daily -Settings $settings `
    -Principal $principal -Description $desc -Force | Out-Null
Write-Host "Registered: $Name (daily at $At)"
Write-Host "  $pythonw $arguments"
