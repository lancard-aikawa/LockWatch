# Register the LockWatch tasks in Task Scheduler (docs/design.md sections 7 and 7.4).
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1                 register both tasks (a missed run starts at next logon)
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -At 13:30       time of "LockWatch scan" (default 9:00)
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -AssessAt 14:00 time of "LockWatch assess" (default 9:30)
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -Data D:\lw     data folder (default: data_dir in the config)
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -Unregister     remove both tasks
#
# "LockWatch scan" runs "scan" daily. "LockWatch assess" runs "assess --new" daily: Claude Code checks only the
# vulnerabilities found after the last assess of public github.com repositories. It does nothing unless
# auto_assess is true in the config, so the setting is the only switch; the task can stay registered.
#
# Keep this file ASCII only. Windows PowerShell 5.1 reads a file without BOM as the ANSI code page
# (cp932 on Japanese Windows), so non-ASCII text breaks the parser. pwsh (7) is not always installed.
#
# The tasks run scripts\lockwatch-launch.py with a base interpreter's pythonw.exe found by
# scripts\find-pythonw.ps1 (Python 3.11 or later; no .venv needed), so no console window opens.
# (.venv\Scripts\pythonw.exe made by uv 0.11 is a console launcher and opens one.) Check the result in <data>\last-run.log and the task's
# "Last Run Result": 0 = done, 1 = LockWatch bug, 2 = usage (e.g. no targets.json), 3 = already running,
# 4 = osv-scanner failed, 5 = Claude Code missing or failed (assess task only).
param(
    [string]$At = "09:00",
    [string]$AssessAt = "09:30",
    [string]$Data = "",
    [switch]$Unregister
)
$ErrorActionPreference = "Stop"

$scanName = "LockWatch scan"
$assessName = "LockWatch assess"

if ($Unregister) {
    foreach ($n in @($scanName, $assessName)) {
        if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $n -Confirm:$false
            Write-Host "Removed: $n"
        } else {
            Write-Host "Not registered: $n"
        }
    }
    return
}

$repo = Split-Path -Parent $PSScriptRoot
# The exe build (docs/design.md section 9.1) has lockwatchw.exe (no console) next to scripts\; use it, no Python needed.
# Otherwise use a base interpreter's pythonw.exe (no .venv needed). find-pythonw.ps1 prints the reason when none is found.
$exeW = Join-Path $repo "lockwatchw.exe"
if (Test-Path -LiteralPath $exeW) {
    $pythonw = $exeW
    $base = "--log"
} else {
    $pythonw = & (Join-Path $PSScriptRoot "find-pythonw.ps1")
    if ($LASTEXITCODE -ne 0 -or -not $pythonw) {
        throw "No Python to run the task (see the message above)."
    }
    $launcher = Join-Path $repo "scripts\lockwatch-launch.py"
    $base = "`"$launcher`" --log"
}
if (-not (Get-Command osv-scanner -ErrorAction SilentlyContinue) -and -not (Test-Path -LiteralPath (Join-Path $repo "osv-scanner.exe"))) {
    Write-Warning "osv-scanner is not on PATH (fine if osv_scanner is set in the config)."
}

if ($Data) { $base += " --data `"$Data`"" }

# Run only while the user is logged on (no stored password).
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

function Register-LockWatchTask([string]$Name, [string]$Time, [string]$Command, [int]$Hours, [string]$Desc) {
    $arguments = "$base $Command"
    $action = New-ScheduledTaskAction -Execute $pythonw -Argument $arguments -WorkingDirectory $repo
    $daily = New-ScheduledTaskTrigger -Daily -At $Time
    # Priority 7 = below normal. Run a missed start when available. Skip when there is no network.
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RunOnlyIfNetworkAvailable `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 7 -ExecutionTimeLimit (New-TimeSpan -Hours $Hours)
    Register-ScheduledTask -TaskName $Name -Action $action -Trigger $daily -Settings $settings `
        -Principal $principal -Description "$Desc ($repo)" -Force | Out-Null
    Write-Host "Registered: $Name (daily at $Time)"
    Write-Host "  $pythonw $arguments"
}

Register-LockWatchTask $scanName $At "scan" 1 "Scan lock files with osv-scanner and write the vulnerability list"
# Claude Code takes up to 30 minutes per repository, and assess --new asks for at most auto_assess_max_repos of them.
Register-LockWatchTask $assessName $AssessAt "assess --new" 2 "Let Claude Code check vulnerabilities found after the last assess (only when auto_assess is true)"
if (-not (Get-Command claude.exe -ErrorAction SilentlyContinue)) {
    Write-Host "Note: claude.exe (Claude Code, native build) is not on PATH. $assessName ends with code 5 if auto_assess is turned on."
}
