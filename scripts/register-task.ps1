# Register the "LockWatch scan" task in Task Scheduler (docs/design.md section 7).
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1                 daily at 9:00 (a missed run starts at next logon)
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -At 13:30
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -Data D:\lw     data folder (default: data_dir in the config)
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\register-task.ps1 -Unregister     remove the task
#
# Keep this file ASCII only. Windows PowerShell 5.1 reads a file without BOM as the ANSI code page
# (cp932 on Japanese Windows), so non-ASCII text breaks the parser. pwsh (7) is not always installed.
#
# The task runs scripts\lockwatch-launch.py with the base interpreter's pythonw.exe (the "home" in
# .venv\pyvenv.cfg), so no console window opens. (.venv\Scripts\pythonw.exe made by uv 0.11 is a
# console launcher and opens one.) Check the result in <data>\last-run.log and the task's
# "Last Run Result": 0 = done, 1 = LockWatch bug, 2 = usage (e.g. no targets.json), 3 = already running,
# 4 = osv-scanner failed.
param(
    [string]$At = "09:00",
    [string]$Data = "",
    [string]$Name = "LockWatch scan",
    [switch]$Unregister
)
$ErrorActionPreference = "Stop"

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false
    Write-Host "Removed: $Name"
    return
}

$repo = Split-Path -Parent $PSScriptRoot
$cfg = Join-Path $repo ".venv\pyvenv.cfg"
if (-not (Test-Path $cfg)) {
    throw "$cfg not found. Run 'uv sync' in the repository first."
}
$homeLine = Get-Content $cfg -Encoding utf8 | Where-Object { $_ -match '^\s*home\s*=' } | Select-Object -First 1
$pythonw = if ($homeLine) { Join-Path ($homeLine -replace '^\s*home\s*=\s*', '').Trim() "pythonw.exe" } else { "" }
if (-not $pythonw -or -not (Test-Path $pythonw)) {
    throw "pythonw.exe of the base Python not found (the 'home' in $cfg)."
}
$launcher = Join-Path $repo "scripts\lockwatch-launch.py"
if (-not (Get-Command osv-scanner -ErrorAction SilentlyContinue)) {
    Write-Warning "osv-scanner is not on PATH (fine if osv_scanner is set in the config)."
}

$arguments = "`"$launcher`" --log"
if ($Data) { $arguments += " --data `"$Data`"" }
$arguments += " scan"

$action = New-ScheduledTaskAction -Execute $pythonw -Argument $arguments -WorkingDirectory $repo
$daily = New-ScheduledTaskTrigger -Daily -At $At
# Priority 7 = below normal. Run a missed start when available. Skip when there is no network.
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Priority 7 -ExecutionTimeLimit (New-TimeSpan -Hours 1)
# Run only while the user is logged on (no stored password).
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask -TaskName $Name -Action $action -Trigger $daily -Settings $settings `
    -Principal $principal -Description "Scan lock files with osv-scanner and write the vulnerability list ($repo)" -Force | Out-Null
Write-Host "Registered: $Name (daily at $At)"
Write-Host "  $pythonw $arguments"
