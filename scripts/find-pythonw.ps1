# Print the full path of a pythonw.exe (Python 3.10 or later) that can run this repository.
# No .venv is needed: the program uses the standard library only.
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\find-pythonw.ps1 [-Tk]
# Exit code 0 and the path on stdout, or exit code 1 and the reason on stderr.
#
# Candidates, in order: the "home" in .venv\pyvenv.cfg, "uv python find", the py launcher, python on PATH.
# Each candidate is started once to check the version. If it is inside a venv, the base interpreter
# (sys.base_prefix) is used, because .venv\Scripts\pythonw.exe made by uv 0.11 is a console launcher
# and opens a console window. -Tk also requires tkinter (for the GUI).
#
# Keep this file ASCII only (Windows PowerShell 5.1 reads a file without BOM as cp932).
param([switch]$Tk)

$repo = Split-Path -Parent $PSScriptRoot
$candidates = New-Object System.Collections.Generic.List[string]

$cfg = Join-Path $repo ".venv\pyvenv.cfg"
if (Test-Path $cfg) {
    $homeLine = Get-Content $cfg -Encoding utf8 | Where-Object { $_ -match '^\s*home\s*=' } | Select-Object -First 1
    if ($homeLine) { $candidates.Add((Join-Path ($homeLine -replace '^\s*home\s*=\s*', '').Trim() "python.exe")) }
}
if (Get-Command uv -ErrorAction SilentlyContinue) {
    $p = & uv python find --system ">=3.10" 2>$null
    if ($LASTEXITCODE -eq 0 -and $p) { $candidates.Add(($p | Select-Object -First 1).Trim()) }
}
if (Get-Command py -ErrorAction SilentlyContinue) {
    $p = & py -3 -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $p) { $candidates.Add(($p | Select-Object -First 1).Trim()) }
}
foreach ($c in @(Get-Command python.exe -All -ErrorAction SilentlyContinue)) { $candidates.Add($c.Source) }

$probe = "import sys; assert sys.version_info >= (3, 10); print(sys.base_prefix)"
if ($Tk) { $probe = "import tkinter; " + $probe }
$tried = @()
foreach ($exe in $candidates) {
    if (-not $exe -or -not (Test-Path $exe) -or ($tried -contains $exe)) { continue }
    $tried += $exe
    $base = & $exe -c $probe 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $base) { continue }
    $base = ($base | Select-Object -First 1).Trim()
    $pythonw = Join-Path $base "pythonw.exe"
    # Microsoft Store Python cannot be started from its install folder; use its pythonw alias instead.
    if ($base -like "*\WindowsApps\*") { $pythonw = Join-Path (Split-Path -Parent $exe) "pythonw.exe" }
    if (Test-Path $pythonw) {
        Write-Output $pythonw
        exit 0
    }
}
$need = if ($Tk) { "Python 3.10 or later with tkinter" } else { "Python 3.10 or later" }
[Console]::Error.WriteLine("$need was not found. Install it from https://www.python.org/ (or 'uv python install'), then run this again.")
if ($tried) { [Console]::Error.WriteLine("Tried: " + ($tried -join ", ")) }
exit 1
