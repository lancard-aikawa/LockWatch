@echo off
rem Open the LockWatch window (status, results, settings, reports).
rem
rem Runs scripts\lockwatch-launch.py with a base interpreter's pythonw.exe found by
rem find-pythonw.ps1 (no .venv needed; .venv\Scripts\pythonw.exe made by uv 0.11 is a
rem console launcher and opens a console window).
setlocal
set "PYW="
for /f "usebackq delims=" %%p in (`powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0find-pythonw.ps1" -Tk`) do set "PYW=%%p"
if not defined PYW (
  echo Python 3.11 or later with tkinter was not found.
  echo Install it from https://www.python.org/ and run this again.
  pause
  exit /b 1
)
start "" "%PYW%" "%~dp0lockwatch-launch.py" gui %*
exit /b 0
