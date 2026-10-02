@echo off
rem Open the LockWatch window (status, results, settings, reports).
rem
rem .venv\Scripts\pythonw.exe made by uv 0.11 is a console launcher (same file as
rem python.exe), so it opens a console window. Run the base interpreter's
rem pythonw.exe (the "home" in .venv\pyvenv.cfg) with lockwatch-launch.py instead.
setlocal
set "ROOT=%~dp0.."
set "CFG=%ROOT%\.venv\pyvenv.cfg"
if not exist "%CFG%" goto nopython
set "HOMEDIR="
for /f "usebackq tokens=1,* delims== " %%a in ("%CFG%") do if /i "%%a"=="home" set "HOMEDIR=%%b"
if not defined HOMEDIR goto nopython
if not exist "%HOMEDIR%\pythonw.exe" goto nopython
start "" "%HOMEDIR%\pythonw.exe" "%~dp0lockwatch-launch.py" gui %*
exit /b 0

:nopython
echo Python for LockWatch not found (%CFG%).
echo Run "uv sync" in the repository folder first.
pause
exit /b 1
