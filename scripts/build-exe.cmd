@echo off
REM Build dist\LockWatch\ (lockwatch.exe, lockwatchw.exe) and dist\LockWatch-<version>-win-x64.zip.
REM See docs/design.md section 9.1. The zip has no lockwatch.json and no data\ (they stay next to the exe).
REM Keep this file ASCII only and CRLF: cmd.exe reads .cmd files as cp932.
setlocal
cd /d "%~dp0.."
uv run --python 3.13 --group build pyinstaller --noconfirm --clean --distpath dist --workpath build\pyinstaller scripts\lockwatch.spec
if errorlevel 1 goto :fail
uv run --python 3.13 python scripts\package_exe.py
if errorlevel 1 goto :fail
exit /b 0

:fail
echo.
echo build failed.
exit /b 1
