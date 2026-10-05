@echo off
rem Open the LockWatch window (status, results, settings, reports). Double-click this file.
rem
rem All the work is in scripts\lockwatch-gui.cmd: it finds Python 3.11 or later with tkinter
rem and opens the window without leaving a console window behind.
rem Keep this file ASCII only with CRLF line endings (cmd misreads UTF-8 and LF-only batch files).
call "%~dp0scripts\lockwatch-gui.cmd" %*
exit /b %errorlevel%
