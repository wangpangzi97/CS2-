@echo off
setlocal
echo Close all gamesense clients first. No Windows account switch is required.
echo This only archives invalid encrypted device state. It does not reset the server.
echo Valid device keys will not be reset. A ciphertext backup will be retained.
echo You may use the native device repair EXE if CMD is unavailable.
if not exist "%~dp0capture.exe" goto missing_capture
if not exist "%SystemRoot%\System32\choice.exe" goto missing_choice
"%SystemRoot%\System32\choice.exe" /C YN /N /M "Archive invalid device state? [Y/N] "
set "GS_CONFIRM=%ERRORLEVEL%"
if "%GS_CONFIRM%"=="1" goto repair
if "%GS_CONFIRM%"=="2" goto cancelled
echo CONFIRMATION_COMMAND_FAILED: %GS_CONFIRM%
echo No repair was performed. Use the native repair EXE or send this error.
pause
exit /b %GS_CONFIRM%
:repair
"%~dp0capture.exe" -archive-invalid-device-key >"%~dp0device-repair-result.txt" 2>&1
set "GS_RESULT=%ERRORLEVEL%"
type "%~dp0device-repair-result.txt"
echo Only ARCHIVED means a backup was created. Then run gamesense.exe and type your card.
pause
exit /b %GS_RESULT%
:cancelled
echo CANCELLED: device state was not changed.
pause
exit /b 0
:missing_capture
echo CAPTURE_EXE_MISSING: fully extract the package into a new folder.
pause
exit /b 66
:missing_choice
echo CONFIRMATION_COMMAND_MISSING: use the native repair EXE. No repair was performed.
pause
exit /b 69
