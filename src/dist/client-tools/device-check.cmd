@echo off
setlocal
if exist "%SystemRoot%\System32\chcp.com" "%SystemRoot%\System32\chcp.com" 65001 >nul
"%~dp0capture.exe" -device-check >"%~dp0device-diagnostic.txt" 2>&1
set "GS_RESULT=%ERRORLEVEL%"
type "%~dp0device-diagnostic.txt"
echo Send device-diagnostic.txt only. Do not send BIN, DEVICE or BACKUP files.
pause
exit /b %GS_RESULT%
