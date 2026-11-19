@echo off
setlocal
if exist "%SystemRoot%\System32\chcp.com" "%SystemRoot%\System32\chcp.com" 65001 >nul
"%~dp0capture.exe" -connection-check >"%~dp0network-diagnostic.txt" 2>&1
set "GS_RESULT=%ERRORLEVEL%"
type "%~dp0network-diagnostic.txt"
echo Send network-diagnostic.txt only. Do not send cards or device key files.
pause
exit /b %GS_RESULT%
