@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"
 
if not exist logs mkdir logs
 
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
    echo [錯誤] 找不到 Python，請安裝 https://www.python.org/downloads/
    pause
    exit /b 1
)
 
echo 使用: %PY%
set "ROOT=%~dp0"
start "" /MIN powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -LiteralPath '%ROOT%open-firewall.bat' -Verb RunAs -WindowStyle Hidden"
 
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080" ^| findstr "LISTENING"') do taskkill /PID %%a /F >nul 2>&1
taskkill /F /IM cloudflared.exe >nul 2>&1
taskkill /F /IM ngrok.exe >nul 2>&1
 
%PY% launch.py
pause
endlocal
