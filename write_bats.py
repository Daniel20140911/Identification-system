"""寫入 CRLF 批次檔（避免 LF 導致雙擊閃退）。"""
from pathlib import Path
 
ROOT = Path(__file__).resolve().parent
 
START = r"""@echo off
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
"""
 
START_ZH = r"""@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "啟動伺服器.bat" (
    call "啟動伺服器.bat"
    exit /b 0
)
where py >nul 2>&1 && (py -3 launch.py & pause & exit /b 0)
python launch.py
pause
"""
 
STOP = r"""@echo off
chcp 65001 >nul
cd /d "%~dp0"
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8080" ^| findstr "LISTENING"') do taskkill /PID %%a /F >nul 2>&1
taskkill /F /IM cloudflared.exe >nul 2>&1
taskkill /F /IM ngrok.exe >nul 2>&1
echo 已關閉
pause
"""
 
FILES = {
    "start.bat": START,
    "stop.bat": STOP,
    "啟動辨識系統.bat": START_ZH,
    "關閉伺服器.bat": r"@echo off\ncd /d \"%~dp0\"\ncall stop.bat\n",
}
 
for name, content in FILES.items():
    path = ROOT / name
    path.write_text(content.replace("\n", "\r\n"), encoding="utf-8", newline="\r\n")
    print("wrote", name)
 