@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "啟動伺服器.bat" (
    call "啟動伺服器.bat"
    exit /b 0
)
where py >nul 2>&1 && (py -3 launch.py & pause & exit /b 0)
python launch.py
pause
