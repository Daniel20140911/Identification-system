@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1
cd /d "%~dp0"
if not exist logs mkdir logs

set "LOG=logs\diagnose.log"
echo === %date% %time% ===> "%LOG%"
echo CD=%CD%>> "%LOG%"
echo USER=%USERNAME%>> "%LOG%"
echo COMPUTER=%COMPUTERNAME%>> "%LOG%"

where python>> "%LOG%" 2>&1
where py>> "%LOG%" 2>&1
python --version>> "%LOG%" 2>&1
py -3 --version>> "%LOG%" 2>&1

if exist venv\pyvenv.cfg (
    echo --- pyvenv.cfg --->> "%LOG%"
    type venv\pyvenv.cfg>> "%LOG%"
)

if exist venv\Scripts\python.exe (
    venv\Scripts\python.exe -c "import sys; print(sys.executable)">> "%LOG%" 2>&1
) else (
    echo venv python missing>> "%LOG%"
)

echo.
echo 診斷完成：%LOG%
type "%LOG%"
echo.
pause
endlocal
