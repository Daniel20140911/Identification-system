@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 啟動中...
"C:\Users\11009_5d7j\AppData\Local\hardware-recognizer\venv-a32f48a503\Scripts\python.exe" -u launch.py
if errorlevel 1 pause
