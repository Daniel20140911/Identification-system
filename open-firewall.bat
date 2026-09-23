@echo off
chcp 65001 >nul
netsh advfirewall firewall delete rule name="物品辨識8080" >nul 2>&1
netsh advfirewall firewall delete rule name="物品辨識5050" >nul 2>&1
netsh advfirewall firewall delete rule name="物品辨識5443" >nul 2>&1
netsh advfirewall firewall add rule name="物品辨識8080" dir=in action=allow protocol=TCP localport=8080 profile=any enable=yes
if errorlevel 1 (
    echo Need administrator
    pause
    exit /b 1
)
echo Firewall OK: 8080
ping 127.0.0.1 -n 3 >nul
