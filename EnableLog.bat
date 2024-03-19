@echo off
SET currentpath=%~dp0
echo 'Running %currentpath%EnableLog.ps1'
cd /d %currentpath%
@powershell -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File '%currentpath%EnableLog.ps1'"
@powershell -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File '%currentpath%Scripts\*.ps1'"
@powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%currentpath%EnableLog.ps1'"
pause