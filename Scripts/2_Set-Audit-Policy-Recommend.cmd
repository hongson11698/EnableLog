@echo off

Echo "Begin Set-Audit-Policy-Recommend"

:: Enable any logs that need to be enabled
echo "Enable log TaskScheduler"
wevtutil.exe sl "Microsoft-Windows-TaskScheduler/Operational" /e:true

echo "Enable log DriverFrameworks"
wevtutil.exe sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true

echo "Enable log DNS-Client"
wevtutil.exe sl "Microsoft-Windows-DNS-Client/Operational" /e:true
::
:: Set Recommend Audit

echo "Audit File System"
Auditpol.exe /set /subcategory:"File System" /success:enable /failure:disable

echo "Audit Audit Policy Change"
Auditpol.exe /set /subcategory:"Audit Policy Change" /success:enable /failure:enable

echo "Audit Authentication Policy Change"
Auditpol.exe /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

echo "Audit File Share"
Auditpol.exe /set /subcategory:"File Share" /success:enable /failure:enable

echo "Audit Account Lockout"
Auditpol.exe /set /subcategory:"Account Lockout" /success:enable /failure:disable

echo "Audit User Account Management"
Auditpol.exe /set /subcategory:"User Account Management" /success:enable /failure:enable

::
:: Set Log Size
echo "Set log size System"
wevtutil.exe sl System /ms:134217728

echo "Set log size Application"
wevtutil.exe sl Application /ms:134217728

echo "Set log size Windows Defender"
wevtutil.exe sl "Microsoft-Windows-Windows Defender/Operational" /ms:134217728

echo "Set log size Bits-Client"
wevtutil.exe sl "Microsoft-Windows-Bits-Client/Operational" /ms:134217728

echo "Set log size WMI-Activity"
wevtutil.exe sl "Microsoft-Windows-WMI-Activity/Operational" /ms:134217728

echo "Set log size TerminalServices"
wevtutil.exe sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /ms:134217728

echo "Set log sizeTaskScheduler"
wevtutil.exe sl "Microsoft-Windows-TaskScheduler/Operational" /ms:134217728

echo "Set log size DNS-Client"
wevtutil.exe sl "Microsoft-Windows-DNS-Client/Operational"  /ms:134217728

echo "Set log size Windows DriverFrameworks"
wevtutil.exe sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /ms:134217728
:: 
::powershell.exe Transciption
echo "Config powershell.exe Transciption"
reg.exe add "hklm\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg.exe add "hklm\Software\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f

:: 
::  Monitor high suspicous file system locations
echo "Setting audit Monitor high suspicous file system locations"
powershell.exe -File "%~dp0\6_Set-Audit-FileSystem.ps1"

Echo "Set-Audit-Policy-Recommend Done"
::set /p DUMMY=Hit ENTER to continue...