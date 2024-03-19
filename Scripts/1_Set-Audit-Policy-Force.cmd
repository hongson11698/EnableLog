@echo off

Echo "Begin Set-Audit-Policy-Force"


::
::  Force Advance Audit Policy
::
echo "Force Advance Audit Policy"
reg.exe add "hklm\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
::
:: SET THE LOG SIZE -
echo "SET THE LOG SIZE Security"
wevtutil.exe sl Security /ms:524288000
::
echo "SET THE LOG SIZE Windows Powershell"
wevtutil.exe sl "Windows Powershell" /ms:524288000
::
echo "SET THE LOG SIZE PowerShell/Operational"
wevtutil.exe sl "Microsoft-Windows-PowerShell/Operational" /ms:524288000
::
:: SET Events to log the Command Line
:: ---------------------
::
echo "SET Events to log the Command Line (KB3031432 required for WinServer2k8)"
:: KB3031432, restart requied
reg.exe add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
::  Set Module Logging for PowerShell
::
echo "Set Module Logging for PowerShell"
reg.exe add "hklm\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg.exe add "hklm\Software\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f

reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"  /f /v ^* /t REG_SZ /d ^*
reg.exe add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"  /f /v ^* /t REG_SZ /d ^*

reg.exe add "hklm\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg.exe add "hklm\Software\Wow6432NodePolicies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

::

:: Reset audit policy
echo "Reset audit policy"
Auditpol.exe  /clear /y

:: Set Critical Audit
echo "Audit Process Creation"
Auditpol.exe /set /subcategory:"Process Creation" /success:enable /failure:enable

echo "Audit Handle Manipulation"
Auditpol.exe /set /subcategory:"Handle Manipulation" /success:enable /failure:disable

echo "Audit Registry"
Auditpol.exe /set /subcategory:"Registry" /success:enable /failure:disable

echo "Audit Logon"
Auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable

echo "Audit Special Logon"
Auditpol.exe /set /subcategory:"Special Logon" /success:enable /failure:enable

echo "Audit Logoff"
Auditpol.exe /set /subcategory:"Logoff" /success:enable /failure:disable

echo "Audit Other Object Access Events"
Auditpol.exe /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

::  Monitor list common ASEPs 

echo "Setting audit Monitor list common ASEPs and OS security"
powershell.exe -File "%~dp0\5_Set-Audit-Registry.ps1"

Echo "Set-Audit-Policy-Force Done"
::set /p DUMMY=Hit ENTER to continue...