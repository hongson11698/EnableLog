@echo off

Echo "Begin Set-Audit-Policy-Optional"

:: Set all other important logs to 128 MB. Increase or decrease to fit your environment.
echo "Set log size Firewall"
wevtutil.exe sl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /ms:134217728

echo "Set log size NTLM"
wevtutil.exe sl "Microsoft-Windows-NTLM/Operational" /ms:134217728
::wevtutil.exe sl "Microsoft-Windows-Security-Mitigations/KernelMode" /ms:134217728
::wevtutil.exe sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728

echo "Set log size PrintService"
wevtutil.exe sl "Microsoft-Windows-PrintService/Admin" /ms:134217728
::wevtutil.exe sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728
echo "Set log size PrintService"
wevtutil.exe sl "Microsoft-Windows-PrintService/Operational" /ms:134217728
::wevtutil.exe sl "Microsoft-Windows-SmbClient/Security" /ms:134217728

echo "Set log size AppLocker"
wevtutil.exe sl "Microsoft-Windows-AppLocker/MSI and Script" /ms:134217728
wevtutil.exe sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:134217728
::wevtutil.exe sl "Microsoft-Windows-AppLocker/Packaged app-Deployment" /ms:134217728
::wevtutil.exe sl "Microsoft-Windows-AppLocker/Packaged app-Execution" /ms:134217728

echo "Set log size CodeIntegrity"
wevtutil.exe sl "Microsoft-Windows-CodeIntegrity/Operational" /ms:134217728

echo "Set log size Diagnosis-Scripted"
wevtutil.exe sl "Microsoft-Windows-Diagnosis-Scripted/Operational" /ms:134217728

:: Check windows os type (server or workstation)
for /f "tokens=2 delims==" %%a in ( 'wmic.exe os get producttype /value' ) do (
    set PRODUCT_TYPE=%%a
)
if %PRODUCT_TYPE%==1 goto :CLIENT_AUDIT
goto :SERVER_AUDIT

:: Enable audit option for client workstation 
:CLIENT_AUDIT
Echo "Audit for workstation"

echo "Audit Credential Validation"
Auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable
echo "Audit Other Account Logon Events"
Auditpol.exe /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
echo "Audit Security Group Management"
Auditpol.exe /set /subcategory:"Security Group Management" /success:enable /failure:enable
echo "Audit Other Account Management Events"
Auditpol.exe /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
::echo "Audit Plug and Play Events"
::Auditpol.exe /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
echo "Audit DPAPI Activity"
Auditpol.exe /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
echo "Audit Kernel Object"
Auditpol.exe /set /subcategory:"Kernel Object" /success:enable /failure:enable

::echo "Audit Removable Storage"
::Auditpol.exe /set /subcategory:"Removable Storage" /success:enable /failure:enable

Auditpol.exe /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
echo "Audit MPSSVC Rule-Level Policy Change"
Auditpol.exe /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
echo "Audit Other System Events"
Auditpol.exe /set /subcategory:"Other System Events" /success:enable /failure:enable
echo "Audit Security State Change"
Auditpol.exe /set /subcategory:"Security State Change" /success:enable /failure:enable
echo "Audit Security System Extension"
Auditpol.exe /set /subcategory:"Security System Extension" /success:enable /failure:enable
echo "Audit System Integrity"
Auditpol.exe /set /subcategory:"System Integrity" /success:enable /failure:enable
echo "Audit Sensitive Privilege Use"
Auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
goto :END_AUDIT

:: Enable audit option for server/domain controller
:SERVER_AUDIT
Echo "Audit for server"
echo "Audit Credential Validation"
Auditpol.exe /set /subcategory:"Credential Validation" /success:enable /failure:enable
echo "Audit Kerberos Authentication Service"
Auditpol.exe /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
echo "Audit Kerberos Service Ticket Operations"
Auditpol.exe /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
::echo "Audit Plug and Play Events"
::Auditpol.exe /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
echo "Audit DPAPI Activity"
Auditpol.exe /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
echo "Audit Directory Service Access"
Auditpol.exe /set /subcategory:"Directory Service Access" /success:enable /failure:enable
echo "Audit Directory Service Changes"
Auditpol.exe /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
echo "Audit IPsec Main Mode"
Auditpol.exe /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable 
echo "Audit Certification Services"
Auditpol.exe /set /subcategory:"Certification Services" /success:enable /failure:enable
echo "Audit Detailed File Share"
Auditpol.exe /set /subcategory:"Detailed File Share" /success:enable /failure:enable
echo "Audit Kernel Object"
Auditpol.exe /set /subcategory:"Kernel Object" /success:enable /failure:enable
echo "Audit Other Object Access Events"
Auditpol.exe /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
::echo "Audit Removable Storage"
::Auditpol.exe /set /subcategory:"Removable Storage" /success:enable /failure:enable
echo "Audit MPSSVC Rule-Level Policy Change"
Auditpol.exe /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
echo "Audit Sensitive Privilege Use"
Auditpol.exe /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
echo "Audit IPsec Driver"
Auditpol.exe /set /subcategory:"IPsec Driver" /success:enable /failure:enable
echo "Audit Other System Events"
Auditpol.exe /set /subcategory:"Other System Events" /success:enable /failure:enable
echo "Audit Security State Change"
Auditpol.exe /set /subcategory:"Security State Change" /success:enable /failure:enable
echo "Audit Security System Extension"
Auditpol.exe /set /subcategory:"Security System Extension" /success:enable /failure:enable
echo "Audit System Integrity"
Auditpol.exe /set /subcategory:"System Integrity" /success:enable /failure:enable
goto :END_AUDIT

:END_AUDIT
Echo "Set-Audit-Policy-Optional Done"
::set /p DUMMY=Hit ENTER to continue...