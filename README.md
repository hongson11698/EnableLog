# Automatic Event log config
Config audit logs and other os security settings to monitor, based on cheat sheet at malwarearchaeology.com, EnableWindowsLogSettings of YamatoSecurity, documents from micosoft and other informations while searching internet :)
# Features

## Auto config windows event log, powershell, sysmon

1. Required Policy
+ Enable Advanced Audit Policy
+ LogSize:
  + Security: 512
  + Microsoft-Windows-PowerShell/Operational: 512
+ Process Create Audit 
  + Enable log Commandline
+ powershell.exe script block log
+ powershell.exe module log
+ Audit Handle Manipulation
+ Audit Registry
  + Monitor list common ASEPs 
+ Security Audit
  + Logoff
  + Logon
  + Special Logon


2. Recommend Policy For general
+ Enable optional log:
  + "Microsoft-Windows-TaskScheduler/Operational /e:true
  + "Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true
  + "Microsoft-Windows-DNS-Client/Operational" /e:true
+ Security Audit
  + File System
    + Monitor FileSystem activites
  + User Account Management
  + Audit Policy Change
  + Authentication Policy Change
  + Account Lockout
  + File Share

+ Log Size:
    + System/Application: Size: 128
    + "Microsoft-Windows-Windows Defender/Operational" /ms:134217728
    + "Microsoft-Windows-Bits-Client/Operational" /ms:1342177288
    + "Microsoft-Windows-WMI-Activity/Operational" /ms:134217728
    + "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /ms:134217728
    + "Microsoft-Windows-TaskScheduler/Operational" /ms:134217728
    + "Microsoft-Windows-DNS-Client/Operational"  /ms:134217728
    + "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /ms:134217728
+ powershell.exe transcript


3. Optional Audit Policy 
+ Increase log size
+ Security Audit For Windows Server 
  + Credential Validation
  + Kerberos Authentication Service
  + Kerberos Service Ticket Operations
  + Plug and Play Events
  + DPAPI Activity
  + Directory Service Access
  + Directory Service Changes
  + IPsec Main Mode
  + Certification Services
  + Detailed File Share
  + Kernel Object
  + Other Object Access Events
  + Removable Storage
  + MPSSVC Rule-Level Policy Change
  + Sensitive Privilege Use
  + IPsec Driver
  + Other System Events
  + Security State Change
  + Security System Extension
  + System Integrity

+ Security Audit For Windows Client
  + Credential Validation
  + Other Account Logon Events
  + Security Group Management
  + Other Account Management Events
  + Plug and Play Events
  + DPAPI Activity
  + Kernel Object
  + Other Object Access Events
  + Removable Storage
  + MPSSVC Rule-Level Policy Change
  + Other System Events
  + Security State Change
  + Security System Extension
  + System Integrity
  + Sensitive Privilege Use


4. Optional Sysmon install
+ Install sysmon with config
+ Size: 1024

## Windows support

- Win 7 / Win 10 / Win 11
- Win server 2008 -> 2022

# Usage
1. Adjust audit_level and sysmon_install option in config.ini

2. Apply config
- Using bat file
  - Run EnableLog.bat as administrator

- Using powershell
  - Open powershell.exe as Administrator in location of EnableLog.ps1 and run:
  - Unblock-File .\EnableLog.ps1
  - Unblock-File .\Scripts\*.ps1
  - .\EnableLog.ps1

3. Refresh Secpol GUI details if gpupdate doesn't work (Optional) 
  - Open Secpol.msc and goto Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group Policy Object
  - Right click "System Audit Policies - Local Group Policy Object" -> Import Settings
  - Select and apply .csv file in current folder (generated after run script)

# References
  - https://www.malwarearchaeology.com/cheat-sheets
  - https://github.com/Yamato-Security/EnableWindowsLogSettings
  - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
  - https://github.com/olafhartong/sysmon-modular/tree/master
  - internet...