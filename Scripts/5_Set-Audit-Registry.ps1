######################################################
#                                                    #
#  powershell.exe AUDITING SCRIPT TO LOG THE BAD STUFF   #
#         This script adds Registry auditing         #
#      to objects commonly accessed by malware.      #
#                   Reference from                   #
#             www.MalwareArchaeology.com             #
#                                                    #
######################################################
#
function AuditAndSegmentExistingIndividualRegKeys {
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$key,
        [string]$AccessSent,
        [string]$KeyAndSubs
    )
    
    if(Test-Path $key){
        $hold = Get-Acl $key
        $hold = $hold.path
        $RegKey_ACL = Get-Acl -Path $hold
        $AccessRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone",$AccessSent,$KeyAndSubs,"none","Success")
        $RegKey_ACL.AddAuditRule($AccessRule)
        $RegKey_ACL | Set-Acl -Path $hold
        Write-Output "Set-Audit-Registry-ASEP  OKAY: $hold"
     }else{
        Write-Output "Set-Audit-Registry-ASEP Error: $key not found" 
     }
}
function AuditAndSegmentExistingUserKeys {
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$keySent,
        [string]$AccessSent,
        [string]$KeyAndSubs
    )
    $hkeyUsers = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('USERS', $env:COMPUTERNAME)
    $hkeyUsersSubkeys = $hkeyUsers.GetSubKeyNames()
    Set-Location Registry::\HKEY_USERS  | out-null
    New-PSDrive HKU Registry HKEY_USERS  | out-null
    Set-Location HKU:  | out-null
    foreach($key in $hkeyUsersSubkeys){
        if(Test-Path -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$key\$keySent\"){
            $RegKey_ACL = Get-Acl -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$key\$keySent\"
            $AccessRule = New-Object System.Security.AccessControl.RegistryAuditRule("Everyone",$AccessSent,$KeyAndSubs,"none","Success")
            $RegKey_ACL.AddAuditRule($AccessRule)
            $RegKey_ACL | Set-Acl -Path "Microsoft.PowerShell.Core\Registry::HKEY_USERS\$key\$keySent\"
            Write-Output "Set-Audit-Registry-ASEP  OKAY: Microsoft.PowerShell.Core\Registry::HKEY_USERS\$key\$keySent\"
        }else{
            Write-Output "Set-Audit-Registry-ASEP Error: $keySent not found"
        }
    }
}

Write-Output "Begin Set-Audit-Registry-ASEP"

# Autorun Entry
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"

AuditAndSegmentExistingIndividualRegKeys "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"

AuditAndSegmentExistingUserKeys "Software\Microsoft\Windows\CurrentVersion\Run" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "Software\Microsoft\Windows\CurrentVersion\RunOnce" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "Software\Microsoft\Windows\CurrentVersion\RunServicesOnce" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "Software\Microsoft\Windows\CurrentVersion\RunServices" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"


# Explorer Autorun Entry
AuditAndSegmentExistingIndividualRegKeys "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"


# Winlogon Autorun Entry
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "Software\Wow6432NodeMicrosoft\Windows NT\CurrentVersion\Winlogon" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"


# Alternative Autorun Entry
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"
AuditAndSegmentExistingUserKeys "Software\Microsoft\Windows NT\CurrentVersion\Windows" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"
AuditAndSegmentExistingUserKeys "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"
AuditAndSegmentExistingUserKeys "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"

# Local Policy Startup Script
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Policies\Microsoft\Windows\System\Scripts" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingUserKeys "Software\Policies\Microsoft\Windows\System\Scripts" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"

# Other Windows Security Setting
AuditAndSegmentExistingIndividualRegKeys "HKLM:\System\CurrentControlSet\Control\Lsa" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\System\CurrentControlSet\Control\SafeBoot" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SecurityProviders" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\System\CurrentControlSet\Control\SecurityProviders\SecurityProviders\WDigest" "SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "none"
AuditAndSegmentExistingIndividualRegKeys "HKLM:\SAM" "ReadKey,QueryValues,SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership" "containerinherit"

Write-Output "Set-Audit-Registry-ASEP Done"