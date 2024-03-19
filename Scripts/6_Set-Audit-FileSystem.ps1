function Set-Audit-FileSystem {
    <#
    .SYNOPSIS
    #  This is based on the 'Windows File Auditing Cheat Sheet'
    #  www.MalwareArchaeology.com\cheat-sheets
    #
    Set File or Dir Auditing for Everyone

    #>
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$path,
        [string]$AccessSent,
        [string]$KeyAndSubs
    )
    try {
        if (Test-Path -LiteralPath $path) {
            $ACL = new-object System.Security.AccessControl.DirectorySecurity
            $AccessRule = new-object System.Security.AccessControl.FileSystemAuditRule("Everyone", $AccessSent, "ContainerInherit, ObjectInherit", "NoPropagateInherit", "Success")
            $ACL.SetAuditRule($AccessRule)
            $ACL | Set-Acl $path
            Write-Output "Set-Audit-FileSystem  OKAY: $path"
        }
        else {
            Write-Output "Set-Audit-FileSystem Error: $path not found"
        }
    }
    catch {
        Write-Output "Set-Audit-FileSystem Error: $path"
    }
}

Write-Output "Begin Set-Audit-FileSystem"

$RootDir = $Env:SystemDrive
$dataFolder = "Music", "Pictures", "Videos", "Documents", "Contacts"
$userFolder = Get-ChildItem -LiteralPath "$env:SystemDrive\users" -Force | Where-Object { $_.PSIsContainer } | Select-Object FullName
if ($userFolder) {
    foreach ($user in $userFolder) {
        # User startup folder
        $userDir = $user.FullName
        Set-Audit-FileSystem "$userDir\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes"
        foreach ($folder in $dataFolder) {
            # User suspicious folder
            $checkDir = "{0}\{1}" -f $userDir, $folder
            Set-Audit-FileSystem "$checkDir" "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes"
        }
    }
}

# Global startup folder
Set-Audit-FileSystem "$RootDir\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes"
Set-Audit-FileSystem "$RootDir\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes"

# Suspicious/Public folder, noisy
$listDir = "$RootDir\Users\public".ToLower(), "$RootDir\ProgramData".ToLower(), "$env:SystemDrive\PerfLogs".ToLower(), "$Env:windir\debug".ToLower(), "$env:Public".ToLower(), "$env:windir\ServiceProfiles\"
foreach ($folder in $listDir) {
    Set-Audit-FileSystem $folder "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes" 
}

# SAM/SECURITY monitor
Set-Audit-FileSystem "$RootDir\Windows\System32\config\SAM" "Modify,Read,ReadAndExecute,ReadAttributes,ReadData,ReadExtendedAttributes,ReadPermissions"
Set-Audit-FileSystem "$RootDir\Windows\System32\config\SECURITY" "Modify,Read,ReadAndExecute,ReadAttributes,ReadData,ReadExtendedAttributes,ReadPermissions"

# IIS Webserver config
Set-Audit-FileSystem "$RootDir\windows\system32\inetsrv\config\applicationhost.config" "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes"
Set-Audit-FileSystem "$RootDir\windows\syswow64\inetsrv\config\applicationhost.config" "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes"

# NTDS
Set-Audit-FileSystem "$RootDir\windows\NTDS\Ntds.dit" "Modify,Read,ReadAndExecute,ReadAttributes,ReadData,ReadExtendedAttributes,ReadPermissions"

Write-Output "Set-Audit-FileSystem Done"
