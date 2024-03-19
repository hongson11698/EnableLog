#    _____             _     _      _                
#   | ____|_ __   __ _| |__ | | ___| |    ___   __ _ 
#   |  _| | '_ \ / _` | '_ \| |/ _ \ |   / _ \ / _` |
#   | |___| | | | (_| | |_) | |  __/ |__| (_) | (_| |
#   |_____|_| |_|\__,_|_.__/|_|\___|_____\___/ \__, |
#                                              |___/ 
#
#   Setting audit log and other os security to monitor
#   References
#       https://www.malwarearchaeology.com/cheat-sheets
#       https://github.com/Yamato-Security/EnableWindowsLogSettings
#       https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations
#       https://github.com/Neo23x0/sysmon-config
#       And the internet...
function Get-IniContent ($filePath) {
    $ini = @{}
    switch -regex -file $FilePath {
        "^\[(.+)\]" # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

try 
{
    Write-Output "#    _____             _     _      _                "
    Write-Output "#   | ____|_ __   __ _| |__ | | ___| |    ___   __ _ "
    Write-Output "#   |  _| | '_ \ / _` | '_ \| |/ _ \ |   / _ \ / _` |"
    Write-Output "#   | |___| | | | (_| | |_) | |  __/ |__| (_) | (_| |"
    Write-Output "#   |_____|_| |_|\__,_|_.__/|_|\___|_____\___/ \__, |"
    Write-Output "#                                              |___/ "
    
    Write-Output "Begin config log"
    $currentDir = (Get-Item .).FullName

    Set-Location -Path $currentDir | Out-Null
    
    Write-Output "Get config from config.ini"
    
    $data = Get-IniContent -filePath "$currentDir\config.ini"
    $Body = ""

    switch ($data['Global']['audit_level'])
    {
        # Audit level 1
        1
        {
            Write-Output "Config audit level 1"
            $process = & "$currentDir\Scripts\1_Set-Audit-Policy-Force.cmd"
            foreach ($line in $process)
            {
               $Body += $line + "`r`n"
            }
        }
        # Audit level 2
        2
        { 
            Write-Output "Config audit level 2"
            $process = & "$currentDir\Scripts\1_Set-Audit-Policy-Force.cmd"
            foreach ($line in $process)
            {
               $Body += $line + "`r`n"
            }
            $process = & "$currentDir\Scripts\2_Set-Audit-Policy-Recommend.cmd"
            foreach ($line in $process)
            {
               $Body += $line + "`r`n"
            }
        }
        # Audit level 3
        3
        {
            Write-Output "Config audit level 3"
            $process = & "$currentDir\Scripts\1_Set-Audit-Policy-Force.cmd"
            foreach ($line in $process)
            {
               $Body += $line + "`r`n"
            }
            $process = & "$currentDir\Scripts\2_Set-Audit-Policy-Recommend.cmd"
            foreach ($line in $process)
            {
               $Body += $line + "`r`n"
            }
            $process = & "$currentDir\Scripts\3_Set-Audit-Policy-Optional.cmd"
            foreach ($line in $process)
            {
               $Body += $line + "`r`n"
            }
        }
    }

    if ($data['Global']['sysmon_setting'] -eq "1")
    {
        Write-Output "Config sysmon"
        $process = & "$currentDir\Scripts\4_Set-Audit-Install-Sysmon.cmd"
        foreach ($line in $process)
        {
           $Body += $line + "`r`n"
        }
    }
    else 
    {
        Write-Output "Not config sysmon"
    }
    
    
    $DateStr = (Get-Date).ToString("yyyy_MM_dd_hh_mm")

    $outfileCsv = "$env:COMPUTERNAME" + "_" + "$DateStr.csv"
    $outfileLog = "$env:COMPUTERNAME" + "_" + "$DateStr.log"
    
    if (Test-Path $outfileLog) {
        Remove-Item $outfileLog
    }

    if (Test-Path $outfileCsv) {
        Remove-Item $outfileCsv
    }

    start-process "auditpol.exe" "/backup /file:$currentDir\$outfileCsv"

    Write-Output "Exported auditpol config to import to SecPol.msc: $outfileCsv"

    $Body | out-file -filepath "$currentDir\$outfileLog"

    Write-Output "Try to refresh Local Security Policy GUI..."
    start-process "gpupdate.exe" "/force"
    
    Write-Output "Completed! Check output in .log file"
}

catch {
    Write-Output "Error! Check config.ini file format and scripts inside .\Scripts folder"
    Write-Output $_
}