@echo off

Echo "Begin Set-Audit-Install-Sysmon"

set DEFAULT_VERSION=Sysmon_for_windows_6.3
:: check windows version
for /f "tokens=4-5 delims=. " %%i in ('ver.exe') do set WINDOZE_VERSION=%%i.%%j

set WINDOZE_VERSION_NAME=Win81_and_above

if "%WINDOZE_VERSION%:~0,1" == "4" (
    set WINDOZE_VERSION_NAME=Unsupported
    GOTO :SET_SYSMON_VERION
)
if "%WINDOZE_VERSION%:~0,1" == "5" ( 
    set WINDOZE_VERSION_NAME=Unsupported
    GOTO :SET_SYSMON_VERION
)
if "%WINDOZE_VERSION%" == "6.0" (
    set WINDOZE_VERSION_NAME=Vista_and_2k8
    GOTO :SET_SYSMON_VERION
)
if "%WINDOZE_VERSION%" == "6.1"  (
    set WINDOZE_VERSION_NAME=Windows_7_2k8_r2
    GOTO :SET_SYSMON_VERION
)
if "%WINDOZE_VERSION%" == "6.2" (
    set WINDOZE_VERSION_NAME=Windows_8_2012
    GOTO :SET_SYSMON_VERION
)

:SET_SYSMON_VERION
echo "Begin install sysmon for %WINDOZE_VERSION_NAME%"
GOTO :CASE_%WINDOZE_VERSION_NAME%
IF ERRORLEVEL 1 GOTO :CASE_Unsupported 

:: sysmon 8.04
:CASE_Vista_and_2k8
SET SYSMON_VER=Sysmon_for_windows_6.0 
GOTO :CHECK_SYSMON
:: sysmon 8.04
:CASE_Windows_7_2k8_r2
SET SYSMON_VER=Sysmon_for_windows_6.0
:: sysmon 10.4
GOTO :CHECK_SYSMON
:CASE_Windows_8_2012
SET SYSMON_VER=Sysmon_for_windows_6.2
GOTO :CHECK_SYSMON
:: sysmon 11+
:CASE_Win81_and_above
SET SYSMON_VER=Sysmon_for_windows_6.3
GOTO :CHECK_SYSMON
:CASE_Unsupported
GOTO :NOT_INSTALL


:CHECK_SYSMON

:: Check if sysmon executable/config exist, otherwise using DEFAULT_VERSION executable name
IF NOT EXIST "%~dp0Sysmon\%SYSMON_VER%.exe" (
    set SYSMON_VER=DEFAULT_VERSION
    IF NOT EXIST "%~dp0Sysmon\%SYSMON_VER%.exe" (
        Echo "Sysmon executable/config not found"
        goto NOT_INSTALL
    )
) 


:: Check if sysmon installed
SC.exe QUERY "Sysmon" > nul
IF ERRORLEVEL 1060 GOTO :INSTALL_SYSMON
GOTO :UPDATE_CONFIG

:: Config command to install sysmon
:INSTALL_SYSMON
echo "Install sysmon"
echo F | xcopy /S /F /Y /Q /C "%~dp0Sysmon\%SYSMON_VER%.exe" "%windir%\Temp\Sysmon.exe" 
"%windir%\Temp\Sysmon.exe" -accepteula -i "%~dp0Sysmon\%SYSMON_VER%.xml" 2>&1
goto :END

:: Config command to update sysmon config 
:UPDATE_CONFIG
echo "Update sysmon config"
echo F | xcopy /S /F /Y /Q /C "%~dp0Sysmon\%SYSMON_VER%.exe" "%windir%\Temp\Sysmon.exe"
"%windir%\Temp\Sysmon.exe" -c "%~dp0Sysmon\%SYSMON_VER%.xml" 2>&1

:END
:: Increase Sysmon logsize 5GB
echo "Increase Sysmon logsize"
wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ms:1073741824

Echo "Set-Audit-Install-Sysmon Done"
::set /p DUMMY=Hit ENTER to continue...
GOTO :EOF

:NOT_INSTALL
Echo "Set-Audit-Install-Sysmon Unable to install/config sysmon"
