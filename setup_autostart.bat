@echo off
title Malabar Sentinel — Auto-Start Setup
color 0A

REM ── Self-elevate if not already Administrator ─────────────────────────────
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo +=====================================================+
echo ^|   Malabar Sentinel — Auto-Start Setup             ^|
echo ^|   Uses XML Task Scheduler (handles spaces in path)^|
echo +=====================================================+
echo.

cd /d "%~dp0"

REM Find python / pythonw
set PYTHONW=
for /f "delims=" %%i in ('where pythonw 2^>nul') do (
    if not defined PYTHONW set PYTHONW=%%i
)
if not defined PYTHONW (
    for /f "delims=" %%i in ('where python 2^>nul') do (
        if not defined PYTHONW set PYTHONW=%%i
    )
)
if not defined PYTHONW (
    echo ERROR: Python not found. Install Python and re-run this script.
    pause & exit /b 1
)

set AGENT_SCRIPT=%~dp0agent\main.py
set WORKDIR=%~dp0
REM Remove trailing backslash from WORKDIR
if "%WORKDIR:~-1%"=="\" set WORKDIR=%WORKDIR:~0,-1%
set TASK_NAME=MalabarSentinelAgent

echo Python  : %PYTHONW%
echo Script  : %AGENT_SCRIPT%
echo Workdir : %WORKDIR%
echo.

echo Choose an option:
echo.
echo   [1] Register auto-start task
echo   [2] Remove auto-start task
echo   [3] Check task status
echo   [4] Run task now (test)
echo   [5] Exit
echo.
set /p CHOICE=Enter choice (1-5): 

if "%CHOICE%"=="1" goto :register
if "%CHOICE%"=="2" goto :remove
if "%CHOICE%"=="3" goto :check
if "%CHOICE%"=="4" goto :runnow
if "%CHOICE%"=="5" exit /b 0
echo Invalid choice. & pause & exit /b 1

:register
echo.
echo Creating startup task via XML (avoids path quoting issues)...
echo.

REM Write the task XML to a temp file
REM Using XML-based registration is the ONLY reliable way when Python path has spaces
set XMLFILE=%TEMP%\malabar_task.xml

REM Create XML using PowerShell (handles Unicode and special chars correctly)
powershell -NoProfile -NonInteractive -Command "$xml = @\"""<?xml version='1.0' encoding='UTF-16'?>
<Task version='1.4' xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>
  <RegistrationInfo>
    <Description>Malabar Sentinel EDR Agent auto-start</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id='Author'>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context='Author'>
    <Exec>
      <Command>$env:PYTHONW_PATH</Command>
      <Arguments>\"$env:AGENT_SCRIPT_PATH\"</Arguments>
      <WorkingDirectory>$env:WORKDIR_PATH</WorkingDirectory>
    </Exec>
  </Actions>
</Task>\"""; $env:PYTHONW_PATH='%PYTHONW%'; $env:AGENT_SCRIPT_PATH='%AGENT_SCRIPT%'; $env:WORKDIR_PATH='%WORKDIR%'; $xml = $xml -replace '\$env:PYTHONW_PATH',$env:PYTHONW_PATH -replace '\$env:AGENT_SCRIPT_PATH',$env:AGENT_SCRIPT_PATH -replace '\$env:WORKDIR_PATH',$env:WORKDIR_PATH; [System.IO.File]::WriteAllText('%XMLFILE%', $xml, [System.Text.Encoding]::Unicode)"

REM Delete existing task
schtasks /Delete /TN "%TASK_NAME%" /F >nul 2>&1

REM Create from XML
schtasks /Create /TN "%TASK_NAME%" /XML "%XMLFILE%" /F

if %errorlevel% EQU 0 (
    echo.
    echo ✓ SUCCESS — Startup task registered!
    echo.
    echo   Task name  : %TASK_NAME%
    echo   Trigger    : At every Windows logon ^(30s delay^)
    echo   Privilege  : Highest ^(Administrator, no UAC^)
    echo   Command    : %PYTHONW%
    echo   Script     : %AGENT_SCRIPT%
    echo.
    echo The agent will auto-start and auto-connect on next login.
    echo Auto-retry connects up to 10 times if server is not ready yet.
) else (
    echo.
    echo ✗ FAILED to create task.
    echo   Ensure you are running this script as Administrator.
)

if exist "%XMLFILE%" del /f "%XMLFILE%"
echo.
pause
exit /b 0

:remove
echo.
schtasks /Delete /TN "%TASK_NAME%" /F
if %errorlevel% EQU 0 (
    echo ✓ Startup task removed.
) else (
    echo Task not found or already removed.
)
echo.
pause
exit /b 0

:check
echo.
schtasks /Query /TN "%TASK_NAME%" /FO LIST 2>nul
if %errorlevel% EQU 0 (
    echo.
    echo ✓ Task IS registered. Agent will auto-start at next logon.
) else (
    echo ✗ Task NOT registered. Run option 1 to register.
)
echo.
pause
exit /b 0

:runnow
echo.
echo Running task now as a test...
schtasks /Run /TN "%TASK_NAME%"
if %errorlevel% EQU 0 (
    echo ✓ Task started. The agent window should appear in a few seconds.
) else (
    echo ✗ Could not run — register it first with option 1.
)
echo.
pause
exit /b 0
