@echo off
title Malabar Sentinel Agent
color 0A

REM ── Self-elevate to Administrator if not already ─────────────────────────────
net session >nul 2>&1
if %errorlevel% NEQ 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM ── We are now running as Administrator ──────────────────────────────────────
echo ============================================
echo   Malabar Sentinel Agent  [Administrator]
echo ============================================
echo.

cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install from https://python.org
    pause & exit /b 1
)

echo Checking agent dependencies...
python -c "import psutil, requests, PyQt5" >nul 2>&1
if errorlevel 1 (
    echo Installing agent dependencies...
    python -m pip install psutil requests watchdog PyQt5 websockets
    echo.
)

echo Starting Malabar Sentinel Agent...
echo The agent will auto-connect and start monitoring.
echo.
python agent\main.py %*

pause
