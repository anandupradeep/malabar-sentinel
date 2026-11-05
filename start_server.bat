@echo off
title SOC EDR Server
color 0A
echo +================================================+
echo ^|      SOC + EDR Platform - Server Launcher     ^|
echo +================================================+
echo.

cd /d "%~dp0server"

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install from https://python.org
    pause & exit /b 1
)

REM Install dependencies if needed
python -c "import fastapi" >nul 2>&1
if errorlevel 1 (
    echo Installing server dependencies...
    python -m pip install fastapi "uvicorn[standard]" pydantic python-multipart httpx cryptography python-dotenv aiosqlite
    echo.
)

REM NOTE: Port 8000 is reserved for Splunk on this system.
REM Malabar Sentinel uses port 9001 by default.
echo Checking if port 9001 is free...
netstat -ano | findstr ":9001 " | findstr "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo.
    echo WARNING: Port 9001 is in use.
    echo The server will automatically find the next free port.
    echo Or specify a port:  python main.py --port 9002
    echo.
)

echo Starting SOC Server on port 9001...
echo Press Ctrl+C to stop.
echo.
python main.py --port 9001 %*

pause
