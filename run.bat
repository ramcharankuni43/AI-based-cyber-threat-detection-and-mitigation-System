@echo off
title AI Cyber Threat Mitigation System - SOC Dashboard
color 0b

echo ======================================================================
echo    AI-Based Network Intrusion Detection & Automated Mitigation System
echo               College Final-Year Project Presentation
echo ======================================================================
echo.

cd /d "%~dp0"

echo [1/3] Checking Python environment...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.10+ and re-run.
    pause
    exit /b 1
)

echo [2/3] Freeing port 8501 if previously in use...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :8501 ^| findstr LISTENING') do (
    taskkill /F /PID %%a >nul 2>&1
)

echo [3/3] Launching Streamlit SOC Dashboard...
echo URL: http://localhost:8501
echo.
echo Press Ctrl+C in this terminal window to stop the server anytime.
echo ======================================================================
echo.

python -m streamlit run app.py --server.port 8501 --server.headless false

pause
