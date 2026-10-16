@echo off
title CyberPulse - Network Packet & Error Detection Sentinel
cd /d "%~dp0"

echo ================================================================
echo   CYBERPULSE // Network Error Detection & Packet Sentinel
echo ================================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [!] Virtual environment not found. Creating .venv...
    python -m venv .venv
    echo [*] Installing dependencies from requirements.txt...
    .\.venv\Scripts\pip install -r requirements.txt
)

echo [*] Starting CyberPulse Server on http://127.0.0.1:5000 ...
echo [*] Open your web browser at http://127.0.0.1:5000
echo [*] Press Ctrl+C in this console to terminate.
echo.

.\.venv\Scripts\python.exe app.py
pause
