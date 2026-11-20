@echo off
setlocal
echo ============================================================================
echo   NETSENTINEL OT: INDUSTRIAL NETWORK SECURITY MONITOR
echo   Starting with Windows Administrator Privileges...
echo ============================================================================

:: 1. Check if running with Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privilege is required for Windows Firewall packet blocking.
    echo [!] Elevating prompt to Administrator now...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: 2. Running elevated
cd /d "%~dp0"
title NetSentinel OT Industrial Security Monitor (ADMINISTRATOR)
cls
echo ============================================================================
echo   NETSENTINEL OT: INDUSTRIAL NETWORK MONITOR & FIREWALL BLOCKER
echo ============================================================================
echo [+] Elevated Token: HIGH INTEGRITY (Administrator Privileges Active)
echo [+] Windows Defender Firewall Control: FULL ACCESS (Inbound + Outbound)
echo [+] Dedicated Interface: Ethernet (Index 9)
echo [+] OT Network Subnet: 192.168.0.0/24
echo [+] Dynamic Block / Unblock: ACTIVE
echo.
echo Starting Web Dashboard and Continuous Monitor...
echo.
py app.py
pause

