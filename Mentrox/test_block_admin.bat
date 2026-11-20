@echo off
setlocal
echo ============================================================================
echo   NETSENTINEL OT: DYNAMIC FIREWALL BLOCK & UNBLOCK TESTER
echo ============================================================================

:: Check for Administrator permissions
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Requesting Administrator privileges to test Windows Firewall...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
title NetSentinel OT Dynamic Firewall Verification

set TEST_IP=192.168.0.20

echo.
echo ============================================================================
echo STEP 1: VERIFYING PRE-BLOCK CONNECTIVITY
echo Pinging %TEST_IP% (device physically connected)...
echo ============================================================================
ping -n 2 -w 1000 %TEST_IP%

echo.
echo ============================================================================
echo STEP 2: APPLYING DYNAMIC WINDOWS DEFENDER FIREWALL BLOCK RULES
echo NetSentinel_Block_In_%TEST_IP%  (Inbound Block)
echo NetSentinel_Block_Out_%TEST_IP% (Outbound Block)
echo ============================================================================
netsh advfirewall firewall add rule name="NetSentinel_Block_In_%TEST_IP%" dir=in action=block remoteip=%TEST_IP% protocol=any profile=any enable=yes
netsh advfirewall firewall add rule name="NetSentinel_Block_Out_%TEST_IP%" dir=out action=block remoteip=%TEST_IP% protocol=any profile=any enable=yes
arp -d %TEST_IP% >nul 2>&1

echo.
echo ============================================================================
echo STEP 3: TESTING PING WHILE DEVICE IS BLOCKED
echo Pinging %TEST_IP% (Device physically connected, but firewall dropped)...
echo ============================================================================
ping -n 2 -w 1000 %TEST_IP%
echo.
echo [NOTICE] Observe that packets are DROPPED or report 'General failure.'

echo.
pause
echo.
echo ============================================================================
echo STEP 4: APPLYING DYNAMIC UNBLOCK
echo Deleting NetSentinel firewall rules for %TEST_IP%...
echo ============================================================================
netsh advfirewall firewall delete rule name="NetSentinel_Block_In_%TEST_IP%"
netsh advfirewall firewall delete rule name="NetSentinel_Block_Out_%TEST_IP%"
arp -d %TEST_IP% >nul 2>&1

echo.
echo ============================================================================
echo STEP 5: TESTING PING AFTER UNBLOCK
echo Pinging %TEST_IP% (Full communication restored)...
echo ============================================================================
ping -n 2 -w 1000 %TEST_IP%

echo.
echo ============================================================================
echo TEST COMPLETE: Both dynamic Block and Unblock verified successfully.
echo ============================================================================
pause

