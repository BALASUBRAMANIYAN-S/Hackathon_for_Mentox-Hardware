# NetSentinel OT Admin PowerShell Launcher
# Ensures the application runs with Administrator privileges for Windows Firewall control

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] NetSentinel requires Administrator privileges for Windows Firewall control." -ForegroundColor Yellow
    Write-Host "[!] Requesting Administrator elevation..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

Set-Location -Path $PSScriptRoot
$host.UI.RawUI.WindowTitle = "NetSentinel OT (ADMINISTRATOR)"

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "   NETSENTINEL OT: INDUSTRIAL NETWORK MONITOR (ADMINISTRATOR)" -ForegroundColor Green
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "[+] Administrator Privileges: ACTIVE" -ForegroundColor Green
Write-Host "[+] Windows Firewall Dynamic IP Blocking: READY" -ForegroundColor Green
Write-Host "[+] Launching py app.py on http://localhost:5000 ..." -ForegroundColor Cyan
Write-Host ""

py app.py

