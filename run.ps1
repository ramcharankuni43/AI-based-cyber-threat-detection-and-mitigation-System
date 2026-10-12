# AI-Based Network Intrusion Detection & Automated Mitigation System
# Native PowerShell 1-Click Launcher

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   AI-Based Network Intrusion Detection & Automated Mitigation System" -ForegroundColor White
Write-Host "              College Final-Year Project Presentation" -ForegroundColor Yellow
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$workDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $workDir

Write-Host "[1/3] Checking Python installation..." -ForegroundColor Gray
try {
    $pyVer = python --version 2>&1
    Write-Host "  Found: $pyVer" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python is not installed or not in PATH." -ForegroundColor Red
    pause
    exit 1
}

Write-Host "[2/3] Checking port 8501..." -ForegroundColor Gray
$portInUse = Get-NetTCPConnection -LocalPort 8501 -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "  Cleaning up existing process on port 8501..." -ForegroundColor Yellow
    $portInUse | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
}

Write-Host "[3/3] Starting SOC Dashboard on http://localhost:8501 ..." -ForegroundColor Green
Write-Host ""
Write-Host "Press Ctrl+C in this terminal window to stop." -ForegroundColor Gray
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

python -m streamlit run app.py --server.port 8501 --server.headless false
