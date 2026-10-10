# PowerShell script to start the Local Laya AI Cyber Risk Backend Service
param (
    [int]$Port = 8000,
    [string]$HostName = "127.0.0.1"
)

$VenvPython = Join-Path $PSScriptRoot "..\.venv_laya\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Error "Virtual environment Python not found at $VenvPython. Run: py -3.13 -m venv .venv_laya && .\.venv_laya\Scripts\python.exe -m pip install -r backend\requirements.txt"
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Starting Local Laya AI Cyber Risk Quantification Service" -ForegroundColor Cyan
Write-Host "  Model: convaiinnovations/laya (ModernBERT-large)" -ForegroundColor Cyan
Write-Host "  Binding: http://$($HostName):$($Port)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Pre-flight check: see if port is already occupied
$ExistingConn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
if ($ExistingConn) {
    Write-Warning "Port $Port is already in use by process ID $($ExistingConn[0].OwningProcess)."
    Write-Warning "If a previous instance of the Laya service is running, stop it or pass a different port."
    exit 1
}

$BackendDir = $PSScriptRoot
& $VenvPython -m uvicorn backend.service:app --host $HostName --port $Port --reload --reload-dir $BackendDir

