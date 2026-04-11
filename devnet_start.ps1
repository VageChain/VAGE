# VageChain DevNet Startup Script (Windows PowerShell)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectPath = Join-Path $scriptPath "vage"

Set-Location $projectPath

Write-Host ">>> Building VageChain L1 Node..." -ForegroundColor Cyan
cargo build --release

if (-not (Test-Path "target/release/vagechain.exe")) {
    Write-Host "[x] Node binary not found!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[V] Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "=== Starting VageChain DevNet Node ===" -ForegroundColor Cyan
Write-Host "   RPC endpoint: http://127.0.0.1:8080/rpc"
Write-Host "   Chain ID: vage_devnet_1"
Write-Host "   Config: configs/devnet.json"
Write-Host ""

& "target/release/vagechain.exe" --config "configs/devnet.json" --log-level info
