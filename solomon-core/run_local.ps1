# run_local.ps1
# Solomon Local Enterprise Orchestrator
# Replicates the complete ZK/PQ container topology locally on Windows without Docker,
# bypassing all IDE/rust-analyzer file-locking conflicts via isolated compilation paths.

$ErrorActionPreference = "Continue"

Write-Host "[Solomon Orchestrator] Initializing Local Enterprise Topology..." -ForegroundColor Cyan

# 1. Clean up any existing stale processes from previous runs
Write-Host "[Teardown] Cleaning up any legacy background processes..." -ForegroundColor Gray
Stop-Process -Name "solomon-control-plane" -ErrorAction SilentlyContinue
Stop-Process -Name "ml-dsa-65" -ErrorAction SilentlyContinue

# 2. Boot the Brain: Solomon Cloud Control Plane (Port 9000)
Write-Host "[1/3] Booting Solomon Cloud Control Plane (Port 9000)..." -ForegroundColor Yellow
$ControlPlane = Start-Process -FilePath "cargo" `
    -ArgumentList "run", "--release", "--target-dir", "C:\Users\usman\AppData\Local\Temp\solomon_control_plane_target" `
    -WorkingDirectory "e:\project solomon\control_plane" `
    -PassThru -NoNewWindow

# 3. Boot the Core: Mock Banking Backend (Port 8081)
Write-Host "[2/3] Booting Mock Banking Backend (Port 8081)..." -ForegroundColor Yellow
$BankingBackend = Start-Process -FilePath "python" `
    -ArgumentList "mock_banking_backend.py" `
    -WorkingDirectory "e:\project solomon" `
    -PassThru -NoNewWindow

# 4. Boot the Shield: Solomon Post-Quantum Proxy (Port 8080)
Write-Host "[3/3] Booting Solomon Post-Quantum Proxy (Port 8080)..." -ForegroundColor Yellow
$Proxy = Start-Process -FilePath "cargo" `
    -ArgumentList "run", "--release", "--features", "proxy", "--target-dir", "C:\Users\usman\AppData\Local\Temp\solomon_target" `
    -WorkingDirectory "e:\project solomon" `
    -PassThru -NoNewWindow

# 5. Let the services spin up and establish handshakes
Write-Host "[Scheduler] Waiting 10 seconds for services to compile, initialize, and complete heartbeats..." -ForegroundColor Gray
Start-Sleep -Seconds 10

# 6. Execute the End-to-End simulation client
Write-Host ""
Write-Host "[Simulation] Triggering E2E Transaction Test Payload..." -ForegroundColor Cyan
python test_e2e.py

# 7. Keypress trigger for graceful teardown
Write-Host ""
Write-Host "[Status] Execution sequence completed. Press any key to stop all background services..." -ForegroundColor Green
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# 8. Teardown
Write-Host ""
Write-Host "[Teardown] Terminating all background processes..." -ForegroundColor Red
try {
    $ControlPlane | Stop-Process -Force -ErrorAction SilentlyContinue
    $BankingBackend | Stop-Process -Force -ErrorAction SilentlyContinue
    $Proxy | Stop-Process -Force -ErrorAction SilentlyContinue
} catch {}

Write-Host "[Teardown] Cleanup complete. Workspace released." -ForegroundColor Green
