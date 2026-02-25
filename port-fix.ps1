# PowerShell Script to Fix Port 5000 Issues
# Run this script when you get "Error: listen EADDRINUSE: address already in use :::5000"

Write-Host "=== Port 5000 Fix Tool ===" -ForegroundColor Cyan

# Function to find process using port 5000
function Find-PortProcess {
    Write-Host "`n1. Finding process using port 5000..." -ForegroundColor Yellow
    $connection = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue
    if ($connection) {
        $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
        if ($process) {
            Write-Host "   Found process:" -ForegroundColor Green
            Write-Host "   - Process Name: $($process.ProcessName)" -ForegroundColor White
            Write-Host "   - Process ID: $($process.Id)" -ForegroundColor White
            Write-Host "   - Started: $($process.StartTime)" -ForegroundColor White
            return $process
        }
    }
    Write-Host "   No process found using port 5000" -ForegroundColor Red
    return $null
}

# Function to kill process
function Kill-PortProcess {
    param($Process)
    Write-Host "`n2. Killing process $($Process.ProcessName) (PID: $($Process.Id))..." -ForegroundColor Yellow
    try {
        Stop-Process -Id $Process.Id -Force
        Write-Host "   Process killed successfully!" -ForegroundColor Green
        Start-Sleep -Seconds 2
        return $true
    } catch {
        Write-Host "   Failed to kill process: $_" -ForegroundColor Red
        return $false
    }
}

# Main execution
$process = Find-PortProcess
if ($process) {
    $response = Read-Host "`nDo you want to kill this process? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        if (Kill-PortProcess -Process $process) {
            Write-Host "`n✅ Port 5000 is now free!" -ForegroundColor Green
            Write-Host "You can now start your backend server with: npm start" -ForegroundColor Cyan
        }
    } else {
        Write-Host "`n⚠️  Process not killed. You can:" -ForegroundColor Yellow
        Write-Host "   1. Use a different port (see .env support in server.cjs)" -ForegroundColor White
        Write-Host "   2. Kill the process manually in Task Manager" -ForegroundColor White
    }
} else {
    Write-Host "`n✅ Port 5000 appears to be free already!" -ForegroundColor Green
}
