# Stop a lab started in the background by killing whatever listens on the port.
#   powershell -ExecutionPolicy Bypass -File scripts\stop-lab.ps1 [-Port 8000]
param([int]$Port = 8000)

$conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    Stop-Process -Id $conn.OwningProcess -Force
    Write-Host "stopped lab (pid $($conn.OwningProcess)) on port $Port"
} else {
    Write-Host "nothing listening on port $Port"
}
