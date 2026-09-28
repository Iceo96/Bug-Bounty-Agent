# Start the local vulnerable lab (loopback only). Press Ctrl+C to stop.
#   powershell -ExecutionPolicy Bypass -File scripts\start-lab.ps1 [-Port 8000]
param([int]$Port = 8000)

$py = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Error "venv not found. Run: python -m venv .venv ; .venv\Scripts\pip install -e `".[dev]`""
    exit 1
}
& $py -m bbagent_lab.server --host 127.0.0.1 --port $Port
