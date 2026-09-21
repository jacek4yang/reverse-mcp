# #57 long-run soak harness.
# Usage:
#   powershell -File scripts\soak.ps1 -Hours 12          # release gate
#   powershell -File scripts\soak.ps1 -Hours 0.0167      # ~60s smoke
# Runs the bounded soak test binary in a loop until the wall-clock budget
# is consumed, then reports pass/fail. Monitors worker-process count so
# orphaned workers are detected. No sample is ever executed - mock workers
# only (real-IDA soak: add -RealIda with a licensed IDA and review output).
param(
    [double]$Hours = 12,
    [switch]$RealIda
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
# Orphan counting must only consider workers spawned from THIS repo's
# target tree: the user may run their own reverse-mcp instances (e.g. an
# MCP server from another location), and an unfiltered count both creates
# false failures and would force-kill the user's processes.
$soakTreePrefix = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path + "\target"
function Get-SoakTreeWorkerCount {
    @(Get-CimInstance Win32_Process -Filter "Name='reverse-mcp.exe'" |
        Where-Object { $_.ExecutablePath -like "$soakTreePrefix*" }).Count
}
function Stop-SoakTreeWorkers {
    Get-CimInstance Win32_Process -Filter "Name='reverse-mcp.exe'" |
        Where-Object { $_.ExecutablePath -like "$soakTreePrefix*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}
# Toolchain comes from PATH (never a machine-specific absolute path).
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "soak: cargo not found on PATH; install the Rust toolchain first"
}

$deadline = (Get-Date).AddHours($Hours)
$runs = 0
$failures = 0
$testArgs = @("test", "-p", "rmcp-broker", "--test", "soak", "--", "--ignored", "--test-threads=1", "--nocapture")
if (-not $RealIda) {
    # The bundled soak test uses mock workers by default; --ignored is only
    # for the real-IDA variant. Mock runs directly:
    $testArgs = @("test", "-p", "rmcp-broker", "--test", "soak", "--", "--test-threads=1", "--nocapture")
}

Write-Host "soak: running for $Hours hours (RealIda=$RealIda)"
while ((Get-Date) -lt $deadline) {
    $runs++
    Write-Host "--- soak iteration $runs at $(Get-Date -Format HH:mm:ss) ---"

    $workerBefore = Get-SoakTreeWorkerCount
    cargo @testArgs
    if ($LASTEXITCODE -ne 0) {
        $failures++
        Write-Host "SOAK FAILURE on iteration $runs"
        if ($failures -ge 3) { throw "soak: 3 failures; aborting" }
    }

    Start-Sleep -Seconds 5
    # Orphan check: each iteration's workers must be gone when the test ends.
    $workerAfter = Get-SoakTreeWorkerCount
    if ($workerAfter -gt 0) {
        Write-Host "WARNING: $workerAfter soak-tree reverse-mcp process(es) still alive after run"
        Stop-SoakTreeWorkers
        $failures++
    }
}

Write-Host ""
Write-Host "=== soak summary ==="
Write-Host "iterations: $runs"
Write-Host "failures:   $failures"
if ($failures -gt 0) { exit 1 }
Write-Host "SOAK PASS"
