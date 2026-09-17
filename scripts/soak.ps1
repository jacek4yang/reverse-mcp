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
$env:PATH = "D:\Applications\Scoop\persist\rustup-msvc\.cargo\bin;$env:SystemRoot\system32;$env:SystemRoot"

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

    $workerBefore = @(Get-Process reverse-mcp -ErrorAction SilentlyContinue).Count
    cargo @testArgs
    if ($LASTEXITCODE -ne 0) {
        $failures++
        Write-Host "SOAK FAILURE on iteration $runs"
        if ($failures -ge 3) { throw "soak: 3 failures; aborting" }
    }

    Start-Sleep -Seconds 5
    # Orphan check: each iteration's workers must be gone when the test ends.
    $workerAfter = @(Get-Process reverse-mcp -ErrorAction SilentlyContinue).Count
    if ($workerAfter -gt 0) {
        Write-Host "WARNING: $workerAfter reverse-mcp process(es) still alive after run"
        Get-Process reverse-mcp | Stop-Process -Force -ErrorAction SilentlyContinue
        $failures++
    }
}

Write-Host ""
Write-Host "=== soak summary ==="
Write-Host "iterations: $runs"
Write-Host "failures:   $failures"
if ($failures -gt 0) { exit 1 }
Write-Host "SOAK PASS"
