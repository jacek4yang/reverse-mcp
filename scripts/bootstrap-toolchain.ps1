# bootstrap-toolchain.ps1 — provision the pinned native build tools.
#
# Wraps `dotslash toolchain/dotslash/<tool>` for every pinfile in
# toolchain/dotslash/ and verifies each tool answers `--version`.
#
# Usage:
#   pwsh scripts/bootstrap-toolchain.ps1          # provision + verify
#   pwsh scripts/bootstrap-toolchain.ps1 -Verify  # verify only (no download)

param(
    [switch]$Verify
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$pinDir = Join-Path $repoRoot "toolchain/dotslash"

function Invoke-Dotslash {
    param([string]$Pin, [string[]]$Args)
    $cmd = Get-Command dotslash -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        throw "dotslash is not installed. See https://dotslash-cli.com/docs/installation"
    }
    $full = @($Pin) + $Args
    & $cmd.Source @full
    if ($LASTEXITCODE -ne 0) {
        throw "dotslash $Pin $($Args -join ' ') failed (exit $LASTEXITCODE)"
    }
}

$tools = @(
    @{ Pin = "ninja"; VersionArgs = @("--version") },
    @{ Pin = "zig";   VersionArgs = @("version") }
)

foreach ($t in $tools) {
    $pin = Join-Path $pinDir $t.Pin
    if (-not (Test-Path $pin)) { throw "missing pinfile: $pin" }
    if (-not $Verify) {
        Write-Host "provisioning $t.Pin ..."
        Invoke-Dotslash -Pin $pin -Args $t.VersionArgs | Write-Host
    } else {
        Write-Host "verifying $t.Pin ..."
        Invoke-Dotslash -Pin $pin -Args $t.VersionArgs | Write-Host
    }
}

Write-Host "toolchain bootstrap: OK"
exit 0
