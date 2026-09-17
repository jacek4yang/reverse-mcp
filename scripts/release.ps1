# #57 Windows x86_64 release build + checksum (reproducible).
# Usage:  powershell -File scripts\release.ps1 [-IdaDir <path>]
# Produces target\release\reverse-mcp.exe + reverse-mcp.exe.sha256 and
# verifies: encoding guard, fmt, clippy -D warnings, mock test suite, bench.
param(
    [string]$IdaDir = $env:IDADIR
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$env:PATH = "D:\Applications\Scoop\persist\rustup-msvc\.cargo\bin;$env:SystemRoot\system32;$env:SystemRoot"
if (-not $env:PATH.Contains("cargo")) {
    # Portable rustup location fallback
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) { throw "cargo not on PATH" }
}

Write-Host "=== 1. encoding guard ==="
python -X utf8 scripts/check-encoding.py
if ($LASTEXITCODE -ne 0) { throw "encoding guard failed" }

Write-Host "=== 2. fmt ==="
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { throw "fmt failed" }

Write-Host "=== 3. clippy (deny warnings) ==="
cargo clippy -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker -p rmcp-broker --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { throw "clippy failed" }

Write-Host "=== 4. mock tests ==="
cargo test -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker -p rmcp-broker
if ($LASTEXITCODE -ne 0) { throw "tests failed" }

Write-Host "=== 5. mock bench gate ==="
cargo run --release -p reverse-mcp -- bench
if ($LASTEXITCODE -ne 0) { throw "bench gate failed" }

Write-Host "=== 6. release build ==="
cargo build --release -p reverse-mcp
if ($LASTEXITCODE -ne 0) { throw "release build failed" }

$exe = "target\release\reverse-mcp.exe"
if (-not (Test-Path $exe)) { throw "release binary missing" }

Write-Host "=== 7. checksum ==="
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash
"$hash  reverse-mcp.exe" | Out-File "$exe.sha256" -Encoding ascii
Write-Host "SHA256: $hash"

Write-Host "=== 8. smoke: version + doctor surface ==="
& $exe version
if ($LASTEXITCODE -ne 0) { throw "version failed" }

Write-Host ""
Write-Host "=== release artifact ready ==="
Write-Host "binary:  $exe"
Write-Host "sha256:  $hash  (written to $exe.sha256)"
Write-Host ""
Write-Host "Local release gates REMAINING (require a licensed IDA 9.2 install):"
Write-Host "  1. real-IDA gated suite:"
Write-Host "     `$env:IDADIR='<ida>'; cargo test -p reverse-mcp --release --features idalib --test idalib_real -- --ignored --test-threads=1"
Write-Host "  2. soak gate (60s bundled, 12h/24h via scripts\soak.ps1):"
Write-Host "     cargo test -p rmcp-broker --test soak"
Write-Host "See docs/RELEASE_CHECKLIST.md for the full sign-off list."
