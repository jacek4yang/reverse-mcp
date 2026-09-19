# reverse-mcp v1.0.0 production release build (Windows x86_64 + IDA 9.2).
#
# Builds the idalib-enabled artifact (NOT mock-only), runs every automated
# gate, packages the distributable ZIP + SHA-256, and fails closed if the
# artifact is not idalib-enabled.
#
# Usage (from a clean Windows x86_64 checkout):
#   powershell -File scripts\release.ps1 [-SkipGates]
#
# Toolchain comes from rust-toolchain.toml via rustup; cargo/python/git are
# resolved from PATH (documented prerequisites), never from machine-specific
# absolute paths.

param(
    [switch]$SkipGates
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

# --- tool resolution from PATH (no machine-specific paths) ---
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $cargo) { throw "cargo not found on PATH (see rust-toolchain.toml / rustup docs)" }
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { throw "python not found on PATH" }
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) { throw "git not found on PATH" }
Write-Host "tools: cargo=$($cargo.Source)"
Write-Host "       python=$($python.Source)"
Write-Host "       git=$($git.Source)"

if (-not $SkipGates) {
    Write-Host "=== 1. encoding guard ==="
    python -X utf8 scripts/check-encoding.py
    if ($LASTEXITCODE -ne 0) { throw "encoding guard failed" }

    Write-Host "=== 2. fmt ==="
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw "fmt failed" }

    Write-Host "=== 3. clippy (deny warnings) ==="
    cargo clippy -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker -p rmcp-broker -p rmcp-wasm --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "clippy failed" }

    Write-Host "=== 4. mock tests ==="
    cargo test -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker -p rmcp-broker -p rmcp-wasm
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }

    Write-Host "=== 5. mock bench gate ==="
    cargo run --release -p reverse-mcp -- bench
    if ($LASTEXITCODE -ne 0) { throw "bench gate failed" }
}
else {
    Write-Host "gates skipped (-SkipGates); run them separately before tagging"
}

Write-Host "=== 6. release build (idalib ENABLED) ==="
cargo build --release -p reverse-mcp --features idalib
if ($LASTEXITCODE -ne 0) { throw "release build failed" }

$exe = "target\release\reverse-mcp.exe"
if (-not (Test-Path $exe)) { throw "release binary missing" }

# Fail closed if the artifact somehow lacks the real backend.
Write-Host "=== 7. verify idalib backend is in the artifact ==="
& $exe doctor | Out-Host
if ($LASTEXITCODE -ne 0) { throw "doctor failed on the release binary" }
# The binary links the IDA runtime (delay-loaded): check the import is
# present via the size/pdb heuristic is unreliable, so verify by capability:
# worker probe must accept the idalib feature probe (exits 0 with a real
# backend requested). This is the same probe the broker uses.
$probe = & $exe worker --probe-backend idalib 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "artifact does not ship the idalib backend (probe failed: $probe) - refusing to package a mock-only artifact"
}
Write-Host "idalib backend probe: OK"

Write-Host "=== 8. package ZIP + SHA-256 ==="
$version = "1.0.0"
$zipName = "reverse-mcp-v$version-windows-x86_64.zip"
$stage = "target\release\pkg\reverse-mcp-v$version-windows-x86_64"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

# Only redistributable project material: the exe + minimal docs.
Copy-Item $exe "$stage\reverse-mcp.exe"
Copy-Item "README.md" $stage -ErrorAction SilentlyContinue
Copy-Item "LICENSE" $stage -ErrorAction SilentlyContinue
Copy-Item "docs\RELEASE_CHECKLIST.md" $stage -ErrorAction SilentlyContinue
Copy-Item "docs\LIMITATIONS.md" $stage -ErrorAction SilentlyContinue

# Guard: never bundle proprietary IDA material or malware corpus bytes.
$forbidden = @("*.dll", "*.i64", "*.idb", "*.hexlic", "*.key", "*.bin", "*.exe.bak")
foreach ($pat in $forbidden) {
    $hit = Get-ChildItem $stage -Filter $pat -Recurse -ErrorAction SilentlyContinue
    if ($hit) { throw "forbidden file pattern '$pat' in package: $($hit.Name)" }
}
# The staged exe must be the only exe.
$exes = Get-ChildItem $stage -Filter "*.exe"
if ($exes.Count -ne 1) { throw "expected exactly one exe in package, found $($exes.Count)" }

Compress-Archive -Path "$stage\*" -DestinationPath "target\release\$zipName" -Force
$zip = "target\release\$zipName"
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash
"$zipHash  $zipName" | Out-File "$zip.sha256" -Encoding ascii

Write-Host "=== 9. smoke: version on the staged artifact ==="
& "$stage\reverse-mcp.exe" version
if ($LASTEXITCODE -ne 0) { throw "version failed" }

Write-Host ""
Write-Host "=== release artifact ready ==="
Write-Host "zip:    $zip"
Write-Host "sha256: $zipHash  (written to $zip.sha256)"
Write-Host ""
Write-Host "Local release gates REMAINING (require a licensed IDA 9.2 install + long-run budget):"
Write-Host "  1. real-IDA gated suite:"
Write-Host "     `$env:IDADIR='<ida>'; cargo test -p reverse-mcp --release --features idalib --test idalib_real -- --ignored --test-threads=1"
Write-Host "  2. real-IDA bench:"
Write-Host "     cargo run --release -p reverse-mcp --features idalib -- bench --real-ida"
Write-Host "  3. large-function hierarchical gate (#72):"
Write-Host "     cargo test -p reverse-mcp --release --features idalib --test largefn_real -- --ignored --test-threads=1"
Write-Host "  4. WASM real-IDA gates (#71):"
Write-Host "     cargo test -p reverse-mcp --release --features idalib --test wasm_real -- --ignored --test-threads=1"
Write-Host "  5. Tier-A + Tier-B acceptance suites (docs/logic_acceptance, docs/malware_acceptance)"
Write-Host "  6. soak gates: 60s bundled; 12h/24h via scripts\soak.ps1 (see docs\RELEASE_CHECKLIST.md)"
