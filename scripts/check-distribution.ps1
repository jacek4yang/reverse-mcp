# check-distribution.ps1 — fail the build if any tracked file looks like proprietary IDA material.
$ErrorActionPreference = 'Stop'

$tracked = git ls-files
if ($LASTEXITCODE -ne 0) { Write-Error "git ls-files failed" }

$badExtensions = @('.7z', '.i64', '.idb', '.hexlic')
$badNames = @('ida.dll', 'ida32.dll', 'idalib.dll', 'idalib32.dll', 'idacli.exe', 'ida.exe', 'idat.exe', 'idapyswitch.exe')
$licensePatterns = @('idapro.hexlic')
# Note: "Hex-Rays" as a plain string appears in legitimate docs (MIT SDK references),
# so the license-marker scan only checks for the license filename itself.
$binaryExtensions = @('.dll', '.exe', '.lib', '.so', '.dylib')

$violations = @()
# License-marker scan: check for the IDA license filename inside tracked text files.
# Skip this script itself (it must contain the marker strings to do its job).
$scanTargets = $tracked | Where-Object { $_ -ne 'scripts/check-distribution.ps1' }
foreach ($f in $scanTargets) {
    $ext = [IO.Path]::GetExtension($f).ToLowerInvariant()
    if ($badExtensions -contains $ext) {
        $violations += "extension: $f"
        continue
    }
    $name = [IO.Path]::GetFileName($f).ToLowerInvariant()
    if ($badNames -contains $name) {
        $violations += "binary name: $f"
        continue
    }
    # License markers inside text files (skip anything already flagged by size/extension heuristics)
    $item = Get-Item -LiteralPath $f -ErrorAction SilentlyContinue
    if ($null -ne $item -and $item.Length -lt 1MB -and $ext -notin $binaryExtensions) {
        try {
            $content = Get-Content -LiteralPath $f -Raw -ErrorAction Stop
            foreach ($p in $licensePatterns) {
                if ($content -match [regex]::Escape($p)) {
                    $violations += "license marker '$p': $f"
                    break
                }
            }
        } catch { }
    }
}

if ($violations.Count -gt 0) {
    Write-Host "DISTRIBUTION VIOLATIONS FOUND:" -ForegroundColor Red
    $violations | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

Write-Host "distribution check: OK ($($tracked.Count) tracked files scanned)"
exit 0
