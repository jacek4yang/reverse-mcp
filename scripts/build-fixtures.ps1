# build-fixtures.ps1 - rebuild the real-IDA test fixtures with EMBEDDED
# symbols (/Z7) so function-name assertions in tests/*_real.rs work on any
# machine.
#
# Why: the committed fixture .exe files reference their .pdb files by the
# ORIGINAL build machine's absolute path (e.g. D:\Workspace\reverse-mcp\...),
# and .pdb files are gitignored. On any other checkout IDA therefore finds
# no symbols and name-dependent assertions fail - on 9.2 and 9.4 alike.
# Rebuilding with /Z7 embeds the CodeView records in the .exe itself.
#
# Requires: MSVC cl.exe on PATH (run from a VS x64 Native Tools prompt) and
# the fixture sources from tests/fixtures/*.c|cpp (committed).
#
# Usage (from the repo root):
#   powershell -File scripts\build-fixtures.ps1
#
# After rebuilding, delete stale analysis caches before re-running the
# gated suites (IDA reuses an existing .i64 next to the temp copy):
#   Remove-Item $env:TEMP\reverse-mcp-it-* -ErrorAction SilentlyContinue

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot "..\tests\fixtures")

function Build($src, $out, $flags) {
    Write-Host "building $out ..."
    & cl /nologo $flags $src "/Fe:$out"
    if ($LASTEXITCODE -ne 0) { throw "cl failed for $src" }
}

# simple.exe: helper/dispatch must stay outline-able -> /Ob0 keeps the
# call from main so xref assertions see it.
Build simple.c simple.exe '/O2','/Ob0','/MD','/Z7'

# deep/types: straightforward optimized dynamic-CRT builds with symbols.
Build deep.c deep.exe '/O2','/MD','/Z7'
Build types.cpp types.exe '/O2','/MD','/Z7','/EHsc'

# obfuscated: junk-pattern shapes are tuned against a /Od /MT build.
Build obfuscated.c obfuscated.exe '/Od','/MT','/Z7'

# hostile corpus: wide_hub must keep its direct-call fanout -> /Ob0.
Build corpus_hostile.c corpus_hostile.exe '/O2','/Ob0','/MT','/Z7'

# signature pair: v1 with symbols; v1b = identical build stripped of debug
# records (stripped-rebuild pairing path). llvm-objcopy required on PATH.
Build crypto.c sig_v1.exe '/O2','/Ob0','/MT','/Z7'
Build crypto.c sig_v1tmp.exe '/O2','/Ob0','/MT','/Z7'
& llvm-objcopy --strip-debug sig_v1tmp.exe sig_v1b.exe
if ($LASTEXITCODE -ne 0) { throw "llvm-objcopy failed (install LLVM or adapt)" }
Remove-Item sig_v1tmp.exe -ErrorAction SilentlyContinue

# giant function fixture (#72): the committed DLL's cmp-chain shape makes
# IDA 9.4's auto-analysis never terminate (idat -B reproduces: stuck at
# "Waiting for the end of the auto analysis"). Rebuilt with clang at -O0
# + -fno-jump-tables the same 3000-case dispatcher compiles to one ~231KB
# function at 0x180001000 (the address tests/largefn_real.rs pins) and 9.4
# analyzes it in seconds. Requires clang.exe on PATH (LLVM; run inside a
# VS x64 Native Tools prompt for the MSVC CRT link).
Set-Location (Join-Path $PSScriptRoot "..	estsixtures\largefn")
& clang -shared -O0 -fno-jump-tables giant_switch_3000.c -o giant_switch_3000.dll
if ($LASTEXITCODE -ne 0) { throw "clang failed for giant_switch_3000.c" }

Remove-Item *.obj -ErrorAction SilentlyContinue
Write-Host "fixtures rebuilt with embedded /Z7 symbols"
