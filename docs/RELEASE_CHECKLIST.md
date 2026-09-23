# Windows x86_64 Release Checklist (issue #57)

Target: **Windows x86_64 + one IDA ABI per artifact — 9.2 production
supported; 9.4 available/unverified (build + ABI gates only until its
real-IDA suite passes on a licensed install).**

Release per backend: `pwsh scripts/release.ps1 -IdaVersion 9.2` (default,
v1.0-compatible name) or `-IdaVersion 9.4` (artifact name carries `-ida94`;
the script fails closed if the compiled ABI or registry verification state
does not match the request).
Everything else (Linux, macOS, other IDA versions) is architecture-supported
but *unverified* until #48 lands; do not claim support in release notes.

## 0. Provenance & safety (hard rules)
- [ ] No test, script or agent step in this release executes unknown or
      malicious binaries. Corpus samples are static byte inputs only
      (parsed by IDA/idalib; never launched, emulated, or installed).
- [ ] Corpus provenance recorded in `docs/CORPUS.md` (synthetic/inert or
      user-provided with hash + license note). No automatic downloads.

## 1. Automated gates (CI / any machine)
- [ ] `python -X utf8 scripts/check-encoding.py` — clean.
- [ ] `cargo fmt --all -- --check` — clean.
- [ ] `cargo clippy -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker
      -p rmcp-broker --all-targets -- -D warnings` — clean.
- [ ] `cargo test -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker
      -p rmcp-broker` — all green (includes docs anti-drift guards).
- [ ] `cargo run --release -p reverse-mcp -- bench` — `all_ok: true`.
- [ ] Soak smoke: `cargo test -p rmcp-broker --test soak` — pass.

## 2. Real-IDA acceptance (licensed IDA 9.2 machine)
- [ ] `$env:IDADIR = "<IDA 9.2 dir>"` set.
- [ ] `cargo test -p reverse-mcp --release --features idalib --test
      idalib_real -- --ignored --test-threads=1` — **all green**, including:
      - hostile-corpus ground truth (functions, recursion edge, fan-out,
        budget/resume, deob analysis-only, API-hash structured answer)
      - malformed/entropy inputs: no crash, no hang, broker healthy after
      - the full #8–#47 regression chain.
- [ ] Hostile-input triage: any worker crash / unbounded output / hang
      found here is fixed or explicitly bounded before proceeding.
- [ ] Large-function hierarchical gate (#72): `cargo test -p reverse-mcp
      --release --features idalib --test largefn_real -- --ignored
      --test-threads=1` — pass (giant fixture classifies + region evidence
      + isolation + drill-in + normal control + zero leak).
- [ ] WASM real-IDA gates (#71): `cargo test -p reverse-mcp --release
      --features idalib --test wasm_real -- --ignored --test-threads=1` —
      pass (br_if disassembly + full `ida_wasm` tool actions + malformed
      bounded failure).
- [ ] Tier-A logic acceptance (external MCP client path): `cargo test -p
      reverse-mcp --test logic_acceptance -- --ignored` — pass, zero
      unsupported confirmed claims.
- [ ] Tier-B malware acceptance: `cargo test -p reverse-mcp --test
      malware_acceptance` — pass.
- [ ] Corpus real (>=20 binaries end-to-end): `cargo test -p reverse-mcp
      --test corpus_real -- --ignored --test-threads=1` — pass.

## 3. Long-run reliability
- [ ] 60-second soak: `cargo test -p rmcp-broker --test soak` — pass.
- [ ] 12h soak: `powershell -File scripts\soak.ps1 -Hours 12` — pass.
      No unbounded memory/handle growth, no orphan reverse-mcp processes,
      no deadlock, no persistent temp-file leak (script warns on orphans).
- [ ] 24h soak (v1.0 target): same command, `-Hours 24` — pass.

## 4. Artifact
- [ ] `pwsh scripts/check-distribution.ps1` — no proprietary IDA material
      tracked in Git (extension/name/license-marker scan).
- [ ] `powershell -File scripts\release.ps1` — runs gates 1 + 4–8 and
      produces:
      - `target/release/reverse-mcp-v1.0.0-windows-x86_64.zip`
        (exe + minimal docs only; forbidden-pattern guard rejects IDA
        proprietary files, keys, corpora, or any second binary)
      - `target/release/reverse-mcp-v1.0.0-windows-x86_64.zip.sha256`
- [ ] The release build is the idalib-ENABLED artifact:
      `cargo build --release -p reverse-mcp --features idalib` (the script
      refuses to package a mock-only artifact via
      `reverse-mcp worker --probe-backend idalib`).
- [ ] Record the hash + build command (`cargo build --release -p
      reverse-mcp --features idalib`, toolchain pinned by
      `rust-toolchain.toml`) in the release notes; the build is
      reproducible from the tag.
- [ ] Smoke the artifact from a clean extraction directory:
      verify SHA-256, `reverse-mcp version`, `reverse-mcp doctor`,
      `reverse-mcp ida list`, start a stdio MCP session, open a real
      database through the public MCP surface (open/info/functions/
      decompile/close), confirm clean shutdown with no orphan workers.
- [ ] `LICENSE` ships in the package (MIT, `Cargo.toml`
      `workspace.package.license`).

## 5. Documentation claims (exact wording)
- [ ] README support line: "Windows x86_64 + IDA Pro 9.2: production
      supported and real-IDA tested." Nothing stronger.
- [ ] LIMITATIONS platform section matches this claim.
- [ ] Known unverified items listed (Linux/macOS, other IDA versions,
      packed-sample coverage limits).
