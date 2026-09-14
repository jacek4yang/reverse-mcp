# reverse-mcp v0.1.0 — Implementation Plan

## Goal

Deliver `jacek4yang/reverse-mcp` v0.1.0: a Rust MCP server giving AI agents headless,
programmatic control over IDA Pro 9.2 — one `reverse-mcp.exe`, broker + self-spawned
workers, stdio + Streamable HTTP, ~15 agent-native tools, token-efficient output.

## Position on local IDA material

- The local `D:\Applications\IDA_Professional` install
- All compilation targets the **official MIT-licensed `HexRaysSA/ida-sdk`** repo
  (tag `v9.2.0-sdk.1`). Nothing proprietary is uploaded; no SDK upload is needed.
- Runtime integration tests require a legitimately licensed IDA 9.2 install. They are
  implemented, gated behind `REVERSE_MCP_IDA_INTEGRATION=1`, and reported truthfully.
- `9.2.Pro.7z` is deleted (it holds installers only; SDK is public).
- `GROK_TASK.md` is git-ignored, never committed.

## Research conclusions (verified)

- `idalib` crate `0.7.2+9.2.250908` is the pinned binding for IDA 9.2 (newer versions
  target 9.3/9.4). `idalib-build` provides `configure_idasdk_linkage()` which links
  SDK stub libs — this is exactly what enables **cloud/CI builds without IDA installed**.
  Runtime instead loads `ida.dll`/`idalib.dll` from the discovered IDA install (PATH/DLL
  dir setup in the worker before FFI init; SDK stub libs are never used at runtime —
  known crash issue binarly-io/idalib#24).
- idalib 0.7.2 API surface covers: IDB open/save/auto_wait, functions (+CFG blocks,
  preds/succs), decompile via hexrays (pseudocode, ctree iteration), segments,
  strings, names, xrefs, bytes (get/patch via idalib-sys), comments (get/set/
  repeatable), text/immediate search, bookmarks, plugins. Gaps (imports/exports,
  types/til, create/delete functions, undefine, call-graph beyond depth 1) get a thin,
  isolated FFI layer (`reverse-ida-sys-ext`) documented with safety invariants.
- `rmcp` 3.x (official modelcontextprotocol/rust-sdk) supports stdio + Streamable HTTP.
- idalib is strictly single-threaded per initialized library → worker-process
  architecture: **one loaded IDB = one worker process = one IDA-owning thread**.

## Deliverables

### 1. Repo hygiene (first commit)
- Strong `.gitignore`: `GROK_TASK.md`, `*.7z`, `target/`, `*.i64`, `*.hexlic`,
  `ida.dll*`, `idalib.dll`, decompiler DLLs (`hex*.dll`), `idacli`, extracted IDA dirs.
- Delete `9.2.Pro.7z`.
- `scripts/check-distribution.ps1`: scans `git ls-files` for proprietary markers
  (extensions, hashes of known IDA binaries, license patterns); wired into CI; fails
  the build on any hit.

### 2. Workspace layout
```
crates/
  rmcp-core/        domain model: db handle, tool schemas, errors, result store, config
  rmcp-ida/         IDA backend: idalib 0.7.2 + minimal FFI extension layer
  rmcp-worker/      worker binary logic: single-threaded IDA loop, JSON-RPC IPC over stdio
  rmcp-broker/      session manager, worker supervision, MCP server (rmcp), CLI
src/main.rs         dispatch: serve | worker | doctor | open | sessions | inspect |
                    decompile | selftest | version  (one exe, CLI and MCP share core)
tests/  fixtures/   C fixture source (main/helper/decrypt_packet/switch/fn-ptr/imports/
                    struct/string), compiled during tests with MSVC or zig cc
docs/               architecture.md, mcp-tools.md, grok-build.md, ida-setup.md,
                    troubleshooting.md
scripts/            check-distribution.ps1, build-release.ps1
.github/workflows/  ci.yml (windows-latest primary; fmt, clippy -D warnings, tests,
                    distribution scan), release.yml (tag-triggered)
```
(Crate names adjusted from task draft to avoid confusion with the `rmcp` SDK crate.)

### 3. IDA auto-discovery (works on a fresh machine)
Resolution order, first hit wins; `doctor` prints every step:
1. `ida_dir` in `reverse-mcp.toml` / `--ida-dir`
2. `IDADIR` env var
3. Windows registry (`HKLM\SOFTWARE\Hex-Rays`, Wow6432 variant)
4. Common paths: `C:\Program Files\IDA*`, `%LOCALAPPDATA%\Programs\IDA*`,
   `/opt/ida*`, `~/ida-pro-*`, `/Applications/IDA*` (Linux/macOS for later)
5. Recursive scan of drive roots (depth-limited, cached) for a directory containing
   `ida.dll` + `idalib.dll` + `plugins/`
6. Verify found dir: version resource of `ida.dll` must be 9.2.x; worker calls
   `get_library_version()` at startup; mismatch → clear `doctor`/capability error.

### 4. MCP tools (~15, final set in docs/mcp-tools.md)
`ida_capabilities, ida_db, ida_inspect, ida_functions, ida_decompile, ida_disassemble,
ida_xrefs, ida_graph, ida_search, ida_bytes, ida_types, ida_edit, ida_analysis,
ida_batch, ida_result` — per GROK_TASK.md §9 semantics: `db` short handles (`db1`,
`target`), ambiguity error when omitted with >1 DB, bounded outputs everywhere,
`capability_unavailable` errors instead of faking, revision numbers + optional
`expected_revision` on mutations, batch with per-op results and caps.

### 5. Broker/worker runtime
- Broker: rmcp ServerHandler; per-db request queue; mutations exclusive; reads
  concurrent across DBs, serialized per DB; worker spawn/handshake/health/timeout/
  crash-detect/respawn/reopen; bounded queues; `max_workers` cap.
- IPC: newline-delimited compact JSON over worker stdio (measured first; only replaced
  if materially slow). IDs are small integers; no UUIDs in model-visible output.
- Result store: threshold (default ~24 KiB) → handle `r17` + preview + `ida_result`
  read/find/metadata/release; TTL configurable; truncation always flagged.
- Logging: `tracing` → stderr/file only; stdout reserved for MCP stdio framing.

### 6. CI (GitHub-hosted, no IDA needed)
- windows-latest: fetch `HexRaysSA/ida-sdk@v9.2.0-sdk.1` → set `IDASDKDIR` →
  `cargo fmt --check`, `clippy --workspace --all-targets -- -D warnings`,
  `cargo test` (unit + schema + mock-backend + CLI + broker concurrency tests +
  distribution scan).
- Mock backend behind a trait (`IdaBackend`) so broker/protocol/result-store logic is
  fully tested without IDA; mock additionally compiled with the real SDK headers in
  CI to catch build breakage early.
- Integration tests (open→analyze→enumerate→decompile→xrefs→strings→rename→comment→
  save→reopen→verify) exist in-tree, run only with `REVERSE_MCP_IDA_INTEGRATION=1`
  and a IDA 9.2 present.

### 7. Docs, release, report
- README (what/why headless/architecture/prereqs/license/doctor/stdio/HTTP/Grok Build
  config/multi-binary/concurrency/tool overview/troubleshooting/security/limits),
  docs/* per §16.
- Release: `cargo fmt/clippy/test` green → `gh repo create jacek4yang/reverse-mcp
  --public --source . --push` → meaningful commits throughout → tag `v0.1.0` →
  `reverse-mcp-v0.1.0-windows-x86_64.zip` (exe + LICENSE + setup reference) →
  SHA-256 → `gh release create` with truthful notes (IDA 9.2 required, not bundled, Windows x86_64 verified; Linux/macOS untested).
- Final report: repo/release URL, commit SHA, tag, artifact + checksum, test counts,
  integration-test status, MCP stdio/HTTP/multi-agent/multi-IDB/crash-recovery
  results, tool list, limitations, Grok Build config snippet.

## Execution order
1. Hygiene + .gitignore + delete archive + distribution-check script (commit 1)
2. Workspace scaffold + config/doctor/discovery (commit 2)
3. rmcp-core domain + result store + mock backend + broker/worker + MCP serve
   (commits 3–5, mock end-to-end stdio test green)
4. rmcp-ida against SDK from GitHub tag; cloud build proven in CI (commit 6)
5. Tools layer by layer (db/inspect/functions → disassemble/xrefs/graph →
   search/bytes/types/edit/analysis → decompile → batch) with unit tests per tool
   (commits 7–9)
6. Concurrency, revision, supervision/recovery, HTTP mode, stress tests (commit 10)
7. Docs + Grok Build guide (commit 11); fmt/clippy/test sweep
8. Publish + release + local runtime verification if a IDA 9.2 is
   available, else ship with honest limitation note