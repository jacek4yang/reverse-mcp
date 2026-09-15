# Limitations & Roadmap

Status: accurate as of commit `b8fe1cd` (2026-09-15), main branch.

This document exists so the tool set is never overstated. Anything not listed
under "Shipped" does not work yet.

## Shipped (real, tested)

- Single `reverse-mcp.exe`: broker (MCP stdio) + self-spawned `worker` mode
  processes; one worker per loaded IDB.
- Real IDA 9.2 backend: open/save/close, auto-analysis, functions, segments,
  strings, names, bytes read, xrefs (to/from), disassembly, Hex-Rays
  decompilation, rename, comments, bookmarks, plugins.
- #19 native capability layer (real-IDA verified on `tests/fixtures/simple.exe`):
  db.metadata (md5/sha256/imagebase/entries), imports.list (per-module entries),
  fixups.list, file.map (EA<->file offset), func.tails (chunks incl. tails),
  func.create/delete/resize (mutation + revision), func.sp_delta,
  insn.features (canon CF_* bits + mnemonic), names.demangle,
  hr.cfunc (bounded typed ctree node summaries with rendered text, lvars with
  type/width/arg flags, return type), hr.lvar_rename (persists via user lvar
  settings, visible in re-decompilation). Capabilities extended honestly with
  `ctree`, `lvars`, `microcode:false`, `switches`, `fixups`, `tails`,
  `sp_delta`, `file_map`.
- Multi-version discovery with per-version backend readiness; refused fallback.
- Function-wide calls graph + CFG graph with hard bounds.
- Optimistic concurrency: `expected_revision` enforced on all mutations.
- Result store for oversized responses.
- MCP stdio transport, 25 tools.
- #28 Windows loader hardening (real-IDA verified): `ida.dll`/`idalib.dll` are
  delay-loaded (`/DELAYLOAD` + `delayimp.lib`) so the broker and mock-worker
  modes start without the IDA install dir on PATH — previously the process died
  with 0xC0000135 before `main`. The worker preloads the DLLs at CRT startup
  (`.CRT$XCU` constructor) whenever `REVERSE_MCP_IDA_DIR` is exported, and
  prepends that dir to `PATH` so IDA's plugin/loader lookups succeed. Workers
  that die before the protocol handshake now produce a stable
  `capability_unavailable` diagnostic naming the missing DLLs and the fix
  (`set IDADIR or add the install dir to PATH`). New `ida_health` MCP tool
  self-reports discovery, runtime-DLL presence, worker probe and idalib
  feature availability even when no install is found.
- Test layers: mock unit/e2e (CI, no IDA) and real-IDA integration
  (`tests/idalib_real.rs`, local, `--ignored`).

## Known limitations (honest)

- `patch_bytes`: the tool surface and `expected_revision` plumbing exist, but
  the real backend returns `capability_unavailable` — IDB byte patching is not
  implemented yet. `ida_bytes action=patch` therefore fails on the real backend.
- `ida_types action=set`: returns `capability_unavailable`; only `list`/`get`
  of local types are wired, and even those are partial (til access via the
  vendored binding is limited).
- `microcode: false` — microcode generation/inspection is NOT implemented in
  #19 and is reported as unsupported in capabilities (planned in #9).
- `func.switch_info`: implemented against `get_switch_info()`, but on the
  test fixture the switch compiles to a cmp chain (no jump table), so no
  address carries switch info there; a real jump-table switch is required to
  exercise the populated path.
- TLS callbacks and exception handlers are not exposed by the SDK surface used
  here; `db.metadata` reports `tls_callbacks_supported:false` and
  `exception_handlers_supported:false` explicitly.
- hr.lvar_rename targets a lvar by its locator definition EA as reported in
  `hr.cfunc` lvars; renaming a lvar that shares its defea with another lvar
  (e.g. two args keyed to the entry) may rename the matching locator slot
  rather than a specific one.
- stdio only: no Streamable HTTP transport yet.
- No worker crash recovery yet: an unexpected worker death fails pending
  requests; the caller must close and reopen the DB. No state machine, no
  automatic respawn.
- Windows x86_64 verified only. Linux/macOS paths exist in discovery and
  DotSlash pinfiles cover linux-x86_64/macos-x86_64/macos-aarch64, but no
  real-IDA runtime test has passed there — platform support is claimed only
  from tested facts.
- One verified backend version: 9.2 (pinned in the backend registry with
  SDK commit + FFI/generator versions + ABI probe facts). Other installed
  IDA versions are discovered and reported as `backend unavailable`.
- The ABI probe verifies `backends/abi/expected-9_2.json` against the real
  SDK headers locally; public CI verifies only the JSON structure and the
  Rust-side mirrors, not the proprietary headers.
- `revision` is per-worker-process memory: it does not survive close/reopen.
- `ida_batch` is read-only by design.

## Roadmap (in planned order)

1. Real types support (til access, function prototypes, apply type) and real
   IDB byte patching (hex validation, old bytes, persist after save/reopen).
2. Worker crash recovery: state machine (Healthy → Crashed → Recovering →
   Healthy), bounded respawn with backoff, session metadata persisted in the
   broker, restore the same public db handle; never replay unknown-success
   mutations.
3. Streamable HTTP transport (loopback default) + multi-agent stress tests.
4. DotSlash toolchain for public build deps (LLVM/libclang only — never IDA)
   + ABI probe hardening in `reverse-ida-sys`.
5. Docs polish, release pipeline, `v0.1.0` artifact
   (`reverse-mcp-v0.1.0-windows-x86_64.zip` + SHA-256), gated on the local
   real-IDA acceptance chain.
