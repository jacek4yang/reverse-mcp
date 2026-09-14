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
- Multi-version discovery with per-version backend readiness; refused fallback.
- Function-wide calls graph + CFG graph with hard bounds.
- Optimistic concurrency: `expected_revision` enforced on all mutations.
- Result store for oversized responses.
- MCP stdio transport, 17 tools.
- Test layers: mock unit/e2e (CI, no IDA) and real-IDA integration
  (`tests/idalib_real.rs`, local, `--ignored`).

## Known limitations (honest)

- `patch_bytes`: the tool surface and `expected_revision` plumbing exist, but
  the real backend returns `capability_unavailable` — IDB byte patching is not
  implemented yet. `ida_bytes action=patch` therefore fails on the real backend.
- `ida_types action=set`: returns `capability_unavailable`; only `list`/`get`
  of local types are wired, and even those are partial (til access via the
  vendored binding is limited).
- `imports_exports: true` in capabilities is optimistic — dedicated
  import/export enumeration tools do not exist yet; imports are only visible
  through names/xrefs.
- stdio only: no Streamable HTTP transport yet.
- No worker crash recovery yet: an unexpected worker death fails pending
  requests; the caller must close and reopen the DB. No state machine, no
  automatic respawn.
- Windows x86_64 verified only. Linux/macOS paths exist in discovery but are
  untested.
- One verified backend version: 9.2. Other installed IDA versions are
  discovered and reported as `backend unavailable`.
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
