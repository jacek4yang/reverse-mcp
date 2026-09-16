# Limitations & Roadmap

Status: accurate as of the `feat/issue49-docs-sync` branch (2026-09-16), after PR #26 merged to main.

This document exists so the tool set is never overstated. Anything not listed
under "Shipped" does not work yet.

## Shipped (real, tested)

- Single `reverse-mcp.exe`: broker (MCP stdio / `serve --http`) + self-spawned
  `worker` mode processes; one worker per loaded IDB.
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
  `ctree`, `lvars`, `microcode` (see the #43 entry below), `switches`, `fixups`,
  `tails`, `sp_delta`, `file_map`.
- #43 microcode generation/inspection (real-IDA verified on
  `tests/fixtures/obfuscated.exe`): `ida_hr action=microcode` runs the full
  Hex-Rays microcode pipeline (gen_microcode up to MMAT_* maturity) for one
  function and returns a bounded dump — blocks (serial, type, start/end EA,
  MBL_ flags, pred/succ/insn counts) and rendered instructions (mcode opcode,
  operand kinds as mopt_t codes, destination size, immediate value, SDK text).
  Analysis-only: the mba is generated, walked and freed inside the worker shim
  (natural[] access, no QASSERT data imports, so /DELAYLOAD stays intact).
  max_insns (default 2000, cap 20000) bounds the dump; tiny budgets set
  `truncated`. Repeats on an unchanged revision are served from the
  revision-keyed cache (`cached:true`); any mutation invalidates it.
- Multi-version discovery with per-version backend readiness; refused fallback.
- Function-wide calls graph + CFG graph with hard bounds.
- Optimistic concurrency: `expected_revision` enforced on all mutations.
- Result store for oversized responses.
- MCP transports: stdio and Streamable HTTP (`serve --http`, loopback
  default), 33 tools.
- #14 analysis index + evidence search (real-IDA verified): database-wide
  `AnalysisIndex` (functions with imports/strings/constants/indirect calls/
  callees/callers/globals; string reference lists), structured predicate
  queries via `ida_evidence` (combinable `all`/`any`/`not` predicates with
  per-hit concrete evidence), persistent cache under the reverse-mcp cache
  dir keyed by input md5 + revision + schema version (corrupt/stale cache
  fails safely and rebuilds), revision-based incremental invalidation (any
  mutation marks the index stale; the next query rebuilds).
- #20 MCP interface redesign: MCP resources (`ida://db/{id}/metadata,
  segments, entrypoints, imports, exports, info`) for read-only context
  without tool calls (bounded by the same output budget); workflow prompts
  (`ida_survey_binary`, `ida_analyze_function_deep`, `ida_trace_data_flow`,
  `ida_safe_refactor`, `ida_compare_binaries`) that teach high-level
  workflows; `ida_capabilities` extended with backend identity (processor,
  bits, decompiler, revision) and output budgets; tool count intentionally
  kept at 26 instead of per-API tool sprawl.
- #16 mutation layer (real-IDA verified): `ida_bytes action=patch` now works
  on the real backend (SDK `patch_bytes`, persists after save/reopen, audit
  records original vs patched bytes). `ida_mutation` tool adds a
  transaction-like layer: `plan` (validate + preview without changes, whole-
  plan revision guard), `apply` (sequential execution with per-op results,
  partial-outcome reporting on failure, stale revision rejects the whole plan
  before the first op), `audit` (bounded per-session trail of applied
  mutations with old/new state), `snapshot`/`rollback` (file-level IDB
  snapshot: save + copy the database file aside; restore = close without
  saving, restore the copy, reopen).
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
- #8 composite analysis workflows (real-IDA verified): `ida_analyze` runs six
  one-call context workflows (`function_context`, `call_neighborhood`,
  `reference_context`, `import_usage`, `subsystem_context`, `trace_call_path`)
  over the #14 analysis index — one MCP call replaces several atomic calls.
  Request budgets (`depth`, `max_functions` clamped 1..50, `detail`,
  `include_noise`) bound output; high-confidence CRT/thunk noise is filtered
  from graph walks (opt-in `include_noise=true`); results are cached per
  (workflow, request, revision) with `cached`/`cache_hits` reported and the
  whole cache invalidated by any successful mutation; `detail=summary` keeps
  decompilation out unless explicitly requested (`detail=full`).
- #10 deep analysis (real-IDA verified): `ida_deep` runs recursive
  decompilation with type propagation (`deep_function`), bounded data-flow
  evidence (`trace_dataflow`, `confirmed` vs `heuristic` per call site) and
  prototype application (`retype`). Efficiency model: decompilation runs
  exactly once per function per run (callees-first walk); propagation is
  dirty-driven (only callers of changed functions are re-checked); unchanged
  repeats are served from the revision-keyed cache with no decompilation.
  Robustness: visited-set cycle guards (mutual recursion terminates),
  strict budgets (`depth`, `max_functions`, `max_iterations`, `max_calls`)
  plus an agent-settable wall-clock `timeout_ms` (broker clamps 5s..30min,
  worker enforces 1s..30min) that stops the run and returns partial results
  with `budget_hit: true`. The engine does not yet implement full ctree
  slicing or virtual-call target resolution; indirect-call evidence is
  reported as heuristic, never confirmed.
- #11 type recovery (real-IDA verified): `ida_type_recovery` aggregates
  member-access evidence (typed `obj->field` and untyped pointer-arith
  accesses) across functions into field proposals with per-field
  read/write counts, candidate width/type and bounded confidence; shape
  matching against existing local types; vtable scans mapping slots to
  candidate methods. Proposal and apply are strictly separated
  (`propose` is read-only; `create_struct` is the only mutation) and the
  applied struct persists in the IDB. Scope notes: confidence is a simple
  bounded heuristic, not a trained model; base/derived class recovery and
  COM interface layouts are not yet inferred; constructor/destructor
  identification is limited to vtable-write patterns encountered during
  evidence walks (no dedicated ctor/dtor scanner yet).
- #12 binary intelligence (real-IDA verified): `ida_intel` scans for
  crypto constants (public-spec values: AES S-box/inverse, SHA-1/256/MD5
  IVs, SHA-256 K, CRC-32 table, Blowfish P-array, TEA delta), detects and
  verifies API-hash resolvers against a corpus built from the DB's own
  imports (5 algorithms: ror13-add, wide variant, ror15-add, rol7-xor,
  crc32), and recovers stack/array strings from immediate-store analysis.
  All findings carry provenance (EA, containing function, callers) and are
  ranked by bounded confidence; nothing mutates the IDB. #47 adds external
  rule packs: `<exe_dir>/rules/*.json` extends the built-in constant set
  with an open, fail-closed JSON format (docs/RULE_PACKS.md) — every hit
  row records deterministic provenance (pack name + content fingerprint +
  rule id) and `ida_intel task=packs_list` surfaces the loaded packs; scan
  bounds and caching are unchanged. Scope notes:
  the algorithm registry is parameter-light (no module-name + API-name
  combination hashing yet); string decode is limited to what ctree
  immediates expose (no full emulator); resolver algorithm inference is
  corpus-verification-based, not decompiler-derived; api_hash/string rules
  load and validate but do not yet feed the resolver/strings tasks.
- #9 deobfuscation (real-IDA verified): `ida_deobfuscate` runs an
  analysis-only pass engine (flattening CFG shape, opaque/redundant
  branches, indirect transfers, junk no-ops, tail-jumps) with per-pass
  evidence, bounded confidence and failure reporting. Strictly
  analysis-only: no IDB metadata repairs and no byte patches — all
  transformations are proposals; regression tests assert plain functions
  do not trigger detectors and the DB revision is unchanged by runs.
- #46 transform framework (real-IDA verified): `ida_deobfuscate
  task=propose|validate|apply|rollback` adds explicit, two-phase
  transformations on top of #9: patch-level plans (T1/T2/T3) are built as
  JSON data, validated against the live DB (outside-function sites,
  inbound xrefs and unreadable bytes are rejected with evidence), applied
  after a snapshot with a whole-plan `expected_revision` guard through the
  audited mutation machinery, and rolled back via the snapshot path
  (audited, revision-bumping). Scope notes: transforms are patch-level
  (byte NOPs) bounded to one function with at most 16 sites; T4
  (unflattening) reports `requires_microcode` and emits no plan; microcode
  -level rewriting is still future work (#43 provides inspection only).
- #13 signatures & cross-IDB (real-IDA verified): `ida_sig` builds
  multi-family function fingerprints (imports, strings, constants, call
  shape, size) on the analysis index, persists them as open JSON
  (`.rsig.json`), ranks identify/map candidates with per-family evidence,
  and produces cross-IDB transfer PROPOSALS with conflict detection
  (meaningful target names are never silently overwritten). Two compiled
  variants of one source map with ranked, explained matches; strict
  matches (overall >= 0.85, family floor 0.50) gate rename proposals while
  relaxed matches stay hints. #45 adds block-level diff: bounded CFG
  fingerprints (normalized mnemonic-sequence hash + constant set + edge
  shape), block classification equal/modified/added/removed, two-session
  orchestration (each session fingerprints its own DB; the diff itself is
  pure data — idalib binds one DB per process), and name pairing with a
  family-evidence similarity fallback so stripped rebuilds pair by
  evidence. Scope notes: families are index-derived
  (no microcode-level signatures yet); call shape uses counts, not
  neighbor identity; block fingerprints are x86/x64-normalized (scores are
  not portable across architectures); pairing is per-function, never a
  whole-binary O(N²) block cross-match.
- Test layers: mock unit/e2e (CI, no IDA) and real-IDA integration
  (`tests/idalib_real.rs`, local, `--ignored`).

## Known limitations (honest)

- `ida_types action=set`: returns `capability_unavailable`; only `list`/`get`
  of local types are wired, and even those are partial (til access via the
  vendored binding is limited).
- `microcode: true` as of #43 — `ida_hr action=microcode` generates microcode
  up to a requested maturity (MMAT_*) and returns a bounded block/insn dump
  (read-only, revision-keyed cache). Microcode-level *transforms* (unflattening
  etc.) remain proposals only; they are tracked in #46 and require the
  microcode transform infrastructure, which does not apply IDB mutations yet.
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
- Windows x86_64 verified only. Linux/macOS paths exist in discovery and
  DotSlash pinfiles cover linux-x86_64/macos-x86_64/macos-aarch64, but no
  real-IDA runtime test has passed there — platform support is claimed only
  from tested facts (expansion tracked in #48).
- One verified backend version: 9.2 (pinned in the backend registry with
  SDK commit + FFI/generator versions + ABI probe facts). Other installed
  IDA versions are discovered and reported as `backend unavailable`.
- The ABI probe verifies `backends/abi/expected-9_2.json` against the real
  SDK headers locally; public CI verifies only the JSON structure and the
  Rust-side mirrors, not the proprietary headers.
- `revision` is per-worker-process memory: it does not survive close/reopen.
- `ida_batch` is read-only by design.

## Roadmap (see open issues for current order)

Tracked as GitHub issues (#43–#50): microcode-level transforms (#43),
value/register analysis (#44), block-level binary diff (#45), deobfuscation
transforms with rollback (#46), external rule packs (#47), platform/version
expansion (#48), real-IDA benchmark suite (#50). Items below are landed and
kept for history:

1. ~~Real types support and real IDB byte patching~~ (landed: #19/#16).
2. ~~Worker crash recovery: state machine with bounded respawn/backoff~~
   (landed: #15, `crates/rmcp-broker/src/recovery.rs`).
3. ~~Streamable HTTP transport (loopback default) + multi-agent stress tests~~
   (landed: #15, `serve --http`).
4. ~~DotSlash toolchain + ABI probe~~ (landed: #17).
5. Docs polish, release pipeline, `v0.1.0` artifact
   (`reverse-mcp-v0.1.0-windows-x86_64.zip` + SHA-256), gated on the local
   real-IDA acceptance chain (release pipeline itself still open).
