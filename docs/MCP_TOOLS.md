# MCP Tools Reference

Status: accurate as of the #49 documentation sync (2026-09-16), main branch.

33 tools. `reverse-mcp bench` runs a reproducible mock-mode task benchmark (round trips, output bytes, wall time, correctness) for regression gating (issue #18); see docs/CAPABILITY_MATRIX.md for the audited capability matrix. Every list/search/graph result is bounded; oversized responses spill
to the result store (`result_ref: rN` + preview), never truncated silently.
Addresses are hex strings (`0x401000`) or decimal. Optional `db` handle: omit it
when exactly one DB is open; with several open, omitting it yields `db_ambiguous`.

Timeouts: long-running analysis tools accept an agent-controlled
`timeout_ms` (clamped 5s..30min broker-side). Defaults: 600s for
`ida_deep` / `ida_type_recovery` / `ida_intel` / `ida_analyze`; 300s for
`ida_deobfuscate` / `ida_sig`; 120s for all other calls. A budget hit returns
partial results with a resume token instead of an error where the engine
supports it (see `ida_deep`).

## Session / environment

### ida_db
`action=open` (path, optional `backend`: `auto`/`mock`/`idalib`, optional
`ida_version`: `9.2`, `latest`, or a range like `>=9.2,<9.4`), `info`, `save`,
`close`, `list`. `open` returns the db handle (`db1`, ...). `info` includes
`function_count`, `min_ea`/`max_ea`, `segment_count`, `bits`, `processor`,
`decompiler`.

### ida_capabilities
Per-DB capability report: `decompile` (hexrays present), `types` (false today),
`patch_bytes` (false today), `rename`, `comments`, `bookmarks`, `plugins`,
`imports_exports`.

### ida_installations
All IDA installs discovered on the machine: version, root, source, decompilers,
backend readiness. Use with `ida_db open ida_version`.

### ida_health
Self-diagnosis that works even when no IDA install is found: discovery results
with per-install runtime-DLL presence (`ida.dll`, `idalib.dll`), worker-binary
probe, idalib feature availability, and a remediation hint. Call this first
when opens fail or the server appears broken: it distinguishes "no install
found" from "install present but DLLs missing" from "worker binary broken".

### ida_mutation
Transaction-like mutation layer. `action=plan`: validate + preview a batch of
operations (rename, comment, patch_bytes with hex, func.create, func.delete,
set_type) without changing anything, with a whole-plan `expected_revision`
guard. `action=apply`: run the plan sequentially with per-op results; a stale
revision rejects the whole plan before the first op runs, and a mid-plan
failure reports `partial: true` with everything already applied. `action=
audit`: bounded per-session trail of applied mutations (old/new state,
revision after each). `action=snapshot`: file-level IDB snapshot (deterministic
rollback). `action=rollback`: close without saving, restore the snapshot,
reopen.

## Reading

### ida_functions
Paginated function list (`offset`, `limit<=1000`): `ea_start`, `ea_end`, `name`,
`size`.

### ida_inspect
One address: function (if any), name, bytes around it.

### ida_decompile
Hex-Rays pseudocode of the function containing `ea`; requires the Hex-Rays
decompiler (`capability_unavailable` otherwise). `ea` must be inside a function.

### ida_disassemble
Bounded disassembly from `ea` (stop at `end` or after `max_insns<=5000`): per-
instruction `ea`, `mnemonic`, `operands`, cleaned `text`.

### ida_xrefs
`direction=to` (default: who references this address) or `from` (what this
address references). Entries: `from`, `to`, `kind` (call/data/flow/far/jump).

### ida_graph
Graph rooted at the function containing `ea`.

- `kind=calls` (default): function-wide call discovery 鈥?walks every instruction
  in the function's range, collects call targets (operand direct targets + code
  xrefs), resolves each target to its containing function, and follows into
  callees up to `depth<=5`.
- `kind=cfg`: IDA flow chart of the function 鈥?basic blocks (`bb_<ea>`) with
  flow edges (succs + fallthrough).

Both bounded by `max_nodes` (default 200, max 5000) and `max_edges` (default
400, max 10000); a truncated response is flagged `"truncated": true`. Graph
edges from `calls` carry the `callsite` address.

### ida_search
`kind=text` (needle inside the DB strings list) or `kind=immediate` (32-bit
immediate `value`). Bounded by `limit`.

### ida_bytes
`action=get` (`size<=4096`) returns hex; `action=patch` applies bytes 鈥?see
Limitations.

### ida_segments
Segment list: `name`, `start_ea`, `end_ea`, permissions (`rwx`).

### ida_analysis
`analyze_wait`: blocks until auto-analysis finishes; returns `analyzed` and the
function count.

### ida_metadata
Extended DB metadata: `md5`/`sha256` of the input file (null when
unavailable), `imagebase`, `entry_count` + `entries` (ordinal/ea/name), plus
honest `tls_callbacks_supported:false` / `exception_handlers_supported:false`
fields (not exposed by the SDK surface used).

### ida_imports
Imported modules with entries (`ea`, `name`, `ordinal`); `module` selects one
index, `offset`/`limit` paginate.

### ida_fixups
Fixup/relocation records (`ea`, `kind`, `flags`, `base`, `sel`, `off`,
`displacement`) with `total`; `offset`/`limit` paginate.

### ida_filemap
`value` + `to_ea=false` (default) maps an EA to the input-file offset;
`to_ea=true` maps a file offset back to an EA. Unmapped values error cleanly.

### ida_func
Function-structure operations. `action=tails` lists the function's chunks
(entry + tails) with sizes and `is_tail_target`; `switch_info` returns bounded
jump-table metadata (flags, jump/value table, ncases, elbase, ...) for the
indirect jump at `ea`; `sp_delta` returns the cumulative SP delta at `ea`.
`create` (`start`, optional `end`), `delete` (`ea`) and `resize` (`ea`,
`new_start`/`new_end`) are mutations: they bump the revision and honour
`expected_revision`.

### ida_hr
Hex-Rays structured view. `action=cfunc` (default) returns the function's
`return_type`, bounded typed `ctree` node summaries (`ea`, `op` as
cot_*/cit_* codes, `c` payload: number value / object EA / var index / member
offset / pointer size, rendered `text`) and `lvars` (`defea`, `name`,
`type_text`, `width`, `is_arg`, `is_result`); `include_ctree`/`include_lvars`
gate the lists, `limit` bounds rows, `*_truncated` flags an exceeded limit.
`action=lvar_rename` renames a lvar by `var_defea` (as reported in `cfunc`
lvars); it is a mutation: bumps the revision and honours `expected_revision`,
and the new name is visible in subsequent decompilations.

### ida_insn
Instruction-level metadata: `action=features` returns the canon `CF_*`
feature bits and mnemonic at `ea`; `action=demangle` demangles `name`
(`changed:false` + passthrough when the name is not demangleable).

## Mutating

### ida_edit
`rename` (new name; collisions auto-uniquified via `SN_FORCE`) and/or `comment`
(`repeatable` flag) at `ea`. Returns `{"changed": true, "revision_after": N}`.

### ida_types
`list` / `get` by name today; `set` with `decl`+`ea` is currently
`capability_unavailable` (see Limitations).

### ida_batch
Up to 20 read-only operations in one round trip, each `{"tool", "args"}`; per-op
results or errors.

### ida_result
Access spilled results: `read` (by `handle` or `text` search), `metadata`,
`find`, `release`.

### ida_evidence
Structured evidence search over a database-wide, revision-aware analysis
index (#14). `action=query` runs a predicate tree: `import`, `string_contains`,
`name_contains`, `constant`, `has_indirect_calls`, `callee_matches`,
`caller_matches`, `reachable_from` (root_ea + levels), `all`/`any`/`not`
combinators. Example: `{"all":[{"import":"VirtualAlloc"},
{"has_indirect_calls":{"min":1}}]}`. Every hit lists concrete matched
evidence (`matched: ["import:VirtualAlloc", "indirect_calls:2", ...]`); the
score is the evidence count, never an opaque number. `action=build` builds
and persists the index under the reverse-mcp cache dir (never IDA's own
directories; keyed by input md5 + revision + schema version; corrupt or
stale cache fails safely and rebuilds). `action=status` reports identity and
whether the index is current 鈥?any mutation bumps the revision and
invalidates it.

### ida_analyze
Agent-native composite analysis workflows (#8): one call returns the context an
agent would otherwise gather with several atomic calls. `ida_analyze` takes the
workflow request as its whole argument and runs `workflow.run` in the worker:
`{"workflow": "...", "ea": "0x140001000", "detail": "summary", ...}`.

Workflows:
- `function_context` 鈥?one-call function briefing: index facts (imports called,
  strings, constants, indirect calls, callers/callees from the index) plus
  xrefs_to (鈮?0). `detail=full` adds decompilation; `summary` (default) omits it.
- `call_neighborhood` 鈥?BFS over call edges from a function, CRT/thunk noise
  filtered (opt back in with `include_noise=true`); reports `truncated` when the
  `max_functions` budget clips the frontier.
- `reference_context` 鈥?who references this data/address: xrefs, the containing
  function, its callers; non-summary detail adds a bounded snippet.
- `import_usage` 鈥?all functions calling a given import, name matched
  case-insensitively against the index.
- `subsystem_context` 鈥?BFS from multiple roots at once; non-summary detail
  adds bounded snippets per function.
- `trace_call_path` 鈥?call path from a function to a target (`target_ea`),
  BFS over caller edges; `found: false` when no route exists within `depth`.

Budgets (per request): `depth` (default 2), `max_functions` (default 10,
clamped 1..50), `detail` (`summary`|`normal`|`full`), `include_noise`. EA
values accept `0x`-hex strings or numbers. Results come from the #14 analysis
index; the index is built or rebuilt automatically when missing or stale.
Responses are cached per (workflow, normalized request, revision) and any
successful mutation invalidates the whole cache; cache hits carry
`cached: true` and `cache_hits`. Oversized responses spill to the result store
as usual.

### ida_deep
Deep analysis (#10): recursive decompilation with type propagation and
bounded data-flow. Three tasks:

- `deep_function` 鈥?post-order recursive walk: callees decompile first, then
  the caller; the recorded prototype already reflects callee improvements,
  so each function is decompiled exactly once per run. Propagation then runs
  on the collected call graph: a function whose prototype changed marks its
  callers dirty and only those are re-checked (functions whose callees did
  not change are never touched again). Reports a convergence trace
  (`iteration N: k type changes ... 0 -> converged`), per-function dossiers
  (prototype, direct call sites with EAs, indirect calls) and a
  `skipped` list explaining what the budget left out.
- `trace_dataflow` 鈥?bounded source->sink evidence across callers/callees
  (`direction=forward|backward|both`). Every evidence row cites the concrete
  call-site EA, the function containing it, and a confidence tag:
  `confirmed` for direct calls, `heuristic` for indirect sites.
- `retype` 鈥?apply a C prototype declaration to a function (mutation;
  invalidates the analysis caches and bumps the revision).

Budgets (agent-controlled, hard caps): `depth` (1..8, default 3),
`max_functions` (1..100, default 20), `max_iterations` (1..20, default 5),
`max_calls` (1..200, default 24), `timeout_ms` (1000..1800000) 鈥?wall-clock
budget; on expiry the run stops and reports `budget_hit: true` with partial
results. Repeats on an unchanged DB revision are served from the
revision-keyed cache (`cached: true`), so re-running without DB changes
performs no decompilation at all.

### ida_type_recovery
Type recovery (#11): infer structure shapes from member-access evidence and
discover vtable candidates. Four tasks:
- `evidence` 鈥?bounded member-access observations of one decompiled
  function: base object, offset, access width, read/write, EA. Covers both
  typed `obj->field` accesses (cot_memptr) and untyped pointer arithmetic
  (`*(T *)((char *)obj + off)`).
- `propose` 鈥?aggregate observations across several functions into field
  proposals with per-field evidence (read/write counts, candidate
  width/type, confidence in [0,1] derived from site counts, independent
  functions, write evidence and width consistency) and a shape match
  against existing local types. PREVIEW ONLY 鈥?nothing is mutated.
- `vtable` 鈥?scan an EA as a vtable: slots resolved to code targets and
  function names; a plausibility verdict (>= 2 code slots).
- `create_struct` 鈥?APPLY a reviewed struct definition (name + fields
  `offset:size:name:type_decl`) as an explicit mutation; bumps the revision
  and invalidates caches. Applied types persist in the IDB.

Proposals never apply silently; observed facts, inference and the applied
mutation are reported separately.

### ida_intel
Binary intelligence (#12): crypto constants, API-hash resolvers, recovered
strings. Three read-only tasks:
- `crypto_scan` 鈥?scans all segments for known crypto constants (AES S-box
  and inverse, SHA-1/SHA-256/MD5 initial states, SHA-256 round constants,
  CRC-32 reflected table, Blowfish P-array, TEA/XTEA delta 鈥?public spec
  values, no third-party rule files). Findings are ranked by confidence
  (rarity-weighted) and each carries the containing function and its
  callers from the analysis index, so one request goes from a constant to
  usable context.
- `resolve_api_hashes` 鈥?detects likely hash-resolver functions (constant
  density + size shape from the #14 index) and verifies candidate
  algorithms (ror13-add, ror13-add-wide, ror15-add, rol7-xor, crc32)
  against a corpus built from the DB's own import names. Verified
  constants list the algorithm + API name; single-hash resolvers are
  flagged low-confidence (0.45) so false positives are visible.
- `recover_strings` 鈥?stack/array string recovery: immediate-store values
  from a function's ctree assemble into printable runs (>= 4 chars) with
  per-run source EAs. The IDB is never patched; decoding is reported, not
  applied.

Results are bounded (`max_findings`/`max_strings`, clamped) and cached per
DB revision via the workflow cache.

### ida_deobfuscate
Deobfuscation analysis (#9): an analysis-only pass engine over one
function. Passes (each with name/version, confidence, evidence, proposed
changes, failure reason, deterministic budget):
- `flatten_detect` 鈥?CFG dispatcher-shape detection (avg in-degree,
  node/edge counts).
- `opaque_branch` 鈥?constant/self comparisons in ctree plus assembly-level
  `cmp regX, regX` / `test regX, regX` followed by a conditional jump.
- `indirect_transfer` 鈥?unresolved `jmp reg` / `call reg` sites.
- `junk_code` 鈥?redundant store/load round trips (`mov [mem], reg` /
  `mov reg, [mem]` pairs on one slot), self-moves, `add 0`.
- `tail_jump` 鈥?`jmp reg` where the register was just assigned (tail-call
  obfuscation).

SAFETY: analysis-only. No IDB metadata repairs, no byte patches;
transformations are proposals the agent can apply later through explicit
mutation tools. `max_passes` (1..16, default 8) bounds the run; a failed
pass reports its failure reason and leaves the database usable. Regression
tests assert plain functions do not trigger detectors.

### ida_sig
Function signatures & cross-IDB comparison (#13). Multi-family
fingerprints (imports, strings, constants, call shape, size 鈥?never a
single hash) built on the analysis index, persisted as open JSON
(`.rsig.json`, documented format, no proprietary content):
- `export` 鈥?build + persist the signature index next to the DB.
- `identify` 鈥?rank reference-index candidates for one function with
  per-family evidence (`imports`/`constants`/`strings`/`calls`/`size`,
  each 0..1) and an overall score. `strict` matches (overall >= 0.85, no
  family below 0.50) are safe for rename proposals; `relaxed` matches are
  hints only.
- `map` 鈥?cross-IDB function mapping between two exported indexes,
  producing TRANSFER PROPOSALS: ranked pairs with per-family evidence and
  conflict detection (a target with a meaningful, non-auto name is flagged
  `conflict: true` and requires explicit approval). Nothing is applied
  automatically; application goes through rename mutations with
  `expected_revision`.

Works across multiple simultaneously-open workers (both DBs export, then
map).

## Resources (read-only context)

Frequently-read state is exposed as MCP resources so agents can pull context
without tool calls; content passes the same output budget as tools:

- `ida://db/{id}/metadata` 鈥?extended metadata (md5/sha256, image base,
  entry points)
- `ida://db/{id}/segments` 鈥?all segments
- `ida://db/{id}/entrypoints` 鈥?entry points (ordinal/ea/name)
- `ida://db/{id}/imports` 鈥?imported modules and entries (paginated)
- `ida://db/{id}/exports` 鈥?export view (entry points)
- `ida://db/{id}/info` 鈥?basic DB info (function count, processor, bits)

`{id}` is the db handle returned by `ida_db action=open`. Unknown handles
yield a stable `unknown_db` error.

## Prompts (workflow hints)

Optional prompts that encode the recommended workflow; clients list them via
`prompts/list` and render with `prompts/get`:

- `ida_survey_binary` 鈥?metadata/segments/entrypoints/imports survey, then a
  structure report
- `ida_analyze_function_deep` 鈥?inspect 鈫?decompile 鈫?lvars 鈫?xrefs 鈫?
  constants, evidence-table summary
- `ida_trace_data_flow` 鈥?bidirectional xref walk with per-hop decompilation
- `ida_safe_refactor` 鈥?plan 鈫?preview 鈫?snapshot 鈫?apply with
  expected_revision 鈫?audit
- `ida_compare_binaries` 鈥?two-db diff of counts, segments, strings, hashes

## Optimistic concurrency

Every mutating tool (`ida_edit`, `ida_bytes action=patch`, `ida_types
action=set`, `ida_func action=create/delete/resize`, `ida_hr
action=lvar_rename`, `ida_mutation action=apply`) accepts `expected_revision`.
If present and stale, the
mutation is
rejected with `revision_conflict` before touching the DB; the revision only
increments after a confirmed successful mutation. Omitted 鈫?no check.
`ida_mutation action=apply` guards the WHOLE plan: a stale revision rejects
the batch before the first operation runs.
