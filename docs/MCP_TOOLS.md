# MCP Tools Reference

Status: accurate as of commit `d1d1937` (2026-09-15), branch feat/issue17-versioned-backends.

25 tools. Every list/search/graph result is bounded; oversized responses spill
to the result store (`result_ref: rN` + preview), never truncated silently.
Addresses are hex strings (`0x401000`) or decimal. Optional `db` handle: omit it
when exactly one DB is open; with several open, omitting it yields `db_ambiguous`.

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

- `kind=calls` (default): function-wide call discovery — walks every instruction
  in the function's range, collects call targets (operand direct targets + code
  xrefs), resolves each target to its containing function, and follows into
  callees up to `depth<=5`.
- `kind=cfg`: IDA flow chart of the function — basic blocks (`bb_<ea>`) with
  flow edges (succs + fallthrough).

Both bounded by `max_nodes` (default 200, max 5000) and `max_edges` (default
400, max 10000); a truncated response is flagged `"truncated": true`. Graph
edges from `calls` carry the `callsite` address.

### ida_search
`kind=text` (needle inside the DB strings list) or `kind=immediate` (32-bit
immediate `value`). Bounded by `limit`.

### ida_bytes
`action=get` (`size<=4096`) returns hex; `action=patch` applies bytes — see
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

## Optimistic concurrency

Every mutating tool (`ida_edit`, `ida_bytes action=patch`, `ida_types
action=set`, `ida_func action=create/delete/resize`, `ida_hr
action=lvar_rename`) accepts `expected_revision`. If present and stale, the
mutation is
rejected with `revision_conflict` before touching the DB; the revision only
increments after a confirmed successful mutation. Omitted → no check.
