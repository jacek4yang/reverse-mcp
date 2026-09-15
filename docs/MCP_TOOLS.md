# MCP Tools Reference

Status: accurate as of commit `d1d1937` (2026-09-15), branch feat/issue17-versioned-backends.

17 tools. Every list/search/graph result is bounded; oversized responses spill
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
action=set`) accepts `expected_revision`. If present and stale, the mutation is
rejected with `revision_conflict` before touching the DB; the revision only
increments after a confirmed successful mutation. Omitted → no check.
