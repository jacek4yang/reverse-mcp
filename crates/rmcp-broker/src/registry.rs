//! Tool registry: 33 agent-facing tools with JSON schemas and dispatch.
//! Single source of truth for list_tools and call_tool.

use std::sync::Arc;

use serde_json::{Value, json};

use rmcp::model::{Tool, object};

use crate::Broker;
use crate::tools;

struct ToolDef {
    name: &'static str,
    description: &'static str,
    schema: Value,
}

fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "ida_capabilities",
            description: "Report server/backend capabilities and limits.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string", "description": "db handle (db1, ...); omit when exactly one DB is open"}}}),
        },
        ToolDef {
            name: "ida_db",
            description: "Manage databases: action=open (path), info, save, close, list. Returns a short db handle.",
            schema: json!({"type": "object", "properties": {"action": {"type": "string", "enum": ["open","info","save","close","list"]}, "path": {"type": "string"}, "db": {"type": "string"}}, "required": ["action"]}),
        },
        ToolDef {
            name: "ida_functions",
            description: "List functions (paginated): name, start/end address, size.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer", "maximum": 1000}}}),
        },
        ToolDef {
            name: "ida_inspect",
            description: "Everything known about one address: function, comment, bytes.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "ea": {"type": "string", "description": "address, hex like 0x401000 or decimal"}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_decompile",
            description: "Decompile the function containing ea; returns pseudocode.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "ea": {"type": "string"}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_disassemble",
            description: "Disassemble from ea (bounded by end or max_insns).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "ea": {"type": "string"}, "end": {"type": "string"}, "max_insns": {"type": "integer", "maximum": 5000}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_xrefs",
            description: "Cross references: direction=to (default) or from.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "ea": {"type": "string"}, "direction": {"type": "string", "enum": ["to", "from"]}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_graph",
            description: "Graph around the function at ea. kind=calls (function-wide call discovery, multi-level) or kind=cfg (basic-block flow). Bounded by depth/max_nodes/max_edges.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "ea": {"type": "string"}, "kind": {"type": "string", "enum": ["calls", "cfg"]}, "depth": {"type": "integer", "maximum": 5}, "max_nodes": {"type": "integer"}, "max_edges": {"type": "integer"}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_search",
            description: "Search: kind=text (needle in strings) or kind=immediate (value).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "kind": {"type": "string", "enum": ["text", "immediate"]}, "text": {"type": "string"}, "value": {"type": "integer"}, "limit": {"type": "integer"}}}),
        },
        ToolDef {
            name: "ida_bytes",
            description: "Read bytes (action=get, size<=4096) or patch (action=patch, hex string).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["get", "patch"]}, "ea": {"type": "string"}, "size": {"type": "integer"}, "hex": {"type": "string"}, "expected_revision": {"type": "integer"}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_types",
            description: "Local type view: action=list/get by name, or set with decl+ea.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["list", "get", "set"]}, "name": {"type": "string"}, "decl": {"type": "string"}, "ea": {"type": "string"}, "expected_revision": {"type": "integer"}}}),
        },
        ToolDef {
            name: "ida_edit",
            description: "Mutate at ea: rename (new name) and/or comment (optionally repeatable). Bumps revision.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "ea": {"type": "string"}, "rename": {"type": "string"}, "comment": {"type": "string"}, "repeatable": {"type": "boolean"}, "expected_revision": {"type": "integer"}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_analysis",
            description: "Wait for auto-analysis to finish; returns function count.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}}}),
        },
        ToolDef {
            name: "ida_batch",
            description: "Run up to 20 read-only operations in one round trip; per-op results.",
            schema: json!({"type": "object", "properties": {"operations": {"type": "array", "items": {"type": "object", "properties": {"tool": {"type": "string"}, "args": {"type": "object"}}, "required": ["tool"]}}}}),
        },
        ToolDef {
            name: "ida_result",
            description: "Access spilled large results: action=read/metadata/find/release on r-handles.",
            schema: json!({"type": "object", "properties": {"action": {"type": "string", "enum": ["read", "metadata", "find", "release"]}, "handle": {"type": "string"}, "text": {"type": "string"}}}),
        },
        ToolDef {
            name: "ida_segments",
            description: "List segments: name, start/end address, permissions.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}}}),
        },
        ToolDef {
            name: "ida_installations",
            description: "List discovered IDA installations: version, source, decompilers, backend readiness. Use with ida_db open ida_version to pick one.",
            schema: json!({"type": "object"}),
        },
        ToolDef {
            name: "ida_mutation",
            description: "Transaction-like mutation layer: action=plan (validate+preview ops without changing anything, whole-plan revision guard), apply (sequential execution with per-op results and partial-outcome reporting), audit (bounded trail of applied mutations with old/new state), snapshot (IDB restore point), rollback (undo to last snapshot). Operations: rename, comment, patch_bytes (hex), func.create, func.delete, set_type with {ea, kind, ...}.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["plan", "apply", "audit", "snapshot", "rollback"]}, "operations": {"type": "array", "items": {"type": "object", "properties": {"ea": {"type": "string"}, "kind": {"type": "string", "enum": ["rename", "comment", "patch_bytes", "func.create", "func.delete", "set_type"]}, "name": {"type": "string"}, "comment": {"type": "string"}, "repeatable": {"type": "boolean"}, "hex": {"type": "string"}, "end": {"type": "string"}, "decl": {"type": "string"}}, "required": ["ea", "kind"]}}, "expected_revision": {"type": "integer"}, "limit": {"type": "integer"}}, "required": ["action"]}),
        },
        ToolDef {
            name: "ida_analyze",
            description: "Composite analysis workflows (#8): one request replaces many atomic calls. workflow=function_context (decompile+prototype+callers/callees+xrefs+strings+constants+imports), call_neighborhood (bounded BFS through call edges, noise-filtered), reference_context (target->xrefs->functions->callers), import_usage (import->sites->callers), subsystem_context (bounded multi-function from roots), trace_call_path (find path between two functions). Budgets: depth, max_functions, detail=summary|normal|full. Unchanged repeats served from a revision-keyed cache (cached=true).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "workflow": {"type": "string", "enum": ["function_context", "call_neighborhood", "reference_context", "import_usage", "subsystem_context", "trace_call_path"]}, "ea": {"type": "string"}, "target_ea": {"type": "string"}, "name": {"type": "string"}, "roots": {"type": "array", "items": {"type": "string"}}, "depth": {"type": "integer"}, "max_functions": {"type": "integer", "maximum": 50}, "detail": {"type": "string", "enum": ["summary", "normal", "full"]}, "include_noise": {"type": "boolean"}}, "required": ["workflow"]}),
        },
        ToolDef {
            name: "ida_evidence",
            description: "Structured evidence search over a database-wide analysis index (#14). action=query (default) runs a predicate tree against function facts: {\"all\":[{\"import\":\"VirtualAlloc\"},{\"has_indirect_calls\":{\"min\":1}}]}, {\"string_contains\":\"...\"}, {\"name_contains\":\"...\"}, {\"constant\":123}, {\"callee_matches\":{...}}, {\"caller_matches\":{...}}, {\"reachable_from\":{\"root_ea\":\"0x...\",\"levels\":2}}, {\"not\":{...}}, {\"any\":[...]}. Every hit lists concrete matched evidence; the score is evidence-derived. action=build rebuilds+persists; action=status shows index summary.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["query", "build", "status"]}, "query": {"type": "object", "properties": {"all": {"type": "array", "items": {"type": "object"}}}, "limit": {"type": "integer", "maximum": 1000}}, "limit": {"type": "integer", "maximum": 1000}}}),
        },
        ToolDef {
            name: "ida_deep",
            description: "Deep analysis (#10): recursive decompilation with type propagation and bounded data-flow. task=deep_function: walks direct callees first (post-order), applies recovered prototypes, re-decompiles improved callers and reports a convergence trace (iteration N: k type changes ... 0 -> converged). task=trace_dataflow: source->sink evidence for a target function across callers/callees with concrete call-site EAs; confidence=confirmed for direct calls, heuristic for indirect. task=retype: apply a C prototype declaration (mutation, invalidates caches). Budgets: depth, max_functions, max_iterations, max_calls. Repeats on an unchanged DB are served from the revision-keyed cache (cached=true).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "task": {"type": "string", "enum": ["deep_function", "trace_dataflow", "retype"]}, "target": {"type": "string", "description": "function ea or name (deep_function/trace_dataflow)"}, "ea": {"type": "string", "description": "function ea (retype)"}, "decl": {"type": "string", "description": "C prototype declaration (retype)"}, "direction": {"type": "string", "enum": ["forward", "backward", "both"]}, "depth": {"type": "integer"}, "max_functions": {"type": "integer"}, "max_iterations": {"type": "integer"}, "max_calls": {"type": "integer"}}, "required": ["task"]}),
        },
        ToolDef {
            name: "ida_type_recovery",
            description: "Type recovery (#11): infer struct shapes from member-access evidence and discover vtable candidates. task=evidence: member-access observations (offset, width, read/write, EA) of one decompiled function. task=propose: aggregate observations across several functions into field proposals with per-field evidence (read/write counts, candidate width/type, confidence 0..1) and a shape match against existing local types; PREVIEW ONLY. task=vtable: scan an EA as a vtable and map slots to candidate methods. task=create_struct: APPLY a reviewed struct definition (name + fields 'offset:size:name:type_decl') as an explicit mutation. Proposals never apply silently; low-confidence proposals are marked as such.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "task": {"type": "string", "enum": ["evidence", "propose", "vtable", "create_struct"]}, "ea": {"type": "string"}, "functions": {"type": "array", "items": {"type": "string"}, "description": "function EAs to aggregate (propose)"}, "name": {"type": "string", "description": "struct name (create_struct)"}, "fields": {"type": "array", "items": {"type": "string"}, "description": "'offset:size:name:type_decl' quadruples (create_struct)"}, "limit": {"type": "integer"}, "max_entries": {"type": "integer"}}, "required": ["task"]}),
        },
        ToolDef {
            name: "ida_intel",
            description: "Binary intelligence (#12): crypto constants, API-hash resolvers, recovered strings. task=crypto_scan: scan all segments for known crypto constants (AES S-box, SHA/MD5 IVs, SHA-256 K, CRC-32 table, Blowfish P-array, TEA delta...); findings ranked by confidence with containing function + callers from the analysis index. task=resolve_api_hashes: detect likely hash-resolver functions and verify candidate algorithms (ror13-add, ror13-add-wide, ror15-add, rol7-xor, crc32) against the DB's own import-name corpus; single-hash resolvers are flagged low-confidence. task=recover_strings: stack/array string recovery from immediate-store analysis of one function; the IDB is never patched. Results are ranked, bounded and searchable.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "task": {"type": "string", "enum": ["crypto_scan", "resolve_api_hashes", "recover_strings"]}, "target": {"type": "string", "description": "function EA (recover_strings)"}, "max_findings": {"type": "integer"}, "max_strings": {"type": "integer"}}, "required": ["task"]}),
        },
        ToolDef {
            name: "ida_deobfuscate",
            description: "Deobfuscation analysis (#9): analysis-only pass engine over one function. Detects control-flow flattening (CFG dispatcher shape), opaque/redundant branches (constant/self comparisons in ctree), indirect transfers (jmp/call reg), junk no-ops (mov reg,reg / add 0), and return-as-jump tail transfers. Every pass reports name/version, confidence, evidence, proposed changes and failure reason; max_passes bounds the run. SAFETY: analysis-only - no IDB metadata repairs, no byte patches; transformations are proposals an agent can apply via explicit ida_mutation actions afterward.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "target": {"type": "string", "description": "function EA"}, "max_passes": {"type": "integer", "maximum": 16}}, "required": ["target"]}),
        },
        ToolDef {
            name: "ida_sig",
            description: "Function signatures & cross-IDB comparison (#13). task=export: build a multi-family fingerprint index (imports, strings, constants, call shape, size - open JSON format '.rsig.json') and persist it next to the DB; returns the path. task=identify: rank reference-index candidates for one function with per-family evidence (score 0..1 explained per family); strict matches are safe for rename proposals, relaxed are hints only. task=map: cross-IDB function mapping between two exported sig indexes producing TRANSFER PROPOSALS with conflict detection (target meaningful names require explicit approval) - nothing is applied automatically.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "task": {"type": "string", "enum": ["export", "identify", "map"]}, "target": {"type": "string", "description": "function EA (identify)"}, "reference": {"type": "object", "description": "reference sig index JSON (identify)"}, "from": {"type": "object", "description": "from sig index (map)"}, "to": {"type": "object", "description": "to sig index (map)"}, "max_candidates": {"type": "integer"}, "max_transfers": {"type": "integer"}}, "required": ["task"]}),
        },
        ToolDef {
            name: "ida_health",
            description: "Self-diagnosis report that works even with no IDA install found: discovery results, runtime DLL presence, worker probe, idalib feature, and a remediation hint.",
            schema: json!({"type": "object"}),
        },
        ToolDef {
            name: "ida_metadata",
            description: "Extended DB metadata: md5/sha256 of the input file, image base, entry points (ordinal/ea/name). TLS callbacks and exception handlers are reported as unsupported when not exposed.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}}}),
        },
        ToolDef {
            name: "ida_imports",
            description: "Imported modules and import entries (ea, name, ordinal); paginated.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "module": {"type": "integer", "description": "module index; omit for all modules"}, "offset": {"type": "integer"}, "limit": {"type": "integer", "maximum": 1000}}}),
        },
        ToolDef {
            name: "ida_fixups",
            description: "Fixup/relocation records (ea, kind, flags, base, sel, off, displacement); paginated.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "offset": {"type": "integer"}, "limit": {"type": "integer", "maximum": 1000}}}),
        },
        ToolDef {
            name: "ida_filemap",
            description: "Map between EA and input-file offset: value + to_ea=false (default) maps EA->offset, to_ea=true maps offset->EA.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "value": {"type": "string", "description": "address or file offset (hex 0x.. or decimal)"}, "to_ea": {"type": "boolean"}}, "required": ["value"]}),
        },
        ToolDef {
            name: "ida_func",
            description: "Function-structure operations: action=tails (chunks incl. tails), create (start[,end]), delete (ea), resize (ea, new_start/new_end), switch_info (jump table at ea), sp_delta. Mutating actions bump the revision and honour expected_revision.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["tails", "create", "delete", "resize", "switch_info", "sp_delta"]}, "ea": {"type": "string"}, "start": {"type": "string"}, "end": {"type": "string"}, "new_start": {"type": "string"}, "new_end": {"type": "string"}, "expected_revision": {"type": "integer"}}, "required": ["action"]}),
        },
        ToolDef {
            name: "ida_hr",
            description: "Hex-Rays structured view: action=cfunc (bounded typed ctree node summaries, lvars with type/width/arg flags, return type), action=microcode (bounded microcode dump at maturity 0-7: blocks with pred/succ/insn counts + rendered instructions with opcode/operand kinds/immediates; revision-keyed cache), or lvar_rename (ea + var_defea + name; bumps revision).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["cfunc", "microcode", "lvar_rename"]}, "ea": {"type": "string"}, "var_defea": {"type": "string"}, "name": {"type": "string"}, "include_ctree": {"type": "boolean"}, "include_lvars": {"type": "boolean"}, "limit": {"type": "integer", "maximum": 50000}, "maturity": {"type": "integer", "maximum": 7}, "max_insns": {"type": "integer", "maximum": 20000}, "expected_revision": {"type": "integer"}}, "required": ["action", "ea"]}),
        },
        ToolDef {
            name: "ida_value",
            description: "Bounded constant/value propagation and indirect-call target proposals (analysis-only): walks the target function plus optional k-hop callees once each (reuses the deep single-decompile cache), merges constant argument evidence per (function, argN) with confidence confirmed/set/heuristic, and probes unresolved indirect call sites against vtable slots. Budget keys: depth (default 1 = intra-procedural only), max_functions, max_calls, timeout_ms; cached per revision.",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "ea": {"type": "string", "description": "target function EA"}, "depth": {"type": "integer", "minimum": 1, "maximum": 16}, "max_functions": {"type": "integer", "maximum": 4096}, "max_calls": {"type": "integer", "maximum": 100000}, "max_iterations": {"type": "integer", "maximum": 100000}, "timeout_ms": {"type": "integer", "maximum": 1800000}, "resume_from": {"type": "string"}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_insn",
            description: "Instruction-level metadata: action=features (canon CF_* feature bits + mnemonic at ea) or demangle (name -> demangled form).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["features", "demangle"]}, "ea": {"type": "string"}, "name": {"type": "string"}}, "required": ["action"]}),
        },
    ]
}

/// Public read-only view of the registry for docs-sync tests and tooling.
pub fn tool_names() -> Vec<&'static str> {
    defs().into_iter().map(|d| d.name).collect()
}

pub fn tool_list() -> Vec<Tool> {
    defs()
        .into_iter()
        .map(|d| Tool::new(d.name, d.description, Arc::new(object(d.schema))))
        .collect()
}

pub async fn call(broker: &Broker, name: &str, args: Value) -> Result<Value, rmcp::ErrorData> {
    match name {
        "ida_capabilities" => tools::tool_capabilities(broker, args).await,
        "ida_db" => tools::tool_db(broker, args).await,
        "ida_functions" => tools::tool_functions(broker, args).await,
        "ida_inspect" => tools::tool_inspect(broker, args).await,
        "ida_decompile" => tools::tool_decompile(broker, args).await,
        "ida_disassemble" => tools::tool_disassemble(broker, args).await,
        "ida_xrefs" => tools::tool_xrefs(broker, args).await,
        "ida_graph" => tools::tool_graph(broker, args).await,
        "ida_search" => tools::tool_search(broker, args).await,
        "ida_bytes" => tools::tool_bytes(broker, args).await,
        "ida_types" => tools::tool_types(broker, args).await,
        "ida_edit" => tools::tool_edit(broker, args).await,
        "ida_analysis" => tools::tool_analysis(broker, args).await,
        "ida_batch" => tools::tool_batch(broker, args).await,
        "ida_result" => tools::tool_result(broker, args).await,
        "ida_segments" => tools::tool_segments(broker, args).await,
        "ida_installations" => tools::tool_installations(broker, args).await,
        "ida_health" => tools::tool_health(broker, args).await,
        "ida_evidence" => tools::tool_evidence(broker, args).await,
        "ida_analyze" => tools::tool_analyze(broker, args).await,
        "ida_deep" => tools::tool_deep(broker, args).await,
        "ida_type_recovery" => tools::tool_type_recovery(broker, args).await,
        "ida_intel" => tools::tool_intel(broker, args).await,
        "ida_deobfuscate" => tools::tool_deobfuscate(broker, args).await,
        "ida_sig" => tools::tool_sig(broker, args).await,
        "ida_metadata" => tools::tool_metadata(broker, args).await,
        "ida_imports" => tools::tool_imports(broker, args).await,
        "ida_fixups" => tools::tool_fixups(broker, args).await,
        "ida_filemap" => tools::tool_filemap(broker, args).await,
        "ida_func" => tools::tool_func(broker, args).await,
        "ida_hr" => tools::tool_hr(broker, args).await,
        "ida_value" => tools::tool_value(broker, args).await,
        "ida_insn" => tools::tool_insn(broker, args).await,
        "ida_mutation" => tools::tool_mutation(broker, args).await,
        other => Err(rmcp::ErrorData::invalid_params(
            format!("unknown tool '{other}'"),
            None,
        )),
    }
}
