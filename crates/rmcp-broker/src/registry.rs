//! Tool registry: 15 agent-facing tools with JSON schemas and dispatch.
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
            description: "Hex-Rays structured view: action=cfunc (bounded typed ctree node summaries, lvars with type/width/arg flags, return type) or lvar_rename (ea + var_defea + name; bumps revision).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["cfunc", "lvar_rename"]}, "ea": {"type": "string"}, "var_defea": {"type": "string"}, "name": {"type": "string"}, "include_ctree": {"type": "boolean"}, "include_lvars": {"type": "boolean"}, "limit": {"type": "integer", "maximum": 50000}, "expected_revision": {"type": "integer"}}, "required": ["ea"]}),
        },
        ToolDef {
            name: "ida_insn",
            description: "Instruction-level metadata: action=features (canon CF_* feature bits + mnemonic at ea) or demangle (name -> demangled form).",
            schema: json!({"type": "object", "properties": {"db": {"type": "string"}, "action": {"type": "string", "enum": ["features", "demangle"]}, "ea": {"type": "string"}, "name": {"type": "string"}}, "required": ["action"]}),
        },
    ]
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
        "ida_metadata" => tools::tool_metadata(broker, args).await,
        "ida_imports" => tools::tool_imports(broker, args).await,
        "ida_fixups" => tools::tool_fixups(broker, args).await,
        "ida_filemap" => tools::tool_filemap(broker, args).await,
        "ida_func" => tools::tool_func(broker, args).await,
        "ida_hr" => tools::tool_hr(broker, args).await,
        "ida_insn" => tools::tool_insn(broker, args).await,
        other => Err(rmcp::ErrorData::invalid_params(
            format!("unknown tool '{other}'"),
            None,
        )),
    }
}
