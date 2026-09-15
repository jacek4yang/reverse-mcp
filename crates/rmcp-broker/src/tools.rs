//! Broker tool implementations: each MCP tool validates args, resolves the
//! db handle, routes to the worker, and bounds the output through the
//! result store. Kept separate from lib.rs so the MCP surface stays declarative.

use serde_json::{Value, json};

use rmcp::ErrorData as McpError;

use crate::{Broker, arg_str, arg_u64, bound_output, resolve_db};

fn err_from(e: rmcp_core::error::Error) -> McpError {
    McpError::invalid_params(e.to_string(), None).borrow_code(e.code())
}

trait BorrowCode {
    fn borrow_code(self, code: &str) -> Self;
}

impl BorrowCode for McpError {
    fn borrow_code(self, code: &str) -> Self {
        // rmcp ErrorData has a code number + message; we embed the stable
        // string code at the front of the message for machine readability.
        let msg = self.message;
        McpError::invalid_params(format!("[{code}] {msg}"), None)
    }
}

/// ida_capabilities — what this server can do (static + backend-driven).
pub async fn tool_capabilities(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let caps = s.call("capabilities", json!({})).await.map_err(err_from)?;
    let mut out = caps;
    out["db"] = json!(db);
    Ok(out)
}

/// ida_db — open/close/save/info/list.
pub async fn tool_db(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let action = arg_str(&args, "action").unwrap_or("info");
    match action {
        "open" => {
            let path = arg_str(&args, "path")
                .ok_or_else(|| mcp_code("invalid_args", "open requires 'path'"))?;
            let mut pool = broker.pool.lock().await;
            // Real backend by default; "mock" stays available for tests and
            // IDA-less smoke runs. `ida_version` supports "9.2", "latest"
            // or ranges like ">=9.2,<9.4"; empty = auto-select.
            let backend_kind = arg_str(&args, "backend").unwrap_or("auto");
            let ida_version = arg_str(&args, "ida_version").unwrap_or("");
            let handle = pool
                .spawn_for(path, broker.config.max_workers, backend_kind, ida_version)
                .await
                .map_err(err_from)?;
            broker
                .open_dbs
                .lock()
                .await
                .push((handle.clone(), path.to_string()));
            let session = pool.session(&handle).await;
            let info = match session {
                Some(s) => {
                    let s = s.lock().await;
                    s.call("db.info", json!({})).await.unwrap_or(json!({}))
                }
                None => json!({}),
            };
            Ok(json!({"db": handle, "path": path, "info": bound_output(broker, "ida_db", info)}))
        }
        "info" => {
            let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
            let s = session.lock().await;
            let info = s.call("db.info", json!({})).await.map_err(err_from)?;
            Ok(json!({"db": db, "info": bound_output(broker, "ida_db", info)}))
        }
        "save" => {
            let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
            let s = session.lock().await;
            s.call("db.save", json!({})).await.map_err(err_from)?;
            Ok(json!({"db": db, "saved": true}))
        }
        "close" => {
            let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
            {
                let s = session.lock().await;
                s.call("db.save", json!({})).await.map_err(err_from)?;
                s.call("db.close", json!({})).await.map_err(err_from)?;
                s.call("shutdown", json!({})).await.map_err(err_from)?;
            }
            broker.pool.lock().await.sessions.retain(|(h, _)| h != &db);
            broker.open_dbs.lock().await.retain(|(h, _)| h != &db);
            Ok(json!({"db": db, "closed": true}))
        }
        "list" => {
            let list = broker.pool.lock().await.list().await;
            Ok(json!({"dbs": list}))
        }
        other => Err(mcp_code(
            "invalid_args",
            &format!("unknown action '{other}'"),
        )),
    }
}

/// ida_functions — paginated function list.
pub async fn tool_functions(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let out = s
        .call(
            "functions",
            json!({
                "offset": arg_u64(&args, "offset", 0),
                "limit": arg_u64(&args, "limit", 100).min(1000),
            }),
        )
        .await
        .map_err(err_from)?;
    Ok(json!({"db": db, "functions": bound_output(broker, "ida_functions", out)}))
}

/// ida_inspect — everything known about one address.
pub async fn tool_inspect(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "inspect requires 'ea' (hex or decimal)"))?;
    let s = session.lock().await;
    let f = s
        .call("function_at", json!({"ea": ea}))
        .await
        .map_err(err_from)?;
    let comment = s
        .call("get_comment", json!({"ea": ea, "repeatable": false}))
        .await
        .map_err(err_from)?;
    let bytes = s
        .call("get_bytes", json!({"ea": ea, "size": 16}))
        .await
        .map_err(err_from)?;
    Ok(
        json!({"db": db, "ea": format!("{ea:#x}"), "function": f, "comment": comment, "bytes": bytes}),
    )
}

/// ida_disassemble.
pub async fn tool_disassemble(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "disassemble requires 'ea'"))?;
    let s = session.lock().await;
    let out = s
        .call(
            "disassemble",
            json!({
                "ea": ea,
                "end": args.get("end"),
                "max_insns": arg_u64(&args, "max_insns", 200).min(5000),
            }),
        )
        .await
        .map_err(err_from)?;
    Ok(json!({"db": db, "insns": bound_output(broker, "ida_disassemble", out)}))
}

/// ida_decompile.
pub async fn tool_decompile(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "decompile requires 'ea'"))?;
    let s = session.lock().await;
    let out = s
        .call("decompile", json!({"ea": ea}))
        .await
        .map_err(err_from)?;
    Ok(json!({"db": db, "pseudocode": bound_output(broker, "ida_decompile", out)}))
}

/// ida_xrefs.
pub async fn tool_xrefs(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "xrefs requires 'ea'"))?;
    let dir = arg_str(&args, "direction").unwrap_or("to");
    let method = match dir {
        "from" => "xrefs_from",
        _ => "xrefs_to",
    };
    let s = session.lock().await;
    let out = s.call(method, json!({"ea": ea})).await.map_err(err_from)?;
    Ok(json!({"db": db, "direction": dir, "xrefs": bound_output(broker, "ida_xrefs", out)}))
}

/// ida_graph — call graph or CFG around a function.
pub async fn tool_graph(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "graph requires 'ea'"))?;
    let kind = match arg_str(&args, "kind").unwrap_or("calls") {
        "calls" => "calls",
        "cfg" => "cfg",
        other => {
            return Err(mcp_code(
                "invalid_args",
                &format!("unknown graph kind '{other}' (calls|cfg)"),
            ));
        }
    };
    let s = session.lock().await;
    let out = s
        .call(
            "graph",
            json!({
                "ea": ea,
                "kind": kind,
                "depth": arg_u64(&args, "depth", 1).min(5),
                "max_nodes": arg_u64(&args, "max_nodes", 200).min(5000),
                "max_edges": arg_u64(&args, "max_edges", 400).min(10000),
            }),
        )
        .await
        .map_err(err_from)?;
    Ok(json!({"db": db, "graph": bound_output(broker, "ida_graph", out)}))
}

/// ida_search.
pub async fn tool_search(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let out = match arg_str(&args, "kind").unwrap_or("text") {
        "immediate" => {
            let v = args
                .get("value")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| mcp_code("invalid_args", "immediate search requires 'value'"))?;
            s.call(
                "search_immediate",
                json!({"value": v, "limit": arg_u64(&args, "limit", 50)}),
            )
            .await
            .map_err(err_from)?
        }
        _ => {
            let needle = arg_str(&args, "text")
                .ok_or_else(|| mcp_code("invalid_args", "text search requires 'text'"))?;
            s.call(
                "search_text",
                json!({"needle": needle, "limit": arg_u64(&args, "limit", 50)}),
            )
            .await
            .map_err(err_from)?
        }
    };
    Ok(json!({"db": db, "hits": bound_output(broker, "ida_search", out)}))
}

/// ida_bytes — get or patch.
pub async fn tool_bytes(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "bytes requires 'ea'"))?;
    let s = session.lock().await;
    match arg_str(&args, "action").unwrap_or("get") {
        "patch" => {
            let hex = arg_str(&args, "hex")
                .ok_or_else(|| mcp_code("invalid_args", "patch requires 'hex'"))?;
            let out = s
                .call("patch_bytes", json!({"ea": ea, "hex": hex, "expected_revision": args.get("expected_revision")}))
                .await
                .map_err(err_from)?;
            Ok(json!({"db": db, "outcome": out}))
        }
        _ => {
            let out = s
                .call(
                    "get_bytes",
                    json!({"ea": ea, "size": arg_u64(&args, "size", 16).min(4096)}),
                )
                .await
                .map_err(err_from)?;
            Ok(json!({"db": db, "bytes": out}))
        }
    }
}

/// ida_types.
pub async fn tool_types(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    match (
        arg_str(&args, "action").unwrap_or("get"),
        arg_str(&args, "name"),
        arg_str(&args, "decl"),
        args.get("ea"),
    ) {
        ("set", _, Some(decl), Some(ea_val)) => {
            let ea = parse_ea(ea_val).ok_or_else(|| mcp_code("invalid_args", "bad ea"))?;
            let out = s
                .call("set_type", json!({"ea": ea, "decl": decl, "expected_revision": args.get("expected_revision")}))
                .await
                .map_err(err_from)?;
            Ok(json!({"db": db, "outcome": out}))
        }
        ("set", _, _, _) => Err(mcp_code("invalid_args", "set requires 'decl' and 'ea'")),
        ("list", _, _, _) | ("get", _, _, _) => {
            let out = s
                .call("types", json!({"name": arg_str(&args, "name")}))
                .await
                .map_err(err_from)?;
            Ok(json!({"db": db, "types": bound_output(broker, "ida_types", out)}))
        }
        (other, _, _, _) => Err(mcp_code(
            "invalid_args",
            &format!("unknown action '{other}'"),
        )),
    }
}

/// ida_edit — rename / comment.
pub async fn tool_edit(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "edit requires 'ea'"))?;
    let s = session.lock().await;
    if let Some(name) = arg_str(&args, "rename") {
        let out = s
            .call(
                "rename",
                json!({"ea": ea, "name": name, "expected_revision": args.get("expected_revision")}),
            )
            .await
            .map_err(err_from)?;
        return Ok(json!({"db": db, "outcome": out}));
    }
    if let Some(comment) = arg_str(&args, "comment") {
        let repeatable = args
            .get("repeatable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let out = s
            .call("set_comment", json!({"ea": ea, "comment": comment, "repeatable": repeatable, "expected_revision": args.get("expected_revision")}))
            .await
            .map_err(err_from)?;
        return Ok(json!({"db": db, "outcome": out}));
    }
    Err(mcp_code(
        "invalid_args",
        "edit requires 'rename' or 'comment'",
    ))
}

/// ida_analysis — wait for analysis.
pub async fn tool_analysis(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let out = s.call("analyze_wait", json!({})).await.map_err(err_from)?;
    Ok(json!({"db": db, "analysis": out}))
}

/// ida_batch — run multiple operations; per-op results, capped count.
pub async fn tool_batch(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let ops = args
        .get("operations")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if ops.len() > 20 {
        return Err(mcp_code("invalid_args", "batch limited to 20 operations"));
    }
    let mut results = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        let tool = op.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        let sub_args = op.get("args").cloned().unwrap_or(json!({}));
        let r = run_named(broker, tool, sub_args).await;
        results.push(json!({
            "index": i,
            "tool": tool,
            "result": match r {
                Ok(v) => v,
                Err(e) => json!({"error": {"code": e.code, "message": e.message}}),
            },
        }));
    }
    Ok(json!({"results": results}))
}

/// ida_result — read/find/metadata/release spilled results.
pub async fn tool_result(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let action = arg_str(&args, "action").unwrap_or("read");
    match action {
        "read" => {
            let handle = arg_str(&args, "handle")
                .ok_or_else(|| mcp_code("invalid_args", "read requires 'handle'"))?;
            broker
                .store
                .get(handle)
                .map_err(|e| mcp_code(e.code(), &e.to_string()))
        }
        "metadata" => {
            let handle = arg_str(&args, "handle")
                .ok_or_else(|| mcp_code("invalid_args", "metadata requires 'handle'"))?;
            broker
                .store
                .metadata(handle)
                .map(|m| serde_json::to_value(m).unwrap_or(json!({})))
                .map_err(|e| mcp_code(e.code(), &e.to_string()))
        }
        "find" => {
            let needle = arg_str(&args, "text")
                .ok_or_else(|| mcp_code("invalid_args", "find requires 'text'"))?;
            Ok(json!({"handles": broker.store.find(needle)}))
        }
        "release" => {
            let handle = arg_str(&args, "handle")
                .ok_or_else(|| mcp_code("invalid_args", "release requires 'handle'"))?;
            broker
                .store
                .release(handle)
                .map(|_| json!({"released": handle}))
                .map_err(|e| mcp_code(e.code(), &e.to_string()))
        }
        other => Err(mcp_code(
            "invalid_args",
            &format!("unknown action '{other}'"),
        )),
    }
}

/// ida_segments handled inside functions tool? No — own tool slice via inspect.
pub async fn tool_segments(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let out = s.call("segments", json!({})).await.map_err(err_from)?;
    Ok(json!({"db": db, "segments": out}))
}

/// ida_metadata — extended DB metadata: input hashes, image base, entry
/// points (issue #19 `db.metadata`). TLS callbacks / exception handlers are
/// reported as unsupported when the backend does not expose them.
pub async fn tool_metadata(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let out = s.call("db.metadata", json!({})).await.map_err(err_from)?;
    Ok(json!({"db": db, "metadata": bound_output(broker, "ida_metadata", out)}))
}

/// ida_imports — imported modules and entries (issue #19 `imports.list`).
pub async fn tool_imports(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let out = s
        .call(
            "imports.list",
            json!({
                "module": args.get("module"),
                "offset": arg_u64(&args, "offset", 0),
                "limit": arg_u64(&args, "limit", 100).min(1000),
            }),
        )
        .await
        .map_err(err_from)?;
    Ok(json!({"db": db, "imports": bound_output(broker, "ida_imports", out)}))
}

/// ida_fixups — fixup/relocation records (issue #19 `fixups.list`).
pub async fn tool_fixups(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let out = s
        .call(
            "fixups.list",
            json!({
                "offset": arg_u64(&args, "offset", 0),
                "limit": arg_u64(&args, "limit", 100).min(1000),
            }),
        )
        .await
        .map_err(err_from)?;
    Ok(json!({"db": db, "fixups": bound_output(broker, "ida_fixups", out)}))
}

/// ida_filemap — EA <-> input-file offset mapping (issue #19 `file.map`).
pub async fn tool_filemap(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let value = args.get("value").and_then(parse_ea).ok_or_else(|| {
        mcp_code(
            "invalid_args",
            "filemap requires 'value' (ea or file offset)",
        )
    })?;
    let to_ea = args.get("to_ea").and_then(|v| v.as_bool()).unwrap_or(false);
    let s = session.lock().await;
    let out = s
        .call("file.map", json!({"value": value, "to_ea": to_ea}))
        .await
        .map_err(err_from)?;
    Ok(json!({"db": db, "map": out}))
}

/// ida_func — function-structure operations: tails (chunks), create,
/// delete, resize, switch info, sp delta (issue #19 function module).
/// Mutating actions bump the revision and honour expected_revision.
pub async fn tool_func(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let action = arg_str(&args, "action").unwrap_or("tails");
    let s = session.lock().await;
    let out = match action {
        "tails" => {
            let ea = args
                .get("ea")
                .and_then(parse_ea)
                .ok_or_else(|| mcp_code("invalid_args", "tails requires 'ea'"))?;
            s.call("func.tails", json!({"ea": ea}))
                .await
                .map_err(err_from)?
        }
        "create" => {
            let start = args
                .get("start")
                .and_then(parse_ea)
                .ok_or_else(|| mcp_code("invalid_args", "create requires 'start'"))?;
            s.call(
                "func.create",
                json!({"start": start, "end": args.get("end"), "expected_revision": args.get("expected_revision")}),
            )
            .await
            .map_err(err_from)?
        }
        "delete" => {
            let ea = args
                .get("ea")
                .and_then(parse_ea)
                .ok_or_else(|| mcp_code("invalid_args", "delete requires 'ea'"))?;
            s.call(
                "func.delete",
                json!({"ea": ea, "expected_revision": args.get("expected_revision")}),
            )
            .await
            .map_err(err_from)?
        }
        "resize" => {
            let ea = args
                .get("ea")
                .and_then(parse_ea)
                .ok_or_else(|| mcp_code("invalid_args", "resize requires 'ea'"))?;
            s.call(
                "func.resize",
                json!({"ea": ea, "new_start": args.get("new_start"), "new_end": args.get("new_end"), "expected_revision": args.get("expected_revision")}),
            )
            .await
            .map_err(err_from)?
        }
        "switch_info" => {
            let ea = args
                .get("ea")
                .and_then(parse_ea)
                .ok_or_else(|| mcp_code("invalid_args", "switch_info requires 'ea'"))?;
            s.call("func.switch_info", json!({"ea": ea}))
                .await
                .map_err(err_from)?
        }
        "sp_delta" => {
            let ea = args
                .get("ea")
                .and_then(parse_ea)
                .ok_or_else(|| mcp_code("invalid_args", "sp_delta requires 'ea'"))?;
            s.call("func.sp_delta", json!({"ea": ea}))
                .await
                .map_err(err_from)?
        }
        other => {
            return Err(mcp_code(
                "invalid_args",
                &format!(
                    "unknown func action '{other}' (tails|create|delete|resize|switch_info|sp_delta)"
                ),
            ));
        }
    };
    Ok(json!({"db": db, "action": action, "result": out}))
}

/// ida_hr — Hex-Rays ctree/lvar summaries and lvar rename
/// (issue #19 `hr.cfunc` / `hr.lvar_rename`), bounded by `limit`.
pub async fn tool_hr(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "hr requires 'ea'"))?;
    let s = session.lock().await;
    match arg_str(&args, "action").unwrap_or("cfunc") {
        "cfunc" => {
            let out = s
                .call(
                    "hr.cfunc",
                    json!({
                        "ea": ea,
                        "include_ctree": args.get("include_ctree").and_then(|v| v.as_bool()).unwrap_or(true),
                        "include_lvars": args.get("include_lvars").and_then(|v| v.as_bool()).unwrap_or(true),
                        "limit": arg_u64(&args, "limit", 2000).min(50000),
                    }),
                )
                .await
                .map_err(err_from)?;
            Ok(json!({"db": db, "cfunc": bound_output(broker, "ida_hr", out)}))
        }
        "lvar_rename" => {
            let var_defea = args
                .get("var_defea")
                .and_then(parse_ea)
                .ok_or_else(|| mcp_code("invalid_args", "lvar_rename requires 'var_defea'"))?;
            let name = arg_str(&args, "name")
                .ok_or_else(|| mcp_code("invalid_args", "lvar_rename requires 'name'"))?;
            let out = s
                .call(
                    "hr.lvar_rename",
                    json!({"ea": ea, "var_defea": var_defea, "name": name, "expected_revision": args.get("expected_revision")}),
                )
                .await
                .map_err(err_from)?;
            Ok(json!({"db": db, "outcome": out}))
        }
        other => Err(mcp_code(
            "invalid_args",
            &format!("unknown hr action '{other}' (cfunc|lvar_rename)"),
        )),
    }
}

/// ida_insn — instruction metadata: canon feature bits + mnemonic
/// (issue #19 `insn.features`), plus name demangling (`names.demangle`).
pub async fn tool_insn(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let s = session.lock().await;
    let out = match arg_str(&args, "action").unwrap_or("features") {
        "features" => {
            let ea = args
                .get("ea")
                .and_then(parse_ea)
                .ok_or_else(|| mcp_code("invalid_args", "features requires 'ea'"))?;
            s.call("insn.features", json!({"ea": ea}))
                .await
                .map_err(err_from)?
        }
        "demangle" => {
            let name = arg_str(&args, "name")
                .ok_or_else(|| mcp_code("invalid_args", "demangle requires 'name'"))?;
            s.call("names.demangle", json!({"name": name}))
                .await
                .map_err(err_from)?
        }
        other => {
            return Err(mcp_code(
                "invalid_args",
                &format!("unknown insn action '{other}' (features|demangle)"),
            ));
        }
    };
    Ok(json!({"db": db, "result": out}))
}

/// ida_installations — all discovered IDA installs with version, source,
/// decompilers and backend readiness, so the agent can pick one explicitly
/// via `ida_db(action=open, ida_version=...)`.
pub async fn tool_installations(broker: &Broker, _args: Value) -> Result<Value, McpError> {
    let explicit = broker.config.ida_dir.clone();
    let installs = tokio::task::spawn_blocking(move || {
        rmcp_core::discovery::discover_all(explicit.as_deref())
    })
    .await
    .map_err(|e| McpError::invalid_params(format!("discovery join: {e}"), None))?;
    Ok(json!({
        "installations": installs,
        "hint": "pass ida_version to ida_db(action=open): exact \"9.2\", \"latest\", or a range \">=9.2,<9.4\"; omit to auto-select (backend-ready highest version)"
    }))
}

/// ida_health — self-report that works even when no IDA install is found.
/// Surfaces discovery results, runtime-DLL presence, worker-exe probe and
/// idalib-feature availability so agents can self-diagnose instead of guessing.
pub async fn tool_health(broker: &Broker, _args: Value) -> Result<Value, McpError> {
    let explicit = broker.config.ida_dir.clone();
    let installs = tokio::task::spawn_blocking(move || {
        rmcp_core::discovery::discover_all(explicit.as_deref())
    })
    .await
    .map_err(|e| McpError::invalid_params(format!("discovery join: {e}"), None))?;

    // Runtime DLL presence per discovered install (the loader resolves these
    // from PATH or the install dir; absence = worker cannot start).
    let runtime_dlls = ["ida.dll", "idalib.dll"];
    let installs: Vec<Value> = installs
        .iter()
        .map(|i| {
            let dll_status: Vec<Value> = runtime_dlls
                .iter()
                .map(|d| {
                    json!({
                        "dll": d,
                        "present": i.root.join(d).exists(),
                    })
                })
                .collect();
            json!({
                "root": i.root,
                "version": i.version,
                "source": i.source.as_str(),
                "backend": i.backend,
                "decompilers": i.decompilers,
                "runtime_dlls": dll_status,
            })
        })
        .collect();
    // Worker probe: can the exe answer the mock probe (protocol alive)?
    let worker_probe_ok = (|| {
        let exe = std::env::current_exe().ok()?;
        let out = std::process::Command::new(exe)
            .args(["worker", "--probe-backend", "mock"])
            .output()
            .ok()?;
        Some(out.status.success())
    })()
    .unwrap_or(false);

    // Configured IDADIR / env visibility for the "why is discovery empty" case.
    let idadir_set = std::env::var_os("IDADIR").is_some();

    let healthy = worker_probe_ok
        && installs.iter().any(|i| {
            i["runtime_dlls"]
                .as_array()
                .map(|a| a.iter().all(|d| d["present"].as_bool().unwrap_or(false)))
                .unwrap_or(false)
        });

    let mut hint = String::new();
    if installs.is_empty() {
        hint.push_str(
            "No IDA installation discovered; set IDADIR or add the IDA install dir to PATH. ",
        );
    } else if !healthy {
        hint.push_str(
            "IDA installations found but the runtime DLLs are incomplete; verify the install. ",
        );
    }
    if !worker_probe_ok {
        hint.push_str("Worker binary probe failed; the reverse-mcp exe may be broken or blocked. ");
    }
    if healthy {
        hint.push_str("All checks passed; open a database with ida_db(action=open).");
    }

    let idalib_feature = {
        // The broker crate itself never links idalib; detect the feature
        // the same way spawning does: probe the worker exe.
        let mut pool = broker.pool.lock().await;
        pool.ensure_worker_exe().is_ok() && pool.worker_has_idalib_feature()
    };

    Ok(json!({
        "healthy": healthy,
        "worker_probe_ok": worker_probe_ok,
        "idalib_feature": idalib_feature,
        "idadir_set": idadir_set,
        "installations": installs,
        "hint": hint,
    }))
}

/// Route a named tool (used by ida_batch).
async fn run_named(broker: &Broker, tool: &str, args: Value) -> Result<Value, McpError> {
    match tool {
        "ida_functions" => tool_functions(broker, args).await,
        "ida_inspect" => tool_inspect(broker, args).await,
        "ida_disassemble" => tool_disassemble(broker, args).await,
        "ida_decompile" => tool_decompile(broker, args).await,
        "ida_xrefs" => tool_xrefs(broker, args).await,
        "ida_search" => tool_search(broker, args).await,
        "ida_bytes" => tool_bytes(broker, args).await,
        "ida_types" => tool_types(broker, args).await,
        "ida_segments" => tool_segments(broker, args).await,
        "ida_metadata" => tool_metadata(broker, args).await,
        "ida_imports" => tool_imports(broker, args).await,
        "ida_fixups" => tool_fixups(broker, args).await,
        "ida_filemap" => tool_filemap(broker, args).await,
        "ida_func" => tool_func(broker, args).await,
        "ida_hr" => tool_hr(broker, args).await,
        "ida_insn" => tool_insn(broker, args).await,
        other => Err(mcp_code(
            "invalid_args",
            &format!("batch cannot run '{other}'"),
        )),
    }
}

fn mcp_code(code: &str, message: &str) -> McpError {
    McpError::invalid_params(format!("[{code}] {message}"), None)
}

/// Parse an EA from hex (0x…) or decimal.
fn parse_ea(v: &Value) -> Option<u64> {
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16).ok();
        }
        return s.parse().ok();
    }
    v.as_u64()
}
