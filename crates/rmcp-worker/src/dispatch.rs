//! Method dispatch for worker requests. Each method maps onto one or a few
//! `IdaBackend` calls. Unknown methods yield a stable error code.

use rmcp_core::backend::{GraphParams, IdaBackend};
use rmcp_core::error::Error;
use rmcp_core::protocol::{WorkerRequest, WorkerResponse};
use serde_json::{Value, json};

use crate::deep;
use crate::plan;
use crate::state::WorkerState;
use crate::workflow;

fn need_backend(state: &mut WorkerState) -> rmcp_core::error::Result<&mut (dyn IdaBackend + '_)> {
    match state.backend.as_deref_mut() {
        Some(b) => Ok(b),
        None => Err(Error::Worker("no db open".into())),
    }
}

/// Methods whose success mutates IDB state (directly or via a plan).
const MUTATING_METHODS: &[&str] = &[
    "patch_bytes",
    "set_comment",
    "rename",
    "set_type",
    "func.create",
    "func.delete",
    "func.resize",
    "hr.lvar_rename",
    "deep.retype",
    "plan.apply",
    "snapshot.restore",
    "analyze_wait",
];

pub fn handle(state: &mut WorkerState, req: WorkerRequest) -> WorkerResponse {
    let WorkerRequest { id, method, params } = req;
    let resp = match dispatch(state, &method, params) {
        Ok(v) => WorkerResponse::ok(id, v),
        Err(e) => WorkerResponse::err(id, &e),
    };
    // #8 cache invalidation: any successful mutation bumps the revision and
    // invalidates every cached workflow result.
    if resp.error.is_none() && MUTATING_METHODS.contains(&method.as_str()) {
        state.workflow_cache.invalidate_all();
    }
    resp
}

fn ea_param(params: &Value, key: &str) -> rmcp_core::error::Result<u64> {
    match params.get(key) {
        Some(Value::String(s)) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16)
                    .map_err(|e| Error::Worker(format!("bad ea '{s}': {e}")))
            } else {
                s.parse::<u64>()
                    .map_err(|e| Error::Worker(format!("bad ea '{s}': {e}")))
            }
        }
        Some(v) => v
            .as_u64()
            .ok_or_else(|| Error::Worker(format!("bad ea value for '{key}'"))),
        None => Err(Error::Worker(format!("missing '{key}'"))),
    }
}

/// Optimistic-concurrency guard: when the request carries
/// `expected_revision`, it must match the DB's current revision. Only
/// increment the revision after a confirmed successful mutation.
fn check_revision(params: &Value, backend: &dyn IdaBackend) -> rmcp_core::error::Result<()> {
    match params.get("expected_revision") {
        None | Some(Value::Null) => Ok(()),
        Some(v) => {
            let expected = v
                .as_u64()
                .ok_or_else(|| Error::Worker("expected_revision must be an integer".into()))?;
            let current = backend.revision();
            if expected != current {
                Err(Error::RevisionConflict { expected, current })
            } else {
                Ok(())
            }
        }
    }
}

fn dispatch(
    state: &mut WorkerState,
    method: &str,
    params: Value,
) -> rmcp_core::error::Result<Value> {
    match method {
        "backend.select" => {
            let kind = params
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("mock");
            match kind {
                "mock" => {
                    state.backend = Some(Box::new(rmcp_ida::MockBackend::new()));
                    Ok(json!({"backend": "mock"}))
                }
                "idalib" => {
                    #[cfg(feature = "idalib")]
                    {
                        // idalib requires init + all calls on the main thread;
                        // worker dispatch runs on main, so this is satisfied.
                        idalib::init_library();
                        idalib::enable_console_messages(false);
                        state.backend = Some(Box::new(rmcp_ida::IdaLibBackend::new()));
                        Ok(json!({"backend": "idalib"}))
                    }
                    #[cfg(not(feature = "idalib"))]
                    Err(Error::CapabilityUnavailable {
                        capability: "idalib".into(),
                        reason: "worker not built with the idalib feature".into(),
                    })
                }
                other => Err(Error::Worker(format!(
                    "backend kind '{other}' not built into this worker"
                ))),
            }
        }
        "shutdown" => {
            state.closed = true;
            Ok(json!({"bye": true}))
        }
        "db.open" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing path".into()))?;
            need_backend(state)?.open(path)
        }
        "db.close" => {
            need_backend(state)?.close()?;
            Ok(json!({"closed": true}))
        }
        "db.save" => {
            need_backend(state)?.save()?;
            Ok(json!({"saved": true}))
        }
        "db.info" => need_backend(state)?.db_info(),
        "capabilities" => {
            let caps = need_backend(state)?.capabilities();
            serde_json::to_value(caps).map_err(|e| Error::Ipc(e.to_string()))
        }
        "revision" => Ok(json!({"revision": need_backend(state)?.revision()})),
        "functions" => {
            let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            let fns = need_backend(state)?.functions(offset, limit)?;
            serde_json::to_value(fns).map_err(|e| Error::Ipc(e.to_string()))
        }
        "function_at" => {
            let ea = ea_param(&params, "ea")?;
            let f = need_backend(state)?.function_at(ea)?;
            serde_json::to_value(f).map_err(|e| Error::Ipc(e.to_string()))
        }
        "segments" => {
            let segs = need_backend(state)?.segments()?;
            serde_json::to_value(segs).map_err(|e| Error::Ipc(e.to_string()))
        }
        "strings" => {
            let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            let strings = need_backend(state)?.strings(offset, limit)?;
            serde_json::to_value(strings).map_err(|e| Error::Ipc(e.to_string()))
        }
        "xrefs_to" => {
            let ea = ea_param(&params, "ea")?;
            let x = need_backend(state)?.xrefs_to(ea)?;
            serde_json::to_value(x).map_err(|e| Error::Ipc(e.to_string()))
        }
        "xrefs_from" => {
            let ea = ea_param(&params, "ea")?;
            let x = need_backend(state)?.xrefs_from(ea)?;
            serde_json::to_value(x).map_err(|e| Error::Ipc(e.to_string()))
        }
        "disassemble" => {
            let ea = ea_param(&params, "ea")?;
            let end = match params.get("end") {
                Some(v) if !v.is_null() => Some(ea_param(&params, "end")?),
                _ => None,
            };
            let max = params
                .get("max_insns")
                .and_then(|v| v.as_u64())
                .unwrap_or(200) as usize;
            let out = need_backend(state)?.disassemble(ea, end, max)?;
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "decompile" => {
            let ea = ea_param(&params, "ea")?;
            need_backend(state)?.decompile(ea)
        }
        "graph" => {
            let ea = ea_param(&params, "ea")?;
            let kind = params
                .get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("calls")
                .to_string();
            if !matches!(kind.as_str(), "calls" | "cfg") {
                return Err(Error::Worker(format!(
                    "unknown graph kind '{kind}' (calls|cfg)"
                )));
            }
            let depth = params.get("depth").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
            let max_nodes = params
                .get("max_nodes")
                .and_then(|v| v.as_u64())
                .unwrap_or(200) as usize;
            let max_edges = params
                .get("max_edges")
                .and_then(|v| v.as_u64())
                .unwrap_or(400) as usize;
            let params = GraphParams {
                kind,
                depth,
                max_nodes,
                max_edges,
            };
            need_backend(state)?.graph(ea, &params)
        }
        "search_text" => {
            let needle = params
                .get("needle")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing needle".into()))?;
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let hits = need_backend(state)?.search_text(needle, limit)?;
            serde_json::to_value(hits).map_err(|e| Error::Ipc(e.to_string()))
        }
        "search_immediate" => {
            let value = params.get("value").and_then(|v| v.as_u64()).unwrap_or(0);
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let hits = need_backend(state)?.search_immediate(value, limit)?;
            serde_json::to_value(hits).map_err(|e| Error::Ipc(e.to_string()))
        }
        "get_bytes" => {
            let ea = ea_param(&params, "ea")?;
            let size = params.get("size").and_then(|v| v.as_u64()).unwrap_or(16) as usize;
            need_backend(state)?.get_bytes(ea, size)
        }
        "patch_bytes" => {
            let ea = ea_param(&params, "ea")?;
            check_revision(&params, need_backend(state)?)?;
            let hex = params
                .get("hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing hex".into()))?;
            let out = need_backend(state)?.patch_bytes(ea, hex)?;
            plan::record_audit(&mut state.audit, "patch_bytes", ea, &out);
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "get_comment" => {
            let ea = ea_param(&params, "ea")?;
            let rep = params
                .get("repeatable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            need_backend(state)?.get_comment(ea, rep)
        }
        "set_comment" => {
            let ea = ea_param(&params, "ea")?;
            check_revision(&params, need_backend(state)?)?;
            let comment = params
                .get("comment")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing comment".into()))?;
            let rep = params
                .get("repeatable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let out = need_backend(state)?.set_comment(ea, comment, rep)?;
            plan::record_audit(&mut state.audit, "comment", ea, &out);
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "rename" => {
            let ea = ea_param(&params, "ea")?;
            check_revision(&params, need_backend(state)?)?;
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing name".into()))?;
            let out = need_backend(state)?.rename(ea, name)?;
            plan::record_audit(&mut state.audit, "rename", ea, &out);
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "types" => {
            let name = params.get("name").and_then(|v| v.as_str());
            let out = need_backend(state)?.types(name)?;
            Ok(out)
        }
        "set_type" => {
            let ea = ea_param(&params, "ea")?;
            check_revision(&params, need_backend(state)?)?;
            let decl = params
                .get("decl")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing decl".into()))?;
            let out = need_backend(state)?.set_type(ea, decl)?;
            plan::record_audit(&mut state.audit, "set_type", ea, &out);
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "analyze_wait" => {
            let out = need_backend(state)?.analyze_wait()?;
            Ok(out)
        }
        // ---- #19: metadata / imports / fixups / file map ----
        "db.metadata" => need_backend(state)?.db_metadata(),
        "imports.list" => {
            let module = match params.get("module") {
                Some(v) if !v.is_null() => Some(
                    v.as_u64()
                        .ok_or_else(|| Error::Worker("bad 'module'".into()))?
                        as usize,
                ),
                _ => None,
            };
            let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            need_backend(state)?.imports(module, offset, limit)
        }
        "fixups.list" => {
            let offset = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            need_backend(state)?.fixups(offset, limit)
        }
        "file.map" => {
            let to_ea = params
                .get("to_ea")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let value = if params.get("value").is_some() {
                ea_param(&params, "value")?
            } else {
                ea_param(&params, "ea")?
            };
            need_backend(state)?.file_map(value, to_ea)
        }
        // ---- #19: functions / control flow ----
        "func.tails" => {
            let ea = ea_param(&params, "ea")?;
            need_backend(state)?.func_tails(ea)
        }
        "func.create" => {
            let start = ea_param(&params, "start")?;
            let end = match params.get("end") {
                Some(v) if !v.is_null() => Some(ea_param(&params, "end")?),
                _ => None,
            };
            check_revision(&params, need_backend(state)?)?;
            let out = need_backend(state)?.func_create(start, end)?;
            plan::record_audit(&mut state.audit, "func.create", start, &out);
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "func.delete" => {
            let ea = ea_param(&params, "ea")?;
            check_revision(&params, need_backend(state)?)?;
            let out = need_backend(state)?.func_delete(ea)?;
            plan::record_audit(&mut state.audit, "func.delete", ea, &out);
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "func.resize" => {
            let ea = ea_param(&params, "ea")?;
            let new_start = match params.get("new_start") {
                Some(v) if !v.is_null() => Some(ea_param(&params, "new_start")?),
                _ => None,
            };
            let new_end = match params.get("new_end") {
                Some(v) if !v.is_null() => Some(ea_param(&params, "new_end")?),
                _ => None,
            };
            check_revision(&params, need_backend(state)?)?;
            let out = need_backend(state)?.func_resize(ea, new_start, new_end)?;
            plan::record_audit(&mut state.audit, "func.resize", ea, &out);
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "func.switch_info" => {
            let ea = ea_param(&params, "ea")?;
            need_backend(state)?.func_switch_info(ea)
        }
        "func.sp_delta" => {
            let ea = ea_param(&params, "ea")?;
            need_backend(state)?.func_sp_delta(ea)
        }
        // ---- #19: Hex-Rays ----
        "hr.cfunc" => {
            let ea = ea_param(&params, "ea")?;
            let include_ctree = params
                .get("include_ctree")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let include_lvars = params
                .get("include_lvars")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(2000) as usize;
            need_backend(state)?.hr_cfunc(ea, include_ctree, include_lvars, limit)
        }
        "hr.lvar_rename" => {
            let ea = ea_param(&params, "ea")?;
            let var_defea = ea_param(&params, "var_defea")?;
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing name".into()))?;
            check_revision(&params, need_backend(state)?)?;
            let out = need_backend(state)?.hr_lvar_rename(ea, var_defea, name)?;
            plan::record_audit(&mut state.audit, "hr.lvar_rename", ea, &out);
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        // ---- #19: instructions / names ----
        "insn.features" => {
            let ea = ea_param(&params, "ea")?;
            need_backend(state)?.insn_features(ea)
        }
        "names.demangle" => {
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing name".into()))?;
            need_backend(state)?.demangle_name(name)
        }
        "list_plugins" => need_backend(state)?.list_plugins(),
        "run_plugin" => {
            let plugin = params
                .get("plugin")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing plugin".into()))?;
            let args = params.get("args").and_then(|v| v.as_str());
            let out = need_backend(state)?.run_plugin(plugin, args)?;
            Ok(out)
        }
        // ---- #16: mutation plans / snapshots / audit trail ----
        "plan.mutations" => {
            let ops_json = params
                .get("operations")
                .and_then(|v| v.as_array())
                .ok_or_else(|| Error::Worker("missing 'operations' array".into()))?;
            let ops = plan::parse_operations(ops_json)?;
            // Whole-plan revision guard at plan time: a stale plan is
            // rejected before any preview state is produced.
            let expected = params.get("expected_revision").and_then(|v| v.as_u64());
            plan::check_plan_revision(need_backend(state)?, expected)?;
            plan::plan(need_backend(state)?, &ops)
        }
        "plan.apply" => {
            let ops_json = params
                .get("operations")
                .and_then(|v| v.as_array())
                .ok_or_else(|| Error::Worker("missing 'operations' array".into()))?;
            let ops = plan::parse_operations(ops_json)?;
            // Whole-plan guard BEFORE the first mutation runs.
            let expected = params.get("expected_revision").and_then(|v| v.as_u64());
            plan::check_plan_revision(need_backend(state)?, expected)?;
            let mut audit = std::mem::take(&mut state.audit);
            // Apply runs with the backend borrowed from state; the audit
            // vec was moved out first so the borrows do not overlap.
            let result = plan::apply(need_backend(state)?, &ops, &mut audit);
            // Keep the audit trail even when the plan fails mid-way: the
            // partial outcome is exactly what the agent needs to see.
            state.audit = audit;
            let out = result?;
            Ok(out)
        }
        "mutation.audit" => {
            let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
            Ok(plan::audit_tail(&state.audit, limit))
        }
        "snapshot.create" => {
            // Backend-agnostic entry point: the real backend wraps IDA's
            // create_undo_point; mock records a logical checkpoint.
            need_backend(state)?.snapshot_create()
        }
        "snapshot.restore" => need_backend(state)?.snapshot_restore(),
        // ---- #14: analysis index / evidence search ----
        "index.build" => {
            let (idx, md5) = need_backend(state)?.build_index()?;
            // Persist under the reverse-mcp cache dir; failure to persist is
            // non-fatal (the in-memory index still serves this session).
            let summary = idx.summary();
            let _ = idx.save(&rmcp_core::layout::cache_dir(), &md5);
            state.index = Some((idx, md5));
            Ok(summary)
        }
        "index.query" => {
            let query: rmcp_core::analysis_index::EvidenceQuery =
                serde_json::from_value(params.get("query").cloned().unwrap_or(json!({})))
                    .map_err(|e| Error::Worker(format!("bad query: {e}")))?;
            // Rebuild on demand if not built yet; rebuild again (incremental
            // invalidation) if the DB revision moved since the build.
            let current_rev = need_backend(state)?.revision();
            let stale = state
                .index
                .as_ref()
                .map(|(idx, _)| idx.revision != current_rev)
                .unwrap_or(true);
            if stale {
                let (idx, md5) = need_backend(state)?.build_index()?;
                state.index = Some((idx, md5));
            }
            let (idx, md5) = state.index.as_ref().expect("just built");
            let hits = idx.query(&query);
            Ok(json!({
                "count": hits.len(),
                "md5": md5,
                "hits": hits,
            }))
        }
        "index.status" => match &state.index {
            Some((idx, md5)) => {
                let mut s = idx.summary();
                s["md5"] = json!(md5);
                s["current"] = json!(idx.revision == need_backend(state)?.revision());
                Ok(s)
            }
            None => Ok(json!({"built": false})),
        },
        // ---- #8: composite analysis workflows ----
        "workflow.run" => {
            let req: workflow::WorkflowRequest = serde_json::from_value(
                params
                    .get("workflow_req")
                    .cloned()
                    .unwrap_or_else(|| params.clone()),
            )
            .map_err(|e| Error::Worker(format!("bad workflow request: {e}")))?;
            // Rebuild the index if absent or stale (workflows run off it).
            let current_rev = need_backend(state)?.revision();
            let stale = state
                .index
                .as_ref()
                .map(|(idx, _)| idx.revision != current_rev)
                .unwrap_or(true);
            if stale {
                let (idx, md5) = need_backend(state)?.build_index()?;
                state.index = Some((idx, md5));
            }
            let key = workflow::cache_key(&req, current_rev);
            if let Some(cached) = state.workflow_cache.get(&key) {
                return Ok(json!({
                    "cached": true,
                    "cache_hits": state.workflow_cache.hits,
                    "result": cached,
                }));
            }
            let (idx, _md5) = state.index.as_ref().expect("just built").clone();
            let result = workflow::run(need_backend(state)?, &idx, &req)?;
            state.workflow_cache.put(key, result.clone());
            Ok(json!({
                "cached": false,
                "cache_hits": state.workflow_cache.hits,
                "result": result,
            }))
        }
        // ---- #10: deep analysis (recursive decompile, type propagation,
        // dataflow). Uses the same workflow cache as #8: identical requests
        // on an unchanged revision are served without re-walking, and any
        // mutation invalidates it.
        "deep.function" => {
            let root = ea_param(&params, "target").or_else(|_| ea_param(&params, "ea"))?;
            let budgets = deep::budgets_from(&params);
            let current_rev = need_backend(state)?.revision();
            let stale = state
                .index
                .as_ref()
                .map(|(idx, _)| idx.revision != current_rev)
                .unwrap_or(true);
            if stale {
                let (idx, md5) = need_backend(state)?.build_index()?;
                state.index = Some((idx, md5));
            }
            // Resume runs continue a specific partial walk and bypass the
            // result cache (they must do fresh work); fresh runs use the
            // revision-keyed cache so unchanged repeats are free.
            let resume = params.get("resume_from").filter(|v| v.is_object());
            let key = (
                "deep_function".to_string(),
                format!("{root:#x}|{budgets:?}"),
                current_rev,
            );
            if resume.is_none()
                && let Some(cached) = state.workflow_cache.get(&key)
            {
                return Ok(json!({
                    "cached": true,
                    "cache_hits": state.workflow_cache.hits,
                    "result": cached,
                }));
            }
            let (idx, _md5) = state.index.as_ref().expect("just built").clone();
            let result = deep::deep_function(need_backend(state)?, &idx, root, &budgets, resume)?;
            if resume.is_none() {
                let key = (
                    "deep_function".to_string(),
                    format!("{root:#x}|{budgets:?}"),
                    current_rev,
                );
                state.workflow_cache.put(key, result.clone());
            }
            Ok(json!({
                "cached": false,
                "cache_hits": state.workflow_cache.hits,
                "result": result,
            }))
        }
        "deep.retype" => {
            let ea = ea_param(&params, "ea")?;
            let decl = params
                .get("decl")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing decl".into()))?;
            check_revision(&params, need_backend(state)?)?;
            let out = need_backend(state)?.deep_apply_prototype(ea, decl)?;
            plan::record_audit(&mut state.audit, "deep.retype", ea, &out);
            state.workflow_cache.invalidate_all();
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "deep.dataflow" => {
            let target = ea_param(&params, "target").or_else(|_| ea_param(&params, "ea"))?;
            let direction = params
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("both")
                .to_string();
            if !matches!(direction.as_str(), "forward" | "backward" | "both") {
                return Err(Error::Worker(format!(
                    "bad direction '{direction}' (forward|backward|both)"
                )));
            }
            let budgets = deep::budgets_from(&params);
            let current_rev = need_backend(state)?.revision();
            let stale = state
                .index
                .as_ref()
                .map(|(idx, _)| idx.revision != current_rev)
                .unwrap_or(true);
            if stale {
                let (idx, md5) = need_backend(state)?.build_index()?;
                state.index = Some((idx, md5));
            }
            let key = (
                "deep_dataflow".to_string(),
                format!("{target:#x}|{direction}|{budgets:?}"),
                current_rev,
            );
            if let Some(cached) = state.workflow_cache.get(&key) {
                return Ok(json!({
                    "cached": true,
                    "cache_hits": state.workflow_cache.hits,
                    "result": cached,
                }));
            }
            let (idx, _md5) = state.index.as_ref().expect("just built").clone();
            let result =
                deep::trace_dataflow(need_backend(state)?, &idx, target, &direction, &budgets)?;
            state.workflow_cache.put(key, result.clone());
            Ok(json!({
                "cached": false,
                "cache_hits": state.workflow_cache.hits,
                "result": result,
            }))
        }
        _ => Err(Error::Worker(format!("unknown method '{method}'"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp_core::protocol::WorkerResponse;

    fn mock_worker() -> WorkerState {
        let mut state = WorkerState::new();
        state.backend = Some(Box::new(rmcp_ida::MockBackend::new()));
        state
    }

    fn send(state: &mut WorkerState, id: u64, method: &str, params: Value) -> WorkerResponse {
        handle(
            state,
            WorkerRequest {
                id,
                method: method.into(),
                params,
            },
        )
    }

    #[test]
    fn stale_revision_is_rejected() {
        let mut state = mock_worker();
        // open + one confirmed mutation bumps the revision to 1
        let r = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        assert!(r.error.is_none(), "open failed: {r:?}");
        let r = send(
            &mut state,
            2,
            "rename",
            json!({"ea": "0x401100", "name": "n1"}),
        );
        assert!(r.error.is_none(), "rename failed: {r:?}");

        // a mutation carrying the now-stale revision 0 must be rejected
        let r = send(
            &mut state,
            3,
            "rename",
            json!({"ea": "0x401100", "name": "n2", "expected_revision": 0}),
        );
        let err = r.error.expect("stale mutation must fail");
        assert_eq!(err.code, "revision_conflict");

        // the DB must be untouched by the rejected mutation
        let r = send(&mut state, 4, "revision", json!({}));
        assert_eq!(r.result.unwrap()["revision"], 1);
    }

    #[test]
    fn matching_revision_is_accepted() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(
            &mut state,
            2,
            "set_comment",
            json!({"ea": "0x401100", "comment": "hi", "expected_revision": 0}),
        );
        let out = r.result.expect("matching-revision mutation must pass");
        assert_eq!(out["changed"], true);
        assert_eq!(out["revision_after"], 1);
    }

    #[test]
    fn omitted_revision_stays_allowed() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(
            &mut state,
            2,
            "rename",
            json!({"ea": "0x401100", "name": "n1"}),
        );
        let out = r.result.expect("omitted expected_revision must pass");
        assert_eq!(out["revision_after"], 1);
    }

    // ---- #19 method tests (mock backend) ----

    #[test]
    fn db_metadata_reports_hashes_and_entries() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(&mut state, 2, "db.metadata", json!({}));
        let out = r.result.expect("db.metadata must pass");
        assert_eq!(out["md5"].as_str().map(|s| s.len()), Some(32));
        assert_eq!(out["sha256"].as_str().map(|s| s.len()), Some(64));
        assert_eq!(out["imagebase"], 0x400000);
        assert_eq!(out["entry_count"], 1);
        // honest reporting of unexposed items
        assert_eq!(out["tls_callbacks_supported"], false);
        assert_eq!(out["exception_handlers_supported"], false);
    }

    #[test]
    fn imports_list_is_bounded_and_shaped() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(&mut state, 2, "imports.list", json!({"limit": 1}));
        let out = r.result.expect("imports.list must pass");
        assert_eq!(out["module_count"], 1);
        let entries = out["modules"][0]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "limit must bound entries");
        assert!(entries[0]["name"].as_str().is_some());
    }

    #[test]
    fn fixups_list_and_file_map_roundtrip() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(&mut state, 2, "fixups.list", json!({}));
        let out = r.result.expect("fixups.list must pass");
        assert_eq!(out["total"], 2);

        // EA -> file offset -> EA roundtrip
        let r = send(&mut state, 3, "file.map", json!({"value": "0x401000"}));
        let out = r.result.expect("file.map ea->offset must pass");
        assert_eq!(out["file_offset"], 0x1400);
        let off = out["file_offset"].as_u64().unwrap();
        let r = send(
            &mut state,
            4,
            "file.map",
            json!({"value": off, "to_ea": true}),
        );
        let out = r.result.expect("file.map offset->ea must pass");
        assert_eq!(out["ea"], 0x401000);

        // unmapped address errors
        let r = send(&mut state, 5, "file.map", json!({"value": "0x1"}));
        assert!(r.error.is_some(), "unmapped value must error");
    }

    #[test]
    fn func_create_delete_and_tails() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(&mut state, 2, "revision", json!({}));
        assert_eq!(r.result.unwrap()["revision"], 0);

        let r = send(&mut state, 3, "func.create", json!({"start": "0x401500"}));
        let out = r.result.expect("func.create must pass");
        assert_eq!(out["changed"], true);
        assert_eq!(out["revision_after"], 1);

        let r = send(&mut state, 4, "func.tails", json!({"ea": "0x401500"}));
        let out = r.result.expect("func.tails must pass");
        assert_eq!(out["chunks"].as_array().unwrap().len(), 1);

        let r = send(
            &mut state,
            5,
            "func.delete",
            json!({"ea": "0x401500", "expected_revision": 1}),
        );
        let out = r.result.expect("func.delete must pass");
        assert_eq!(out["revision_after"], 2);

        // deleting a non-function address fails
        let r = send(&mut state, 6, "func.delete", json!({"ea": "0xdead"}));
        assert!(r.error.is_some());
    }

    #[test]
    fn func_switch_info_and_sp_delta() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(&mut state, 2, "func.switch_info", json!({"ea": "0x401310"}));
        let out = r.result.expect("switch_info must pass");
        assert_eq!(out["ncases"], 4);

        let r = send(&mut state, 3, "func.switch_info", json!({"ea": "0x401000"}));
        assert!(r.error.is_some(), "non-switch address must error");

        let r = send(&mut state, 4, "func.sp_delta", json!({"ea": "0x401100"}));
        let out = r.result.expect("sp_delta must pass");
        assert_eq!(out["sp_delta"], -8);
    }

    #[test]
    fn hr_cfunc_and_lvar_rename() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(
            &mut state,
            2,
            "hr.cfunc",
            json!({"ea": "0x401200", "limit": 1}),
        );
        let out = r.result.expect("hr.cfunc must pass");
        assert!(out["ctree"].as_array().unwrap().len() <= 1);
        assert_eq!(out["lvars_truncated"], false);

        // decompile-disabled backend reports capability_unavailable
        let mut state2 = WorkerState::new();
        state2.backend = Some(Box::new(rmcp_ida::MockBackend::new().without_decompile()));
        let r = handle(
            &mut state2,
            WorkerRequest {
                id: 3,
                method: "hr.cfunc".into(),
                params: json!({"ea": "0x401200"}),
            },
        );
        assert_eq!(r.error.unwrap().code, "capability_unavailable");

        let r = send(
            &mut state,
            4,
            "hr.lvar_rename",
            json!({"ea": "0x401200", "var_defea": "0x401200", "name": "buf"}),
        );
        let out = r.result.expect("hr.lvar_rename must pass");
        assert_eq!(out["changed"], true);
    }

    #[test]
    fn insn_features_and_demangle() {
        let mut state = mock_worker();
        let _ = send(&mut state, 1, "db.open", json!({"path": "fixture.i64"}));
        let r = send(&mut state, 2, "insn.features", json!({"ea": "0x401000"}));
        let out = r.result.expect("insn.features must pass");
        assert_eq!(out["mnemonic"], "mov");

        let r = send(&mut state, 3, "names.demangle", json!({"name": "_Z3fooi"}));
        let out = r.result.expect("names.demangle must pass");
        assert_eq!(out["changed"], true);

        let r = send(
            &mut state,
            4,
            "names.demangle",
            json!({"name": "plain_name"}),
        );
        let out = r.result.expect("demangle passthrough must pass");
        assert_eq!(out["changed"], false);
    }
}
