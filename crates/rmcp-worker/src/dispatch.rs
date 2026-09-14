//! Method dispatch for worker requests. Each method maps onto one or a few
//! `IdaBackend` calls. Unknown methods yield a stable error code.

use rmcp_core::backend::IdaBackend;
use rmcp_core::error::Error;
use rmcp_core::protocol::{WorkerRequest, WorkerResponse};
use serde_json::{Value, json};

use crate::state::WorkerState;

fn need_backend(state: &mut WorkerState) -> rmcp_core::error::Result<&mut (dyn IdaBackend + '_)> {
    match state.backend.as_deref_mut() {
        Some(b) => Ok(b),
        None => Err(Error::Worker("no db open".into())),
    }
}

pub fn handle(state: &mut WorkerState, req: WorkerRequest) -> WorkerResponse {
    let WorkerRequest { id, method, params } = req;
    match dispatch(state, &method, params) {
        Ok(v) => WorkerResponse::ok(id, v),
        Err(e) => WorkerResponse::err(id, &e),
    }
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
            let depth = params.get("depth").and_then(|v| v.as_u64()).unwrap_or(1) as u32;
            need_backend(state)?.graph(ea, depth)
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
            let hex = params
                .get("hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing hex".into()))?;
            let out = need_backend(state)?.patch_bytes(ea, hex)?;
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
            let comment = params
                .get("comment")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing comment".into()))?;
            let rep = params
                .get("repeatable")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let out = need_backend(state)?.set_comment(ea, comment, rep)?;
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "rename" => {
            let ea = ea_param(&params, "ea")?;
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing name".into()))?;
            let out = need_backend(state)?.rename(ea, name)?;
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "types" => {
            let name = params.get("name").and_then(|v| v.as_str());
            let out = need_backend(state)?.types(name)?;
            Ok(out)
        }
        "set_type" => {
            let ea = ea_param(&params, "ea")?;
            let decl = params
                .get("decl")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker("missing decl".into()))?;
            let out = need_backend(state)?.set_type(ea, decl)?;
            serde_json::to_value(out).map_err(|e| Error::Ipc(e.to_string()))
        }
        "analyze_wait" => {
            let out = need_backend(state)?.analyze_wait()?;
            Ok(out)
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
        _ => Err(Error::Worker(format!("unknown method '{method}'"))),
    }
}
