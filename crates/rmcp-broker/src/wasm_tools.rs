//! #71: `ida_wasm` MCP tool - WebAssembly analysis surface.
//!
//! Fuses two engines:
//! - the IDA-native WASM loader facts already open in the worker
//!   (functions with names, segments mapping wasm sections to EAs, xrefs);
//! - the independent rmcp-wasm parser (normalized module model: types,
//!   imports/exports, globals/tables/memories, element/data segments,
//!   features, name/producers custom sections).
//!
//! Cross-engine agreement is reported as `confirmed`; mismatches surface as
//! diagnostics, never silently hidden. Hex-Rays has no WASM decompiler and
//! none is claimed: the `pseudocode` action is the deterministic
//! rmcp-wasm renderer and is labeled as such.
//!
//! Static only: the parser never executes module code.

use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::{arg_str, bound_output, mcp_code, resolve_db, Broker};
use crate::tools::{err_from, McpError};

/// Default parse budget: bounded so adversarial modules fail locally.
const PARSE_LIMIT_BYTES: usize = 256 * 1024 * 1024;

pub async fn tool_wasm(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let action = arg_str(&args, "action").unwrap_or("info");
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;

    // The module model comes from the file on disk (static parse); the db
    // handle guarantees the IDA side is open and provides EA-space facts.
    let s = session.lock().await;
    let db_path = s
        .db_path()
        .ok_or_else(|| mcp_code("no_db", "wasm actions require an open database"))?
        .to_string();
    let raw = tokio::fs::read(&db_path)
        .await
        .map_err(|e| mcp_code("io", &format!("cannot read module file: {e}")))?;
    if raw.len() > PARSE_LIMIT_BYTES {
        return Err(mcp_code(
            "budget",
            &format!("module exceeds parse budget ({PARSE_LIMIT_BYTES} bytes)"),
        ));
    }
    let model = rmcp_wasm::module::parse(&raw).map_err(|e| {
        mcp_code(
            "wasm_parse",
            &format!("not a parseable WASM module: {e}"),
        )
    })?;

    // IDA-side facts (native loader) for cross-engine fusion.
    let ida_functions = s
        .call("functions", json!({"offset": 0, "limit": 10_000}))
        .await
        .map_err(err_from)?;
    let ida_segments = s
        .call("segments", json!({"offset": 0, "limit": 200}))
        .await
        .map_err(err_from)?;
    drop(s);

    let mut diagnostics: Vec<String> = Vec::new();

    // Cross-check 1: defined-function count (model vs native loader).
    let ida_fn_count = ida_functions.as_array().map(|a| a.len()).unwrap_or(0);
    let model_fn_count = model.functions.len();
    let count_confirmed = ida_fn_count == model_fn_count;
    if !count_confirmed {
        diagnostics.push(format!(
            "function count mismatch: parser={model_fn_count} ida={ida_fn_count}"
        ));
    }

    // Cross-check 2: wasm code offsets inside the IDA address space have a
    // segment covering them (the native loader maps code bodies to EAs).
    let seg_ranges: Vec<(u64, u64, String)> = ida_segments
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| {
                    Some((
                        s["start"].as_u64()?,
                        s["end"].as_u64()?,
                        s["name"].as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let code_section = model
        .sections
        .iter()
        .find(|s| s.name == "code")
        .map(|s| (s.offset, s.offset + s.size));
    let code_mapping = match code_section {
        Some((start, end)) => {
            let covered = seg_ranges
                .iter()
                .any(|(s, e, _)| *s <= start && end <= *e);
            if covered {
                "confirmed".to_string()
            } else {
                diagnostics.push(format!(
                    "code section [{start:#x},{end:#x}) not covered by any IDA segment"
                ));
                "mismatch".to_string()
            }
        }
        None => "absent".to_string(),
    };

    match action {
        "info" => {
            let out = json!({
                "engine": "rmcp-wasm + IDA native loader",
                "binary_sha256": model.binary_sha256,
                "wasm_version": model.version,
                "sections": model.sections,
                "features": model.features,
                "counts": {
                    "types": model.types.len(),
                    "imports": model.imports.len(),
                    "exports": model.exports.len(),
                    "functions_defined": model_fn_count,
                    "globals": model.globals.len(),
                    "tables": model.tables.len(),
                    "memories": model.memories.len(),
                    "elements": model.elements.len(),
                    "datas": model.datas.len(),
                },
                "custom": model.custom,
                "start": model.start,
                "cross_check": {
                    "function_count_confirmed": count_confirmed,
                    "code_offset_mapping": code_mapping,
                },
                "diagnostics": diagnostics,
                "hexrays": "unavailable (IDA has no WASM decompiler; pseudocode action is the rmcp-wasm renderer)",
            });
            Ok(json!({"db": db, "wasm": bound_output(broker, "ida_wasm.info", out)}))
        }
        "imports" | "exports" | "globals" | "tables" | "memories" | "elements" | "datas"
        | "types" | "sections" => {
            let out = match action {
                "imports" => json!({"imports": model.imports,
                    "wasi_groups": wasi_groups(&model.imports)}),
                "exports" => json!({"exports": model.exports}),
                "globals" => json!({"globals": model.globals}),
                "tables" => json!({"tables": model.tables}),
                "memories" => json!({"memories": model.memories}),
                "elements" => json!({"elements": model.elements}),
                "datas" => json!({"datas": model.datas}),
                "types" => json!({"types": model.types}),
                _ => json!({"sections": model.sections}),
            };
            Ok(json!({"db": db, "wasm": bound_output(broker, &format!("ida_wasm.{action}"), out)}))
        }
        "functions" => {
            // Fuse: parser index-space + IDA names/EA mapping where the
            // native loader found them. Provenance on every row.
            let ida_by_index: BTreeMap<usize, &Value> = ida_functions
                .as_array()
                .map(|a| a.iter().enumerate().collect())
                .unwrap_or_default();
            let mut rows = Vec::with_capacity(model.functions.len());
            for (i, f) in model.functions.iter().enumerate() {
                let ida = ida_by_index.get(&i).copied();
                let type_ref = model.types.get(f.type_index as usize);
                rows.push(json!({
                    "wasm_index": f.index,
                    "type_index": f.type_index,
                    "signature": type_ref,
                    "code_offset": f.code_offset,
                    "code_size": f.code_size,
                    "local_types": f.local_types,
                    "name_parser": f.name,
                    "ida_name": ida.and_then(|v| v["name"].as_str()),
                    "ida_ea": ida.and_then(|v| v["ea_start"].as_u64()),
                    "name_source": match (f.name.as_deref(), ida.and_then(|v| v["name"].as_str())) {
                        (Some(_), Some(_)) => "parser+ida",
                        (Some(_), None) => "parser",
                        (None, Some(_)) => "ida",
                        (None, None) => "none",
                    },
                }));
            }
            let out = json!({
                "functions": rows,
                "function_count_confirmed": count_confirmed,
                "diagnostics": diagnostics,
            });
            Ok(json!({"db": db, "wasm": bound_output(broker, "ida_wasm.functions", out)}))
        }
        "cfg" => {
            // Structured control flow for one function from the parser.
            let idx = args
                .get("index")
                .and_then(parse_index)
                .ok_or_else(|| mcp_code("invalid_args", "cfg requires 'index'"))?;
            let f = model
                .functions
                .iter()
                .find(|f| f.index == idx)
                .ok_or_else(|| mcp_code("invalid_args", &format!("function index {idx} not in module")))?;
            let body = &raw[f.code_offset as usize
                ..(f.code_offset + f.code_size) as usize];
            let cfg = rmcp_wasm::cfg::analyze_body(body)
                .map_err(|e| mcp_code("wasm_cfg", &format!("structured CFG failed: {e}")))?;
            let out = serde_json::to_value(&cfg)
                .map_err(|e| mcp_code("internal", &e.to_string()))?;
            Ok(json!({"db": db, "wasm": bound_output(broker, "ida_wasm.cfg", out)}))
        }
        "pseudocode" => {
            // Deterministic WASM-native rendering - explicitly NOT Hex-Rays.
            let idx = args
                .get("index")
                .and_then(parse_index)
                .ok_or_else(|| mcp_code("invalid_args", "pseudocode requires 'index'"))?;
            let f = model
                .functions
                .iter()
                .find(|f| f.index == idx)
                .ok_or_else(|| mcp_code("invalid_args", &format!("function index {idx} not in module")))?;
            let body = &raw[f.code_offset as usize
                ..(f.code_offset + f.code_size) as usize];
            let cfg = rmcp_wasm::cfg::analyze_body(body)
                .map_err(|e| mcp_code("wasm_cfg", &format!("structured CFG failed: {e}")))?;
            let text = rmcp_wasm::pseudo::render(&model, idx, body, &cfg)
                .map_err(|e| mcp_code("wasm_pseudo", &format!("pseudocode failed: {e}")))?;
            let out = json!({
                "wasm_index": idx,
                "engine": "rmcp-wasm structured renderer (deterministic; NOT Hex-Rays output)",
                "pseudocode": text,
            });
            Ok(json!({"db": db, "wasm": bound_output(broker, "ida_wasm.pseudocode", out)}))
        }
        "indirect_targets" => {
            // Evidence-backed indirect call resolution (never fabricated
            // certainty): SSA constant indices where proven, candidates
            // bounded by type compatibility.
            let idx = args
                .get("index")
                .and_then(parse_index)
                .ok_or_else(|| mcp_code("invalid_args", "indirect_targets requires 'index'"))?;
            let f = model
                .functions
                .iter()
                .find(|f| f.index == idx)
                .ok_or_else(|| mcp_code("invalid_args", &format!("function index {idx} not in module")))?;
            let body = &raw[f.code_offset as usize
                ..(f.code_offset + f.code_size) as usize];
            let cfg = rmcp_wasm::cfg::analyze_body(body)
                .map_err(|e| mcp_code("wasm_cfg", &format!("structured CFG failed: {e}")))?;
            let targets = rmcp_wasm::calls::resolve_indirect(&model, &cfg.indirect_calls, &BTreeMap::new());
            let out = serde_json::to_value(&targets)
                .map_err(|e| mcp_code("internal", &e.to_string()))?;
            Ok(json!({"db": db, "wasm": bound_output(broker, "ida_wasm.indirect_targets", out)}))
        }
        other => Err(mcp_code(
            "invalid_args",
            &format!("unknown action '{other}' (info|sections|types|imports|exports|functions|globals|tables|memories|elements|datas|cfg|pseudocode|indirect_targets)"),
        )),
    }
}

fn parse_index(v: &Value) -> Option<u32> {
    match v {
        Value::String(s) => s.trim().parse().ok(),
        Value::Number(n) => n.as_u64().map(|n| n as u32),
        _ => None,
    }
}

fn wasi_groups(imports: &[rmcp_wasm::module::ImportEntry]) -> Vec<Value> {
    let mut by_module: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for i in imports.iter().filter(|i| i.wasi) {
        by_module
            .entry(i.module.clone())
            .or_default()
            .push(i.name.clone());
    }
    by_module
        .into_iter()
        .map(|(module, names)| json!({"module": module, "imports": names}))
        .collect()
}
