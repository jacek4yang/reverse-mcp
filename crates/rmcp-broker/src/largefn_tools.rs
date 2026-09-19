//! #72 §6: hierarchical large-function analysis tool surface.
//!
//! `ida_analyze workflow=function_hierarchical`:
//!   1. preflight (worker `function_at` + `graph kind=cfg`, no Hex-Rays)
//!      classifies the function normal|large|pathological;
//!   2. normal functions keep the unchanged whole-function path;
//!   3. large/pathological: the CFG is partitioned into virtual regions
//!      and each region is analyzed in a disposable isolation worker with
//!      the fallback chain (Hex-Rays snippet -> microcode -> raw-IDA
//!      evidence) under a true hard timeout;
//!   4. overview-first response with a resumable frontier; region drill-in
//!      via `workflow=function_region` + region_id.
//!
//! Normal-function behavior is untouched: the hierarchical path only runs
//! when the agent asks for it or preflight says so.

use serde_json::{Value, json};

use crate::dataflow::{DataflowLimits, RegionFacts, run_dataflow};
use crate::isolation::{DisposableOutcome, iso_stats, run_isolated};
use crate::largefn::{complexity_from_function_graph, partition_from_graph};
use crate::preflight::{AnalysisMode, Thresholds};
use crate::regions::PartitionOptions;
use crate::tools::{McpError, err_from, parse_ea};
use crate::{Broker, arg_str, arg_u64, bound_output, mcp_code, resolve_db};

/// Graph caps well above any real giant (audit fixture: 3005 blocks).
const CFG_MAX_NODES: u64 = 200_000;
const CFG_MAX_EDGES: u64 = 400_000;

/// workflow=function_hierarchical handler.
pub async fn tool_analyze_hierarchical(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "function_hierarchical requires 'ea'"))?;
    let max_regions = arg_u64(&args, "max_regions", 16).clamp(1, 256) as usize;
    let hard_timeout_ms = arg_u64(&args, "hard_timeout_ms", 120_000).clamp(5_000, 1_800_000);
    let thresholds = Thresholds::default();
    let opts = PartitionOptions::default();
    let limits = DataflowLimits::default();

    // ---- 1. Preflight: worker facts only, no Hex-Rays (cheap even for
    // pathological functions; audit: graph on the giant took 51ms).
    let s = session.lock().await;
    let func = s
        .call("function_at", json!({"ea": format!("{ea:#x}")}))
        .await
        .map_err(err_from)?;
    let graph = s
        .call(
            "graph",
            json!({
                "ea": format!("{ea:#x}"),
                "kind": "cfg",
                "depth": 1,
                "max_nodes": CFG_MAX_NODES,
                "max_edges": CFG_MAX_EDGES,
            }),
        )
        .await
        .map_err(err_from)?;
    let decompiler_available = s
        .call("capabilities", json!({}))
        .await
        .map_err(err_from)?
        .get("decompile")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let complexity = complexity_from_function_graph(&func, &graph, decompiler_available);
    let mode = complexity.mode(&thresholds);

    // ---- 2. Normal functions: unchanged whole-function path.
    if mode == AnalysisMode::Normal {
        let mut req = args.clone();
        if let Some(obj) = req.as_object_mut() {
            obj.remove("db");
        }
        req["workflow"] = json!("function_context");
        let out = s
            .call("workflow.run", json!({"workflow_req": req}))
            .await
            .map_err(err_from)?;
        return Ok(json!({
            "db": db,
            "analysis": out,
            "mode": "normal",
            "complexity": complexity,
        }));
    }

    // ---- 3. Region partition (pure bookkeeping over the fetched graph).
    let partition = partition_from_graph(&graph, ea, &opts);

    // Isolation-layer inputs (resolved from the live pool).
    let pool = broker.pool.lock().await;
    let worker_exe = pool
        .resolved_worker_exe()
        .ok_or_else(|| mcp_code("worker_missing", "worker exe not found"))?;
    let ida_dir = pool.resolved_ida_dir();
    drop(pool);
    let db_path = s.db_path().unwrap_or_default().to_string();
    drop(s);

    // ---- 4. Per-region analysis through the disposable worker.

    let mut region_outcomes = Vec::new();
    let mut facts: std::collections::BTreeMap<String, RegionFacts> = Default::default();
    let mut analyzed = 0usize;
    let mut hexrays_failures = 0usize;
    for r in partition.regions.iter().take(max_regions) {
        let params = json!({
            "ea": format!("{:#x}", r.block_eas.first().copied().unwrap_or(0)),
            "end_ea": format!("{:#x}", r.block_eas.last().copied().unwrap_or(0)),
            "region_id": r.region_id,
            "role": r.role,
            "max_insns": 4000,
        });
        let outcome = run_isolated(
            &worker_exe,
            ida_dir.as_deref(),
            &db_path,
            "region.evidence",
            params,
            std::time::Duration::from_millis(hard_timeout_ms),
        )
        .await;

        let (status, evidence) = match outcome {
            Ok(DisposableOutcome::Ok(v)) => {
                analyzed += 1;
                ("complete", v)
            }
            Ok(DisposableOutcome::BadResponse { detail, .. }) => {
                // Structured Hex-Rays failure: degrade to raw evidence.
                analyzed += 1;
                hexrays_failures += 1;
                (
                    "partial_fallback_raw",
                    json!({
                        "fallback": "raw_ida_disassembly",
                        "hexrays_error": detail,
                        "blocks": r.block_eas.len(),
                    }),
                )
            }
            Ok(DisposableOutcome::Timeout { after, stage }) => (
                "timeout",
                json!({
                    "hexrays_error": format!("hard timeout after {after:?}"),
                    "stage": stage,
                    "note": "disposable worker killed; primary session unaffected",
                }),
            ),
            Ok(DisposableOutcome::Crashed { detail, stage }) => (
                "crashed",
                json!({
                    "hexrays_error": detail,
                    "stage": stage,
                    "note": "disposable worker killed; primary session unaffected",
                }),
            ),
            Err(e) => (
                "rejected",
                json!({"error": e.to_string(), "note": "isolation cap or setup failure; primary session unaffected"}),
            ),
        };
        region_outcomes.push(json!({
            "region_id": r.region_id,
            "role": r.role,
            "blocks": r.block_eas.len(),
            "status": status,
            "evidence": evidence,
        }));
        facts.insert(
            r.region_id.clone(),
            RegionFacts {
                region_id: r.region_id.clone(),
                out_facts: vec![],
                in_requests: vec![],
            },
        );
    }

    let dataflow = run_dataflow(&partition, &facts, &limits, |_, _| vec![]);
    let iso = iso_stats().snapshot();
    let remaining = partition.regions.len().saturating_sub(max_regions);
    let partial = analyzed < partition.regions.len();

    let overview = json!({
        "mode": match mode {
            AnalysisMode::Normal => "normal",
            AnalysisMode::Large => "large_region",
            AnalysisMode::Pathological => "pathological",
        },
        "complexity": complexity,
        "function_ea": format!("{ea:#x}"),
        "partition": {
            "version": partition.version,
            "regions_total": partition.regions.len(),
            "regions_requested": max_regions,
            "regions_skipped": remaining,
            "diagnostics": partition.diagnostics,
        },
        "important_regions": region_outcomes,
        "analysis_status": if partial { "partial" } else { "complete" },
        "hexrays_failures": hexrays_failures,
        "resume": {
            "frontier": dataflow.frontier,
            "hint": if remaining > 0 {
                "more regions remain: re-run with a larger max_regions or drill into a region via workflow=function_region"
            } else {
                "drill into a region via workflow=function_region with its region_id"
            },
        },
        "dataflow": {
            "iterations": dataflow.iterations,
            "converged": dataflow.converged,
            "stop_reason": dataflow.stop_reason,
        },
        "isolation": iso,
    });
    Ok(json!({
        "db": db,
        "analysis": bound_output(broker, "ida_analyze.function_hierarchical", overview),
    }))
}

/// workflow=function_region handler: drill into one region of a partition.
/// Evidence is computed fresh (bounded disassembly window + optional
/// per-region Hex-Rays attempt through the isolation worker).
pub async fn tool_analyze_region(broker: &Broker, args: Value) -> Result<Value, McpError> {
    let (db, session) = resolve_db(broker, arg_str(&args, "db")).await?;
    let ea = args
        .get("ea")
        .and_then(parse_ea)
        .ok_or_else(|| mcp_code("invalid_args", "function_region requires 'ea'"))?;
    let region_id = arg_str(&args, "region_id")
        .ok_or_else(|| mcp_code("invalid_args", "function_region requires 'region_id'"))?
        .to_string();
    let hard_timeout_ms = arg_u64(&args, "hard_timeout_ms", 120_000).clamp(5_000, 1_800_000);
    let max_insns = arg_u64(&args, "max_insns", 4000).clamp(10, 20_000);
    let try_hexrays = arg_u64(&args, "try_hexrays", 1) == 1;
    let opts = PartitionOptions::default();

    // Rebuild the partition to locate the requested region (deterministic:
    // same graph -> same partition -> same region ids).
    let s = session.lock().await;
    let graph = s
        .call(
            "graph",
            json!({
                "ea": format!("{ea:#x}"),
                "kind": "cfg",
                "depth": 1,
                "max_nodes": CFG_MAX_NODES,
                "max_edges": CFG_MAX_EDGES,
            }),
        )
        .await
        .map_err(err_from)?;
    let partition = partition_from_graph(&graph, ea, &opts);
    let region = partition
        .regions
        .iter()
        .find(|r| r.region_id == region_id)
        .ok_or_else(|| {
            mcp_code(
                "unknown_region",
                &format!(
                    "region '{region_id}' not in partition of {ea:#x}; valid regions: {}",
                    partition
                        .regions
                        .iter()
                        .map(|r| r.region_id.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            )
        })?
        .clone();

    let entry_ea = region.block_eas.first().copied().unwrap_or(0);
    let exit_ea = region.block_eas.last().copied().unwrap_or(0);

    // Bounded disassembly window over the region (primary session, cheap).
    let disasm = s
        .call(
            "disassemble",
            json!({
                "ea": format!("{entry_ea:#x}"),
                "end": format!("{:#x}", exit_ea.saturating_add(1)),
                "max_insns": max_insns,
            }),
        )
        .await
        .map_err(err_from)?;

    // Optional per-region Hex-Rays attempt through the disposable worker.
    let mut hexrays: Option<Value> = None;
    if try_hexrays {
        let pool = broker.pool.lock().await;
        let worker_exe = pool.resolved_worker_exe();
        let ida_dir = pool.resolved_ida_dir();
        drop(pool);
        if let Some(worker_exe) = worker_exe {
            let db_path = s.db_path().unwrap_or_default().to_string();
            match run_isolated(
                &worker_exe,
                ida_dir.as_deref(),
                &db_path,
                "region.evidence",
                json!({
                    "ea": format!("{entry_ea:#x}"),
                    "end_ea": format!("{:#x}", exit_ea.saturating_add(1)),
                    "region_id": region_id,
                    "role": region.role,
                    "max_insns": max_insns,
                }),
                std::time::Duration::from_millis(hard_timeout_ms),
            )
            .await
            {
                Ok(DisposableOutcome::Ok(v)) => hexrays = Some(v),
                Ok(DisposableOutcome::BadResponse { detail, stage }) => {
                    hexrays = Some(
                        json!({"status": "fallback_raw", "hexrays_error": detail, "stage": stage}),
                    );
                }
                Ok(DisposableOutcome::Timeout { after, stage }) => {
                    hexrays = Some(
                        json!({"status": "timeout", "after": format!("{after:?}"), "stage": stage}),
                    );
                }
                Ok(DisposableOutcome::Crashed { detail, stage }) => {
                    hexrays = Some(json!({"status": "crashed", "detail": detail, "stage": stage}));
                }
                Err(e) => hexrays = Some(json!({"status": "rejected", "error": e.to_string()})),
            }
        }
    }

    let out = json!({
        "function_ea": format!("{ea:#x}"),
        "region_id": region.region_id,
        "role": region.role,
        "blocks": region.block_eas.len(),
        "block_eas": region.block_eas.iter().map(|b| format!("{b:#x}")).collect::<Vec<_>>(),
        "pred_regions": region.pred_regions,
        "succ_regions": region.succ_regions,
        "partition_reason": region.partition_reason,
        "disassembly": disasm,
        "hexrays": hexrays,
    });
    Ok(json!({
        "db": db,
        "region": bound_output(broker, "ida_analyze.function_region", out),
    }))
}
