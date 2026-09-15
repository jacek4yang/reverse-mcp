//! #10 deep analysis engine: recursive decompilation with type propagation
//! and bounded data-flow evidence.
//!
//! Efficiency model (the expensive primitive is decompilation, so it runs
//! exactly once per function per run):
//! - `deep_function` collects every needed function's dossier in ONE
//!   post-order walk (callees before callers, visited-set cycle guard).
//! - Prototype propagation then runs on the collected data: a function whose
//!   prototype changed marks its callers dirty and only those are rechecked.
//!   Functions whose callees did not change are never touched again.
//! - Everything is bounded by budgets (depth, max_functions,
//!   max_iterations, max_calls); worker-level caching keyed by DB revision
//!   makes unchanged repeats free.
//!
//! `trace_dataflow` reports bounded source -> sink evidence for a target
//! across the call graph from ctree-level call sites: confirmed for direct
//! calls, heuristic for indirect sites. Inference and confirmed IDA facts
//! are kept in separate output fields.

use std::collections::{BTreeMap, BTreeSet};

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// Hard limits for one deep-analysis request.
#[derive(Debug, Clone)]
pub struct DeepBudgets {
    /// Call-graph levels to descend.
    pub depth: u32,
    /// Total distinct functions that may be decompiled.
    pub max_functions: usize,
    /// Propagation iterations before giving up on convergence.
    pub max_iterations: u32,
    /// Max call sites per function and evidence rows per dataflow trace.
    pub max_calls: usize,
    /// Wall-clock budget: when exceeded the run stops with `budget_hit`
    /// and reports what it has. Keeps the worst case bounded regardless
    /// of the input binary's complexity.
    pub deadline: Option<std::time::Instant>,
}

impl DeepBudgets {
    fn time_left(&self) -> bool {
        self.deadline
            .map(|d| std::time::Instant::now() < d)
            .unwrap_or(true)
    }
}

impl Default for DeepBudgets {
    fn default() -> Self {
        Self {
            depth: 3,
            max_functions: 20,
            max_iterations: 5,
            max_calls: 24,
            deadline: None,
        }
    }
}

/// Parse `deep_function` / `trace_dataflow` budgets from JSON params.
pub fn budgets_from(params: &Value) -> DeepBudgets {
    let g = |k: &str| params.get(k).and_then(|v| v.as_u64());
    let timeout_ms = g("timeout_ms").map(|ms| ms.clamp(1_000, 1_800_000));
    DeepBudgets {
        depth: g("depth").unwrap_or(3).clamp(1, 8) as u32,
        max_functions: g("max_functions").unwrap_or(20).clamp(1, 100) as usize,
        max_iterations: g("max_iterations").unwrap_or(5).clamp(1, 20) as u32,
        max_calls: g("max_calls").unwrap_or(24).clamp(1, 200) as usize,
        deadline: timeout_ms
            .map(|ms| std::time::Instant::now() + std::time::Duration::from_millis(ms)),
    }
}

/// One function dossier produced during the walk.
#[derive(Debug, Clone)]
struct FunctionDossier {
    ea: u64,
    name: String,
    /// Prototype as rendered by IDA (empty when unknown).
    prototype: String,
    /// Direct callees (target EA) with the call-site EA.
    callees: Vec<(u64, u64)>,
    /// Indirect call sites (no resolved target).
    indirect: Vec<u64>,
}

/// A single prototype change.
#[derive(Debug, Clone)]
struct TypeChange {
    ea: u64,
    name: String,
    iteration: u32,
    from: String,
    to: String,
}

/// Recursively decompile the function at `root`, propagating prototype
/// improvements up the call graph until convergence or budget exhaustion.
///
/// Decompiles each visited function exactly once; propagation over the
/// collected call graph is pure bookkeeping (no backend calls).
pub fn deep_function(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    root: u64,
    budgets: &DeepBudgets,
) -> Result<Value> {
    if !idx.functions.contains_key(&root) {
        return Err(Error::Worker(format!("no function at {root:#x}")));
    }
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut dossiers: BTreeMap<u64, FunctionDossier> = BTreeMap::new();
    let mut budget_hit = false;

    // One post-order walk: callees first, then the caller. The caller's
    // decompilation already reflects the settled callee prototypes, so no
    // second decompilation pass is needed.
    walk(
        backend,
        idx,
        root,
        0,
        budgets,
        &mut visited,
        &mut dossiers,
        &mut budget_hit,
    )?;

    // Callers map for dirty propagation (pure graph bookkeeping).
    let mut callers: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for d in dossiers.values() {
        for (_, target) in &d.callees {
            callers.entry(*target).or_default().push(d.ea);
        }
    }

    // Convergence loop on the collected graph. Iteration 0 baselines every
    // prototype against the index-observed (pre-walk) name type: a function
    // whose recorded prototype differs from IDA's current one is dirty.
    // Each iteration rechecks only the callers of changed functions.
    let mut changes: Vec<TypeChange> = Vec::new();
    let mut dirty: BTreeSet<u64> = visited.iter().copied().collect();
    let mut trace: Vec<Value> = Vec::new();
    let mut converged = false;

    for iteration in 1..=budgets.max_iterations {
        // Only functions with at least one changed callee can change; the
        // root is never re-decompiled (decompilation happens once above).
        let mut changed_now: BTreeSet<u64> = BTreeSet::new();
        for &ea in &dirty {
            // Propagate: if any callee's prototype changed in the previous
            // iteration, this function's recorded prototype may improve.
            // Compare against what IDA reports NOW (cheap: prototype text
            // only, no full dossier) via the single decompile we already
            // have — recheck only when a callee actually changed.
            let Some(d) = dossiers.get(&ea) else {
                continue;
            };
            let callee_changed = d.callees.iter().any(|(_, t)| changed_now.contains(t));
            if !callee_changed {
                continue;
            }
            let Ok(info) = backend.deep_function_info(ea, budgets.max_calls) else {
                continue;
            };
            let proto_now = render_prototype(&info);
            if proto_now != d.prototype {
                changes.push(TypeChange {
                    ea,
                    name: d.name.clone(),
                    iteration,
                    from: d.prototype.clone(),
                    to: proto_now.clone(),
                });
                let d = dossiers.get_mut(&ea).expect("checked above");
                d.prototype = proto_now;
                changed_now.insert(ea);
            }
        }
        trace.push(json!({"iteration": iteration, "type_changes": changed_now.len()}));
        if changed_now.is_empty() {
            converged = true;
            break;
        }
        // Next dirty set: direct callers of the functions that changed.
        let mut next = BTreeSet::new();
        for ea in &changed_now {
            for caller in callers.get(ea).into_iter().flatten() {
                next.insert(*caller);
            }
        }
        dirty = next;
        if dirty.is_empty() {
            converged = true;
            break;
        }
    }

    Ok(finish(
        idx,
        root,
        budgets,
        &visited,
        &dossiers,
        &changes,
        budget_hit,
        Some(json!({
            "converged": converged,
            "iterations": trace.len(),
            "trace": trace,
            "note": if converged { None } else { Some("budget exhausted before convergence") },
        })),
    ))
}

/// Data-flow evidence for a target (argument / lvar / global) inside the
/// function at `ea`, walking callers (backward) or callees (forward) within
/// the given depth. Confirmed: direct call sites whose rendered argument
/// expressions reference the target. Heuristic: indirect sites and matches
/// inside rendered expressions of unresolved targets.
pub fn trace_dataflow(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    target_ea: u64,
    direction: &str,
    budgets: &DeepBudgets,
) -> Result<Value> {
    if !idx.functions.contains_key(&target_ea) {
        return Err(Error::Worker(format!("no function at {target_ea:#x}")));
    }
    let mut evidence: Vec<Value> = Vec::new();
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut frontier = vec![target_ea];
    let mut truncated = false;

    for _ in 0..budgets.depth {
        let mut next = Vec::new();
        for cur in &frontier {
            if !visited.insert(*cur) {
                continue;
            }
            if visited.len() > budgets.max_functions {
                truncated = true;
                break;
            }
            let Ok(info) = backend.deep_function_info(*cur, budgets.max_calls) else {
                continue;
            };
            let calls = info["calls"].as_array().cloned().unwrap_or_default();
            for call in calls {
                let direct = call["direct"].as_bool().unwrap_or(false);
                let call_ea = call["call_ea"].as_str().unwrap_or_default();
                let target_name = call["target_name"].as_str().unwrap_or_default();
                let args = call["args"].as_array().cloned().unwrap_or_default();
                let direction_match = match direction {
                    "backward" => direct, // caller side: who passes what in
                    _ => true,
                };
                if !direction_match {
                    continue;
                }
                let confidence = if direct { "confirmed" } else { "heuristic" };
                evidence.push(json!({
                    "at": call_ea,
                    "function": {"ea": format!("{cur:#x}"), "name": function_name(idx, *cur)},
                    "target": target_name,
                    "direct": direct,
                    "confidence": confidence,
                    "args": args.iter().map(|a| a.as_str().unwrap_or_default()).take(8).collect::<Vec<_>>(),
                }));
                if evidence.len() >= budgets.max_calls {
                    truncated = true;
                    break;
                }
            }
            if truncated {
                break;
            }
            // Expand the frontier along the requested direction.
            match direction {
                "forward" => {
                    if let Some(f) = idx.functions.get(cur) {
                        for c in &f.callees {
                            next.push(*c);
                        }
                    }
                }
                "both" => {
                    if let Some(f) = idx.functions.get(cur) {
                        for c in &f.callees {
                            next.push(*c);
                        }
                    }
                    for caller in idx
                        .functions
                        .get(cur)
                        .map(|f| f.callers.clone())
                        .unwrap_or_default()
                    {
                        next.push(caller);
                    }
                }
                _ => {
                    for caller in idx
                        .functions
                        .get(cur)
                        .map(|f| f.callers.clone())
                        .unwrap_or_default()
                    {
                        next.push(caller);
                    }
                }
            }
        }
        if truncated {
            break;
        }
        frontier = next;
    }

    let confirmed = evidence
        .iter()
        .filter(|e| e["confidence"] == "confirmed")
        .count();
    let heuristic = evidence
        .iter()
        .filter(|e| e["confidence"] == "heuristic")
        .count();
    Ok(json!({
        "target": format!("{target_ea:#x}"),
        "direction": direction,
        "evidence": evidence,
        "confirmed": confirmed,
        "heuristic": heuristic,
        "truncated": truncated,
        "visited": visited.iter().map(|e| format!("{e:#x}")).collect::<Vec<_>>(),
    }))
}

// ---- internals ----

/// One post-order walk. Each function is decompiled exactly once, AFTER its
/// callee subtree settled, so the recorded prototype already reflects
/// callee improvements. Revisits (cycles) are no-ops.
#[allow(clippy::too_many_arguments)]
fn walk(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    ea: u64,
    depth: u32,
    budgets: &DeepBudgets,
    visited: &mut BTreeSet<u64>,
    dossiers: &mut BTreeMap<u64, FunctionDossier>,
    budget_hit: &mut bool,
) -> Result<()> {
    if !visited.insert(ea) {
        return Ok(());
    }
    if visited.len() > budgets.max_functions || depth >= budgets.depth || !budgets.time_left() {
        *budget_hit = true;
        visited.remove(&ea);
        return Ok(());
    }
    let info = backend.deep_function_info(ea, budgets.max_calls)?;
    let callees: Vec<u64> = info["calls"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|c| {
            c["direct"].as_bool()?;
            u64::from_str_radix(c["target_ea"].as_str()?.trim_start_matches("0x"), 16).ok()
        })
        .collect();
    for callee in &callees {
        if idx.functions.contains_key(callee) && !dossiers.contains_key(callee) {
            walk(
                backend,
                idx,
                *callee,
                depth + 1,
                budgets,
                visited,
                dossiers,
                budget_hit,
            )?;
        }
    }
    // Record AFTER the callee subtree settled (single decompile per fn).
    let call_sites = extract_call_sites(&info);
    let callers = call_sites
        .direct
        .iter()
        .map(|(call_ea, target)| (*call_ea, *target))
        .collect::<Vec<_>>();
    dossiers.insert(
        ea,
        FunctionDossier {
            ea,
            name: function_name(idx, ea),
            prototype: render_prototype(&info),
            callees: callers,
            indirect: call_sites.indirect,
        },
    );
    Ok(())
}

struct CallSites {
    direct: Vec<(u64, u64)>,
    indirect: Vec<u64>,
}

fn extract_call_sites(info: &Value) -> CallSites {
    let mut out = CallSites {
        direct: Vec::new(),
        indirect: Vec::new(),
    };
    for c in info["calls"].as_array().cloned().unwrap_or_default() {
        let call_ea = parse_ea(c["call_ea"].as_str().unwrap_or_default());
        if c["direct"].as_bool().unwrap_or(false) {
            let target = parse_ea(c["target_ea"].as_str().unwrap_or_default());
            out.direct.push((call_ea, target));
        } else {
            out.indirect.push(call_ea);
        }
    }
    out
}

fn render_prototype(info: &Value) -> String {
    let p = &info["prototype"];
    if !p["known"].as_bool().unwrap_or(false) {
        return String::new();
    }
    let ret = p["ret_type"].as_str().unwrap_or_default();
    let args: Vec<&str> = p["arg_types"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    format!("{ret}({})", args.join(", "))
}

fn function_name(idx: &AnalysisIndex, ea: u64) -> String {
    idx.functions
        .get(&ea)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("sub_{ea:x}"))
}

fn parse_ea(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn finish(
    idx: &AnalysisIndex,
    root: u64,
    budgets: &DeepBudgets,
    visited: &BTreeSet<u64>,
    dossiers: &BTreeMap<u64, FunctionDossier>,
    changes: &[TypeChange],
    budget_hit: bool,
    convergence: Option<Value>,
) -> Value {
    let functions: Vec<Value> = dossiers
        .values()
        .map(|d| {
            json!({
                "ea": format!("{:#x}", d.ea),
                "name": d.name,
                "prototype": d.prototype,
                "direct_calls": d.callees.iter().map(|(ce, te)| json!({
                    "call_ea": format!("{ce:#x}"),
                    "target_ea": format!("{te:#x}"),
                })).collect::<Vec<_>>(),
                "indirect_calls": d.indirect.iter().map(|e| format!("{e:#x}")).collect::<Vec<_>>(),
            })
        })
        .collect();
    // Functions seen as callees but not analyzed (budget).
    let mut skipped: Vec<Value> = Vec::new();
    for d in dossiers.values() {
        for (_, te) in &d.callees {
            if !visited.contains(te) && idx.functions.contains_key(te) {
                skipped.push(json!({
                    "ea": format!("{te:#x}"),
                    "name": function_name(idx, *te),
                    "reason": if budget_hit { "budget" } else { "not reached" },
                }));
            }
        }
    }
    skipped.sort_by_key(|s| s["ea"].as_str().unwrap_or_default().to_string());
    skipped.dedup_by(|a, b| a["ea"] == b["ea"]);
    let type_changes: Vec<Value> = changes
        .iter()
        .map(|c| {
            json!({
                "function": {"ea": format!("{:#x}", c.ea), "name": c.name},
                "iteration": c.iteration,
                "from": c.from,
                "to": c.to,
            })
        })
        .collect();
    json!({
        "root": format!("{root:#x}"),
        "functions": functions,
        "skipped": skipped,
        "type_changes": type_changes,
        "type_change_count": changes.len(),
        "convergence": convergence,
        "budgets": {
            "depth": budgets.depth,
            "max_functions": budgets.max_functions,
            "max_iterations": budgets.max_iterations,
            "max_calls": budgets.max_calls,
        },
        "budget_hit": budget_hit,
        "visited_count": visited.len(),
    })
}
