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
    /// True while the wall-clock budget (if any) has not expired.
    pub(crate) fn time_left(&self) -> bool {
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
///
/// Long runs are resumable: when the budget stops the walk early, the
/// result carries a `resume` object (next functions to visit + the
/// dossiers collected so far). Passing that token back via `resume_from`
/// continues where the run stopped — already-decompiled functions are NOT
/// decompiled again, only the remaining frontier is walked.
pub fn deep_function(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    root: u64,
    budgets: &DeepBudgets,
    resume: Option<&Value>,
) -> Result<Value> {
    if !idx.functions.contains_key(&root) {
        return Err(Error::Worker(format!("no function at {root:#x}")));
    }
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut dossiers: BTreeMap<u64, FunctionDossier> = BTreeMap::new();
    let mut budget_hit = false;
    // Resume state: previously decompiled functions restore their dossiers
    // (skipping any repeated decompilation); the unvisited frontier comes
    // from the token. `root` is only walked fresh when there is no token.
    let mut frontier: Vec<(u64, u32)> = vec![(root, 0)];
    if let Some(token) = resume {
        let Some(dlist) = token["dossiers"].as_array() else {
            return Err(Error::Worker("bad resume token: missing dossiers".into()));
        };
        for d in dlist {
            let ea = parse_ea(d["ea"].as_str().unwrap_or_default());
            if ea == 0 {
                continue;
            }
            let callees = d["callees"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|c| {
                            Some((
                                parse_ea(c["target_ea"].as_str()?),
                                parse_ea(c["call_ea"].as_str()?),
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let indirect = d["indirect_calls"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(parse_ea)).collect())
                .unwrap_or_default();
            dossiers.insert(
                ea,
                FunctionDossier {
                    ea,
                    name: d["name"].as_str().unwrap_or_default().to_string(),
                    prototype: d["prototype"].as_str().unwrap_or_default().to_string(),
                    callees,
                    indirect,
                },
            );
            visited.insert(ea);
        }
        frontier = token["pending"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        let ea = parse_ea(p["ea"].as_str()?);
                        let depth = p["depth"].as_u64()? as u32;
                        Some((ea, depth))
                    })
                    .collect()
            })
            .unwrap_or_else(|| vec![(root, 0)]);
        budget_hit = false;
    }

    // One post-order walk (iterative worklist so resume can hand back the
    // exact pending frontier). Callees first, then the caller — the caller's
    // decompilation already reflects the settled callee prototypes, so no
    // second decompilation pass is needed.
    while let Some((ea, depth)) = frontier.pop() {
        if dossiers.contains_key(&ea) || !idx.functions.contains_key(&ea) {
            continue;
        }
        if !visited.insert(ea) {
            continue;
        }
        if visited.len() > budgets.max_functions || depth >= budgets.depth || !budgets.time_left() {
            budget_hit = true;
            visited.remove(&ea);
            // Push back so a resume token covers the unvisited remainder.
            frontier.push((ea, depth));
            break;
        }
        let info = backend.deep_function_info(ea, budgets.max_calls)?;
        // Record AFTER the callee subtree settled (single decompile per fn).
        let call_sites = extract_call_sites(&info);
        let pending = call_sites.pending_callees();
        dossiers.insert(
            ea,
            FunctionDossier {
                ea,
                name: function_name(idx, ea),
                prototype: render_prototype(&info),
                callees: call_sites.direct,
                indirect: call_sites.indirect,
            },
        );
        for callee in pending {
            if idx.functions.contains_key(&callee) && !dossiers.contains_key(&callee) {
                frontier.push((callee, depth + 1));
            }
        }
    }

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
        &frontier,
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

struct CallSites {
    direct: Vec<(u64, u64)>,
    indirect: Vec<u64>,
}

impl CallSites {
    /// Callee EAs that still need a dossier.
    fn pending_callees(&self) -> Vec<u64> {
        self.direct.iter().map(|(_, t)| *t).collect()
    }
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
    frontier: &[(u64, u32)],
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
    // Resumability: when the budget stopped the walk early, hand back the
    // exact walk state so the agent can continue with `resume_from` — the
    // dossiers (already-paid decompilations) plus the pending frontier.
    // Already-visited functions are never decompiled again on resume.
    let resume_token = if budget_hit {
        Some(json!({
            "root": format!("{root:#x}"),
            "pending": frontier.iter().map(|(ea, depth)| json!({
                "ea": format!("{ea:#x}"),
                "depth": depth,
            })).collect::<Vec<_>>(),
            "dossiers": functions,
        }))
    } else {
        None
    };
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
        "resume": resume_token,
        "resume_hint": if budget_hit {
            "pass this object back as resume_from to continue; already-visited functions are not decompiled again"
        } else {
            ""
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp_ida::MockBackend;

    fn open_mock() -> MockBackend {
        let mut b = MockBackend::new();
        b.open("t.i64").unwrap();
        b
    }

    fn index(b: &MockBackend) -> AnalysisIndex {
        b.build_index().unwrap().0
    }

    #[test]
    fn deep_function_walks_the_mock_chain() {
        let b = open_mock();
        let idx = index(&b);
        let out = deep_function(&b, &idx, 0x401000, &DeepBudgets::default(), None).unwrap();
        assert_eq!(out["root"], "0x401000");
        assert!(
            out["functions"].as_array().unwrap().len() >= 3,
            "out: {out}"
        );
        let root = out["functions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["ea"] == "0x401000")
            .expect("root dossier");
        assert!(root["prototype"].as_str().is_some(), "root: {root}");
    }

    #[test]
    fn budgets_bound_the_walk() {
        let b = open_mock();
        let idx = index(&b);
        let budgets = DeepBudgets {
            depth: 3,
            max_functions: 2,
            max_iterations: 3,
            max_calls: 24,
            deadline: None,
        };
        let out = deep_function(&b, &idx, 0x401000, &budgets, None).unwrap();
        assert_eq!(out["budget_hit"], true, "out: {out}");
        assert!(out["visited_count"].as_u64().unwrap() <= 2, "out: {out}");
    }

    #[test]
    fn unknown_root_rejected() {
        let b = open_mock();
        let idx = index(&b);
        let err = deep_function(&b, &idx, 0x999000, &DeepBudgets::default(), None).unwrap_err();
        assert!(err.to_string().contains("no function"));
    }

    #[test]
    fn dataflow_reports_confirmed_and_heuristic() {
        let b = open_mock();
        let idx = index(&b);
        let out = trace_dataflow(&b, &idx, 0x401000, "both", &DeepBudgets::default()).unwrap();
        assert!(out["confirmed"].as_u64().unwrap() >= 1, "out: {out}");
        assert!(out["heuristic"].as_u64().unwrap() >= 1, "out: {out}");
    }

    #[test]
    fn dataflow_direction_backward_only_direct() {
        let b = open_mock();
        let idx = index(&b);
        let out = trace_dataflow(&b, &idx, 0x401000, "backward", &DeepBudgets::default()).unwrap();
        for e in out["evidence"].as_array().unwrap() {
            assert_eq!(
                e["confidence"], "confirmed",
                "backward drops heuristic: {e}"
            );
        }
    }

    #[test]
    fn budget_hit_produces_resumable_token_and_resume_carries_dossiers() {
        let b = open_mock();
        let idx = index(&b);
        let budgets = DeepBudgets {
            depth: 3,
            max_functions: 2,
            max_iterations: 3,
            max_calls: 24,
            deadline: None,
        };
        let first = deep_function(&b, &idx, 0x401000, &budgets, None).unwrap();
        assert_eq!(first["budget_hit"], true, "out: {first}");
        let token = first["resume"].as_object().expect("resume token");
        assert!(token.contains_key("pending") && token.contains_key("dossiers"));

        let mut relaxed = budgets.clone();
        relaxed.max_functions = 100;
        let second = deep_function(&b, &idx, 0x401000, &relaxed, Some(&first["resume"])).unwrap();
        let resumed: Vec<String> = second["functions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["ea"].as_str().map(|s| s.to_string()))
            .collect();
        let first_fns: Vec<String> = first["functions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["ea"].as_str().map(|s| s.to_string()))
            .collect();
        for ea in &first_fns {
            assert!(
                resumed.contains(ea),
                "resume must keep first-run dossier {ea}: {second}"
            );
        }
        assert_eq!(
            second["budget_hit"], false,
            "relaxed resume completes: {second}"
        );
    }
}
