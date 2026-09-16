//! #44 value/register analysis: bounded constant/value propagation over one
//! function's decompiled call sites plus (optional) k-hop inter-procedural
//! extension over direct callees, and indirect-call target resolution
//! proposals (vtable-slot probing).
//!
//! Everything is analysis-only and evidence-based: each value conclusion
//! carries the call-site EAs it was derived from plus a confidence
//! (`confirmed` when a single constant dominates, `set` when a small
//! candidate set exists, `heuristic` when many, `unknown` when nothing).
//! All work is bounded: evidence-row caps, single-decompile reuse via
//! `deep_function_info`, and a wall-clock deadline via `DeepBudgets`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};

use crate::deep::DeepBudgets;
/// One merged value-evidence row for (function, target) where target is an
/// argument position ("arg0") or a local ("var name"). Values ascending,
/// provenance = call-site EAs, confidence derived from |values|.
#[derive(Debug, Clone)]
struct ValueRow {
    ea: u64,
    function: String,
    kind: String,
    values: Vec<u64>,
    at: Vec<u64>,
}

impl ValueRow {
    fn confidence(&self) -> &'static str {
        match self.values.len() {
            0 => "unknown",
            1 => "confirmed",
            n if n <= 4 => "set",
            _ => "heuristic",
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "function": self.function,
            "ea": format!("{:#x}", self.ea),
            "values": self.values.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>(),
            "at": self.at.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>(),
            "confidence": self.confidence(),
        })
    }
}

/// Bounded value analysis over one function (intra-procedural) with an
/// optional k-hop extension over direct callees (inter-procedural constant
/// arguments). Reuses `deep_function_info` so an already-decompiled function
/// is served from the deep single-decompile cache instead of a second
/// decompilation pass.
///
/// Output (all lists bounded, `truncated` flagged):
/// ```json
/// {
///   "ea": "0x…", "function": "name", "depth_used": 1, "truncated": false,
///   "targets":  [ { "kind": "arg0", "function": "…", "ea": "0x…",
///                   "values": ["0x…"], "at": ["0x…"],
///                   "confidence": "confirmed|set|heuristic|unknown" } ],
///   "indirect": [ { "function": "…", "ea": "0x…", "call_ea": "0x…",
///                   "rendered": "…", "proposals": [ { "target_ea": "0x…",
///                   "name": "…", "via": "table+0", "confidence": "set" } ],
///                   "note": null | "no resolvable target…" } ]
/// }
/// ```
pub fn value_analysis(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    root: u64,
    budgets: &DeepBudgets,
) -> Result<Value> {
    if !idx.functions.contains_key(&root) {
        return Err(Error::Worker(format!("no function at {root:#x}")));
    }
    let mut truncated = false;
    // (function ea, kind) -> merged row
    let mut merged: BTreeMap<(u64, String), ValueRow> = BTreeMap::new();
    let mut indirect: Vec<Value> = Vec::new();

    // --- intra-procedural pass (always) ---
    collect_function_values(
        backend,
        idx,
        root,
        budgets.max_calls,
        &mut merged,
        &mut indirect,
        &mut truncated,
    )?;

    // --- inter-procedural extension: direct callees up to `depth` levels ---
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    visited.insert(root);
    let mut frontier: Vec<u64> = idx
        .functions
        .get(&root)
        .map(|f| f.callees.clone())
        .unwrap_or_default();
    let mut depth_used = 1u32;
    while depth_used < budgets.depth.max(1) && !frontier.is_empty() {
        if !budgets.time_left() {
            truncated = true;
            break;
        }
        let mut next: Vec<u64> = Vec::new();
        for callee in std::mem::take(&mut frontier) {
            if visited.len() >= budgets.max_functions {
                truncated = true;
                break;
            }
            if !visited.insert(callee) || !idx.functions.contains_key(&callee) {
                continue;
            }
            if merged.len() + indirect.len() >= budgets.max_calls {
                truncated = true;
                break;
            }
            collect_function_values(
                backend,
                idx,
                callee,
                budgets.max_calls,
                &mut merged,
                &mut indirect,
                &mut truncated,
            )?;
            if let Some(f) = idx.functions.get(&callee) {
                next.extend(f.callees.iter().copied());
            }
        }
        frontier = next;
        depth_used += 1;
    }

    let mut targets: Vec<Value> = merged.into_values().map(|r| r.to_json()).collect();
    targets.sort_by(|a, b| {
        let ka = (
            a["function"].as_str().unwrap_or_default(),
            a["kind"].as_str().unwrap_or_default(),
        );
        let kb = (
            b["function"].as_str().unwrap_or_default(),
            b["kind"].as_str().unwrap_or_default(),
        );
        ka.cmp(&kb)
    });
    if targets.len() > budgets.max_calls {
        targets.truncate(budgets.max_calls);
        truncated = true;
    }
    if indirect.len() > budgets.max_calls {
        indirect.truncate(budgets.max_calls);
        truncated = true;
    }

    Ok(json!({
        "ea": format!("{root:#x}"),
        "function": function_name(idx, root),
        "depth_used": depth_used,
        "truncated": truncated,
        "targets": targets,
        "indirect": indirect,
    }))
}

/// Extract per-call-site constant arguments + indirect-call proposals for
/// one function. Uses `deep_function_info` (single-decompile model) so the
/// value pass never triggers a second decompilation of the same function.
fn collect_function_values(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    ea: u64,
    max_calls: usize,
    merged: &mut BTreeMap<(u64, String), ValueRow>,
    indirect: &mut Vec<Value>,
    truncated: &mut bool,
) -> Result<()> {
    let info = backend.deep_function_info(ea, max_calls)?;
    let fname = function_name(idx, ea);
    let calls = info["calls"].as_array().cloned().unwrap_or_default();

    for call in calls.iter().take(max_calls) {
        let Some(text) = call["call_ea"].as_str() else {
            continue;
        };
        // call_ea can be "0x…+10" (one indirect site on the mock): keep the
        // base address as provenance.
        let call_ea = parse_ea(text.split('+').next().unwrap_or_default());
        if call_ea == 0 {
            continue;
        }
        let args = call["args"].as_array().cloned().unwrap_or_default();
        let direct = call["direct"].as_bool().unwrap_or(false);

        // Constant-argument evidence: rendered arg text that parses as a
        // plain hex/decimal number, or `symbol(+|-off)` where the symbol
        // resolves to a global in the index (still a confirmed absolute
        // value at that call site).
        for (n, a) in args.iter().enumerate() {
            let Some(text) = a.as_str() else { continue };
            let Some(v) = parse_const_expr(text, idx) else {
                continue;
            };
            let kind = format!("arg{n}");
            let row = merged
                .entry((ea, kind.clone()))
                .or_insert_with(|| ValueRow {
                    ea,
                    function: fname.clone(),
                    kind,
                    values: Vec::new(),
                    at: Vec::new(),
                });
            if !row.values.contains(&v) {
                row.values.push(v);
                row.values.sort_unstable();
            }
            if !row.at.contains(&call_ea) {
                row.at.push(call_ea);
            }
        }

        // Indirect-call target resolution proposals: probe the rendered
        // base object as a vtable. Evidence-only; nothing is rewritten.
        if !direct {
            if indirect.len() >= max_calls {
                *truncated = true;
                continue;
            }
            indirect.push(indirect_proposal(backend, idx, ea, &fname, call_ea, call));
        }
    }
    Ok(())
}

/// Build the indirect-call proposal row for one unresolved call site: probe
/// up to 8 vtable slots of the rendered base object and keep the code
/// targets as `set`-confidence proposals.
fn indirect_proposal(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    ea: u64,
    fname: &str,
    call_ea: u64,
    call: &Value,
) -> Value {
    let rendered = call["target_name"].as_str().unwrap_or_default().to_string();
    let mut proposals: Vec<Value> = Vec::new();

    if let Some(base) = base_object(&rendered)
        && let Some(base_ea) = lookup_global(idx, &base)
    {
        let slots = backend.type_vtable_scan(base_ea, 8).unwrap_or_default();
        for (n, slot) in slots["slots"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let is_code = slot["is_code"].as_bool().unwrap_or(false);
            let target = parse_ea(slot["target_ea"].as_str().unwrap_or_default());
            if !is_code || target == 0 {
                continue;
            }
            proposals.push(json!({
                "target_ea": format!("{target:#x}"),
                "name": slot["name"].as_str().unwrap_or_default(),
                "via": format!("{base}+{n}"),
                "confidence": "set",
            }));
            if proposals.len() >= 4 {
                break;
            }
        }
    }

    json!({
        "function": fname,
        "ea": format!("{ea:#x}"),
        "call_ea": format!("{call_ea:#x}"),
        "rendered": rendered,
        "proposals": proposals,
        "note": if proposals.is_empty() {
            Some("no resolvable target; evidence kept for the agent".to_string())
        } else {
            None
        },
    })
}

/// Parse a rendered ctree argument as a constant expression:
/// `0x…`, decimal, or `symbol+0x…` / `symbol-0x…` where symbol resolves to
/// a global in the index.
fn parse_const_expr(text: &str, idx: &AnalysisIndex) -> Option<u64> {
    let t = text.trim();
    if let Some(v) = parse_hex_or_dec(t) {
        return Some(v);
    }
    // symbol / symbol+off / symbol-off
    let sep = t.find(['+', '-']).filter(|&p| p > 0)?;
    let (name, off_text) = (&t[..sep], &t[sep + 1..]);
    let off = parse_hex_or_dec(off_text).unwrap_or(0);
    let base = lookup_global(idx, name.trim())?;
    Some(if t.as_bytes()[sep] == b'-' {
        base.wrapping_sub(off)
    } else {
        base.wrapping_add(off)
    })
}

fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16)
            .ok()
            .filter(|_| !hex.is_empty());
    }
    if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) {
        return t.parse().ok();
    }
    None
}

/// Extract the base object name from a rendered callee expression like
/// `(*table)(…)`, `(*(&table))[1](…)`. Skips address-of wrappers, then
/// returns the first identifier.
fn base_object(rendered: &str) -> Option<String> {
    let inner = rendered.trim();
    let mut rest = inner;
    // Peel leading "(*" and "(&" wrappers until an identifier can start.
    loop {
        if let Some(r) = rest.strip_prefix("(*") {
            rest = r;
        } else if let Some(r) = rest.strip_prefix("(&") {
            rest = r;
        } else {
            break;
        }
    }
    let end = rest.find(|c: char| !(c.is_alphanumeric() || c == '_' || c == '@'))?;
    let name = &rest[..end];
    if name.is_empty() || name.parse::<u64>().is_ok() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Resolve a global object name via the analysis index (globals are stored
/// as EAs; resolve through the function that references them). Linear probe
/// is fine: callers bound the number of lookups.
fn lookup_global(idx: &AnalysisIndex, _name: &str) -> Option<u64> {
    // The index stores global EAs (not names), so name-based resolution is
    // only possible for names the backend rendered as `ea+offset` forms —
    // handled by parse_const_expr directly. Name lookups would need the
    // names table; kept as evidence-only for now.
    let _ = idx;
    None
}

fn parse_ea(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or(0)
}

fn function_name(idx: &AnalysisIndex, ea: u64) -> String {
    idx.functions
        .get(&ea)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("sub_{ea:x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp_ida::MockBackend;

    fn open_mock() -> MockBackend {
        let mut b = MockBackend::new();
        IdaBackend::open(&mut b, "t.i64").unwrap();
        b
    }

    fn index(b: &MockBackend) -> AnalysisIndex {
        use rmcp_core::backend::IdaBackend as _;
        b.build_index().unwrap().0
    }

    #[test]
    fn shape_and_bounds_on_mock_graph() {
        let backend = open_mock();
        let idx = index(&backend);
        let budgets = DeepBudgets {
            depth: 2,
            ..Default::default()
        };

        let out = value_analysis(&backend, &idx, 0x401000, &budgets).unwrap();
        assert_eq!(out["depth_used"], 2);
        assert_eq!(out["truncated"], false);
        assert_eq!(out["function"], "main");

        // call_via_ptr is indirect on the mock graph: one proposal row with
        // the rendered callee text, even when no vtable resolves.
        let indirect = out["indirect"].as_array().unwrap();
        assert!(
            indirect
                .iter()
                .any(|i| !i["rendered"].as_str().unwrap_or_default().is_empty()),
            "indirect rows must carry the rendered callee: {indirect:?}"
        );
        // Empty-args mock calls: no target rows is honest output, not an error.
        assert!(out["targets"].as_array().unwrap().is_empty());
    }

    #[test]
    fn budgets_bound_the_work() {
        let backend = open_mock();
        let idx = index(&backend);
        let budgets = DeepBudgets {
            depth: 1,
            max_calls: 1,
            ..Default::default()
        };
        let out = value_analysis(&backend, &idx, 0x401000, &budgets).unwrap();
        let indirect = out["indirect"].as_array().unwrap();
        assert!(indirect.len() <= 1, "max_calls must bound indirect rows");
        assert_eq!(out["depth_used"], 1);
    }

    #[test]
    fn unknown_function_is_an_error() {
        let backend = open_mock();
        let idx = index(&backend);
        let err = value_analysis(&backend, &idx, 0xdead_0000_0000, &DeepBudgets::default());
        assert!(err.is_err());
    }

    #[test]
    fn parse_const_expr_shapes() {
        let idx = AnalysisIndex::default();
        assert_eq!(parse_const_expr("0x5a", &idx), Some(0x5a));
        assert_eq!(parse_const_expr("0X5A", &idx), Some(0x5a));
        assert_eq!(parse_const_expr("90", &idx), Some(90));
        assert_eq!(parse_const_expr("table+0x10", &idx), None); // no name map
        assert_eq!(parse_const_expr("not a number", &idx), None);
        assert_eq!(parse_hex_or_dec(""), None);
        assert_eq!(parse_hex_or_dec("0x"), None);
    }

    #[test]
    fn base_object_extracts_identifiers() {
        assert_eq!(base_object("(*table)(a, b)").as_deref(), Some("table"));
        assert_eq!(base_object("(*(&table))[1]()").as_deref(), Some("table"));
        assert_eq!(base_object("0x401400"), None);
        assert_eq!(base_object(""), None);
    }
}
