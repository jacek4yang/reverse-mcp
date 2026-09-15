//! #8 workflow engine: composite analysis workflows that replace many
//! repetitive atomic calls with one bounded, cache-aware request returning
//! compact, high-signal evidence.
//!
//! Workflows: `function_context`, `call_neighborhood`, `reference_context`,
//! `import_usage`, `subsystem_context`, `trace_call_path`.
//!
//! Every workflow takes budgets (`depth`, `max_functions`, `detail =
//! summary|normal|full`). Results are revision-keyed: repeating an unchanged
//! workflow is served from the worker-side cache; a mutation bumps the
//! revision and invalidates it. Deterministic parts of the AnalysisIndex are
//! reused instead of rescanning.

use std::collections::{BTreeMap, BTreeSet};

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Budgets and options for a workflow run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Budgets {
    #[serde(default = "default_depth")]
    pub depth: u32,
    #[serde(default = "default_max_functions")]
    pub max_functions: u32,
    #[serde(default)]
    pub detail: String,
    /// Disable CRT/library noise filtering (default: filtered).
    #[serde(default)]
    pub include_noise: bool,
}

fn default_depth() -> u32 {
    2
}
fn default_max_functions() -> u32 {
    10
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            depth: default_depth(),
            max_functions: default_max_functions(),
            detail: "summary".into(),
            include_noise: false,
        }
    }
}

/// Common runtime/library noise: functions that add no signal for an agent.
/// Heuristic, high-confidence only (thunks + well-known CRT/runtime names).
fn is_noise(name: &str) -> bool {
    let n = name.to_lowercase();
    n.starts_with("j_")
        || n.starts_with("?__")
        || n.starts_with("__scrt")
        || n.starts_with("__acrt")
        || n.starts_with("_guard")
        || n.starts_with("__report_gsfailure")
        || n.starts_with("__crt")
        || n.starts_with("__std_")
        || n == "memset"
        || n == "memcpy"
        || n == "memmove"
        || n == "memcmp"
        || n == "strcpy"
        || n == "strlen"
}

/// Parsed workflow request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRequest {
    pub workflow: String,
    #[serde(default, deserialize_with = "de_opt_ea")]
    pub ea: Option<u64>,
    #[serde(default, deserialize_with = "de_opt_ea")]
    pub target_ea: Option<u64>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "de_ea_list")]
    pub roots: Vec<u64>,
    #[serde(flatten)]
    pub budgets: Budgets,
}

/// EAs accept hex "0x.." or decimal (agents send strings over MCP).
fn de_ea<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = serde_json::Value::deserialize(deserializer)?;
    match v {
        serde_json::Value::Number(n) => {
            n.as_u64().ok_or_else(|| serde::de::Error::custom("bad ea"))
        }
        serde_json::Value::String(s) => {
            let s = s.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).map_err(serde::de::Error::custom)
            } else {
                s.parse::<u64>().map_err(serde::de::Error::custom)
            }
        }
        _ => Err(serde::de::Error::custom("bad ea value")),
    }
}

fn de_opt_ea<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(deserializer)?;
    match v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => de_ea(v).map(Some).map_err(serde::de::Error::custom),
    }
}

fn de_ea_list<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Vec::<serde_json::Value>::deserialize(deserializer)?;
    let mut out = Vec::with_capacity(v.len());
    for item in v {
        out.push(de_ea(item).map_err(serde::de::Error::custom)?);
    }
    Ok(out)
}

/// The worker-side cache: workflow result keyed by a canonical request hash
/// + DB revision. One entry per distinct request.
#[derive(Default)]
pub struct WorkflowCache {
    entries: BTreeMap<(String, String, u64), Value>,
    /// Requests served from cache (metrics for the benchmark).
    pub hits: u64,
    /// Requests that needed a fresh run.
    pub misses: u64,
}

impl WorkflowCache {
    pub fn get(&mut self, key: &(String, String, u64)) -> Option<Value> {
        if let Some(v) = self.entries.get(key).cloned() {
            self.hits += 1;
            Some(v)
        } else {
            self.misses += 1;
            None
        }
    }

    pub fn put(&mut self, key: (String, String, u64), value: Value) {
        self.entries.insert(key, value);
    }

    /// Invalidate everything (any mutation invalidates: workflows touch
    /// names, xrefs, and code alike).
    pub fn invalidate_all(&mut self) {
        self.entries.clear();
    }
}

/// Canonical cache key: workflow + normalized request JSON + revision.
pub fn cache_key(req: &WorkflowRequest, revision: u64) -> (String, String, u64) {
    let mut norm = serde_json::to_value(req).unwrap_or(json!({}));
    if let Some(obj) = norm.as_object_mut() {
        obj.remove("budgets");
    }
    let body = serde_json::to_string(&norm).unwrap_or_default();
    (req.workflow.clone(), body, revision)
}

/// Resolve a function EA by name via the index; None if not found.
fn find_by_name(idx: &AnalysisIndex, name: &str) -> Option<u64> {
    let needle = name.to_lowercase();
    idx.functions
        .values()
        .find(|f| f.name.to_lowercase() == needle || f.demangled.to_lowercase() == needle)
        .map(|f| f.ea_start)
}

fn function_name(idx: &AnalysisIndex, ea: u64) -> String {
    idx.functions
        .get(&ea)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("sub_{ea:x}"))
}

/// Noise filter over a set of function EAs (uses index names).
fn filter_noise(idx: &AnalysisIndex, eas: &mut Vec<u64>, include_noise: bool) {
    if include_noise {
        return;
    }
    eas.retain(|ea| {
        idx.functions
            .get(ea)
            .map(|f| !is_noise(&f.name))
            .unwrap_or(true)
    });
}

/// Run a workflow against the backend + index. All outputs are bounded by
/// the budgets; large decompilations spill through the caller's result
/// store (the worker layer wraps `detail=full` content).
pub fn run(backend: &dyn IdaBackend, idx: &AnalysisIndex, req: &WorkflowRequest) -> Result<Value> {
    let detail_full = req.budgets.detail == "full";
    let max_functions = req.budgets.max_functions.clamp(1, 50) as usize;
    match req.workflow.as_str() {
        "function_context" => function_context(backend, idx, req, detail_full),
        "call_neighborhood" => call_neighborhood(backend, idx, req, max_functions),
        "reference_context" => reference_context(backend, idx, req, max_functions),
        "import_usage" => import_usage(idx, req, max_functions),
        "subsystem_context" => subsystem_context(backend, idx, req, max_functions),
        "trace_call_path" => trace_call_path(idx, req),
        other => Err(Error::Worker(format!(
            "unknown workflow '{other}' (function_context|call_neighborhood|\
             reference_context|import_usage|subsystem_context|trace_call_path)"
        ))),
    }
}

/// Decompile + prototype + callers/callees + xrefs + strings + constants +
/// imports for one function.
fn function_context(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    req: &WorkflowRequest,
    detail_full: bool,
) -> Result<Value> {
    let ea = req
        .ea
        .or_else(|| req.name.as_deref().and_then(|n| find_by_name(idx, n)))
        .ok_or_else(|| Error::Worker("function_context requires 'ea' or 'name'".into()))?;
    let facts = idx
        .functions
        .get(&ea)
        .ok_or_else(|| Error::Worker(format!("no function at {ea:#x}")))?;

    let decompile = if detail_full {
        backend
            .decompile(ea)
            .unwrap_or(json!({"unavailable": true}))
    } else {
        json!(null)
    };

    let callers: Vec<Value> = facts
        .callers
        .iter()
        .map(|c| json!({"ea": format!("{c:#x}"), "name": function_name(idx, *c)}))
        .collect();
    let callees: Vec<Value> = facts
        .callees
        .iter()
        .map(|c| json!({"ea": format!("{c:#x}"), "name": function_name(idx, *c)}))
        .collect();

    let xrefs_to = backend
        .xrefs_to(ea)?
        .into_iter()
        .take(50)
        .map(|x| json!({"from": format!("{:#x}", x.from), "kind": x.kind}))
        .collect::<Vec<_>>();

    Ok(json!({
        "ea": format!("{ea:#x}"),
        "name": facts.name,
        "prototype_hint": {
            "imports_called": facts.imports,
            "indirect_calls": facts.indirect_calls,
        },
        "strings": facts.strings,
        "constants": facts.constants.iter().map(|c| format!("{c:#x}")).collect::<Vec<_>>(),
        "callers": callers,
        "callees": callees,
        "xrefs_to": xrefs_to,
        "decompile": decompile,
        "detail": req.budgets.detail,
    }))
}

/// BFS around a function through call edges, noise-filtered.
fn call_neighborhood(
    _backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    req: &WorkflowRequest,
    max_functions: usize,
) -> Result<Value> {
    let ea = req
        .ea
        .or_else(|| req.name.as_deref().and_then(|n| find_by_name(idx, n)))
        .ok_or_else(|| Error::Worker("call_neighborhood requires 'ea' or 'name'".into()))?;
    if !idx.functions.contains_key(&ea) {
        return Err(Error::Worker(format!("no function at {ea:#x}")));
    }
    let mut visited = BTreeSet::new();
    visited.insert(ea);
    let mut frontier = vec![ea];
    let mut edges: Vec<Value> = Vec::new();
    for _ in 0..req.budgets.depth {
        let mut next = Vec::new();
        for cur in &frontier {
            let Some(f) = idx.functions.get(cur) else {
                continue;
            };
            let mut callees = f.callees.clone();
            filter_noise(idx, &mut callees, req.budgets.include_noise);
            for c in callees {
                if visited.len() >= max_functions {
                    break;
                }
                if visited.insert(c) {
                    next.push(c);
                }
                edges.push(json!({
                    "from": format!("{cur:#x}"),
                    "to": format!("{c:#x}"),
                    "to_name": function_name(idx, c),
                }));
            }
            if visited.len() >= max_functions {
                break;
            }
        }
        frontier = next;
        if visited.len() >= max_functions {
            break;
        }
    }
    let functions: Vec<Value> = visited
        .iter()
        .map(|ea| {
            let f = idx.functions.get(ea);
            json!({
                "ea": format!("{ea:#x}"),
                "name": f.map(|f| f.name.clone()).unwrap_or_default(),
                "strings": f.map(|f| f.strings.clone()).unwrap_or_default(),
                "imports": f.map(|f| f.imports.clone()).unwrap_or_default(),
            })
        })
        .collect();
    Ok(json!({
        "root": format!("{ea:#x}"),
        "depth": req.budgets.depth,
        "functions": functions,
        "edges": edges,
        "truncated": visited.len() >= max_functions,
    }))
}

/// Target -> xrefs -> containing functions -> pseudocode snippets -> callers.
fn reference_context(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    req: &WorkflowRequest,
    max_functions: usize,
) -> Result<Value> {
    let ea = req
        .ea
        .ok_or_else(|| Error::Worker("reference_context requires 'ea'".into()))?;
    let xrefs = backend.xrefs_to(ea)?;
    let mut items = Vec::new();
    let mut seen_fns = BTreeSet::new();
    for x in xrefs.iter().take(100) {
        let from = x.from;
        let Some(f) = idx.functions.range(..=from).next_back() else {
            continue;
        };
        let (f_ea, facts) = (f.0, f.1);
        if !seen_fns.insert(*f_ea) || seen_fns.len() > max_functions {
            continue;
        }
        // One snippet line from the decompilation (bounded).
        let snippet = if req.budgets.detail != "summary" {
            backend.decompile(*f_ea).ok().and_then(|d| {
                d["pseudocode"]
                    .as_str()
                    .map(|s| s.chars().take(400).collect::<String>())
            })
        } else {
            None
        };
        items.push(json!({
            "xref_from": format!("{from:#x}"),
            "kind": x.kind,
            "function": {"ea": format!("{f_ea:#x}"), "name": facts.name},
            "callers": facts.callers.iter().map(|c| format!("{c:#x}")).collect::<Vec<_>>(),
            "snippet": snippet,
        }));
    }
    Ok(json!({
        "target": format!("{ea:#x}"),
        "references": items,
        "truncated": items.len() >= max_functions,
    }))
}

/// Import/API -> call sites -> containing functions -> upper callers.
fn import_usage(idx: &AnalysisIndex, req: &WorkflowRequest, max_functions: usize) -> Result<Value> {
    let name = req
        .name
        .as_deref()
        .ok_or_else(|| Error::Worker("import_usage requires 'name'".into()))?;
    let mut sites = Vec::new();
    for f in idx.functions.values() {
        if f.imports.iter().any(|i| {
            i.eq_ignore_ascii_case(name) || i.to_lowercase().contains(&name.to_lowercase())
        }) {
            sites.push(json!({
                "function": {"ea": format!("{:#x}", f.ea_start), "name": f.name},
                "callers": f.callers.iter().map(|c| format!("{c:#x}")).collect::<Vec<_>>(),
            }));
            if sites.len() >= max_functions {
                break;
            }
        }
    }
    Ok(json!({
        "import": name,
        "sites": sites,
        "truncated": sites.len() >= max_functions,
    }))
}

/// Bounded multi-function analysis from one or more roots (like
/// call_neighborhood but collecting deeper facts per function).
fn subsystem_context(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    req: &WorkflowRequest,
    max_functions: usize,
) -> Result<Value> {
    let roots = if !req.roots.is_empty() {
        req.roots.clone()
    } else if let Some(ea) = req.ea {
        vec![ea]
    } else {
        return Err(Error::Worker(
            "subsystem_context requires 'roots' (array of EAs) or 'ea'".into(),
        ));
    };
    for r in &roots {
        if !idx.functions.contains_key(r) {
            return Err(Error::Worker(format!("no function at {r:#x}")));
        }
    }
    let mut visited = BTreeSet::new();
    let mut frontier = roots.clone();
    for ea in &roots {
        visited.insert(*ea);
    }
    let mut edges: Vec<Value> = Vec::new();
    for _ in 0..req.budgets.depth {
        let mut next = Vec::new();
        for cur in &frontier {
            let Some(f) = idx.functions.get(cur) else {
                continue;
            };
            let mut callees = f.callees.clone();
            filter_noise(idx, &mut callees, req.budgets.include_noise);
            for c in callees {
                if visited.len() >= max_functions {
                    break;
                }
                if visited.insert(c) {
                    next.push(c);
                }
                edges.push(json!({"from": format!("{cur:#x}"), "to": format!("{c:#x}")}));
            }
        }
        frontier = next;
    }
    let mut functions = Vec::new();
    for ea in visited.iter().take(max_functions) {
        let Some(f) = idx.functions.get(ea) else {
            continue;
        };
        let decomp = if req.budgets.detail == "normal" || req.budgets.detail == "full" {
            backend.decompile(*ea).ok().and_then(|d| {
                d["pseudocode"]
                    .as_str()
                    .map(|s| s.chars().take(600).collect::<String>())
            })
        } else {
            None
        };
        functions.push(json!({
            "ea": format!("{ea:#x}"),
            "name": f.name,
            "strings": f.strings,
            "imports": f.imports,
            "constants": f.constants.iter().map(|c| format!("{c:#x}")).collect::<Vec<_>>(),
            "pseudocode_snippet": decomp,
        }));
    }
    Ok(json!({
        "roots": roots.iter().map(|r| format!("{r:#x}")).collect::<Vec<_>>(),
        "functions": functions,
        "edges": edges,
        "truncated": visited.len() > max_functions,
    }))
}

/// Find call paths between two functions/APIs (BFS up to depth, bounded).
fn trace_call_path(idx: &AnalysisIndex, req: &WorkflowRequest) -> Result<Value> {
    let from = req
        .ea
        .or_else(|| req.name.as_deref().and_then(|n| find_by_name(idx, n)))
        .ok_or_else(|| Error::Worker("trace_call_path requires 'ea' (source)".into()))?;
    let to = req
        .target_ea
        .or_else(|| req.roots.first().copied())
        .ok_or_else(|| {
            Error::Worker("trace_call_path requires 'target_ea' (destination)".into())
        })?;
    // BFS storing parents.
    let mut parents: BTreeMap<u64, u64> = BTreeMap::new();
    parents.insert(from, from);
    let mut frontier = vec![from];
    let mut found = false;
    for _ in 0..req.budgets.depth {
        let mut next = Vec::new();
        for cur in &frontier {
            if *cur == to {
                found = true;
                break;
            }
            let Some(f) = idx.functions.get(cur) else {
                continue;
            };
            for c in &f.callees {
                if !parents.contains_key(c) {
                    parents.insert(*c, *cur);
                    next.push(*c);
                }
            }
        }
        if found {
            break;
        }
        frontier = next;
    }
    if !parents.contains_key(&to) {
        return Ok(json!({
            "from": format!("{from:#x}"),
            "to": format!("{to:#x}"),
            "path": [],
            "found": false,
        }));
    }
    let _ = found;
    // Reconstruct.
    let mut path = vec![to];
    let mut cur = to;
    while cur != from {
        cur = parents[&cur];
        path.push(cur);
    }
    path.reverse();
    let path: Vec<Value> = path
        .iter()
        .map(|ea| json!({"ea": format!("{ea:#x}"), "name": function_name(idx, *ea)}))
        .collect();
    Ok(json!({
        "from": format!("{from:#x}"),
        "to": format!("{to:#x}"),
        "path": path,
        "found": true,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp_core::analysis_index::FunctionFacts;
    use rmcp_ida::MockBackend;

    fn index_for_mock() -> AnalysisIndex {
        let b = MockBackend::new();
        let (idx, _) = b.build_index().unwrap();
        idx
    }

    #[test]
    fn function_context_summary_has_no_decompile() {
        let mut b = MockBackend::new();
        b.open("t.i64").unwrap();
        let idx = index_for_mock();
        let req = WorkflowRequest {
            workflow: "function_context".into(),
            ea: Some(0x401000),
            target_ea: None,
            name: None,
            roots: vec![],
            budgets: Budgets::default(),
        };
        let out = run(&b, &idx, &req).unwrap();
        assert_eq!(out["name"], "main");
        assert!(out["decompile"].is_null(), "summary must omit decompile");
        assert!(out["callees"].as_array().is_some());
    }

    #[test]
    fn budgets_are_clamped() {
        let mut b = MockBackend::new();
        b.open("t.i64").unwrap();
        let idx = index_for_mock();
        let req = WorkflowRequest {
            workflow: "call_neighborhood".into(),
            ea: Some(0x401000),
            target_ea: None,
            name: None,
            roots: vec![],
            budgets: Budgets {
                depth: 10,
                max_functions: 9999,
                detail: "summary".into(),
                include_noise: false,
            },
        };
        let out = run(&b, &idx, &req).unwrap();
        // max_functions clamps to 50.
        assert!(out["functions"].as_array().unwrap().len() <= 50);
    }

    #[test]
    fn cache_key_changes_with_revision() {
        let req = WorkflowRequest {
            workflow: "function_context".into(),
            ea: Some(1),
            target_ea: None,
            name: None,
            roots: vec![],
            budgets: Budgets::default(),
        };
        let k1 = cache_key(&req, 1);
        let k2 = cache_key(&req, 2);
        assert_ne!(k1, k2, "revision bump must change the cache key");
    }

    #[test]
    fn workflow_cache_hit_and_invalidation() {
        let mut cache = WorkflowCache::default();
        let req = WorkflowRequest {
            workflow: "function_context".into(),
            ea: Some(1),
            target_ea: None,
            name: None,
            roots: vec![],
            budgets: Budgets::default(),
        };
        let key = cache_key(&req, 1);
        assert!(cache.get(&key).is_none());
        cache.put(key.clone(), json!({"cached": true}));
        assert!(cache.get(&key).is_some());
        assert_eq!(cache.hits, 1);
        // A mutation invalidates everything.
        cache.invalidate_all();
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.misses, 2);
    }

    #[test]
    fn noise_filter_drops_thunks() {
        let mut idx = AnalysisIndex::default();
        idx.functions.insert(
            1,
            FunctionFacts {
                ea_start: 1,
                name: "j_memset".into(),
                ..Default::default()
            },
        );
        let mut eas = vec![1];
        filter_noise(&idx, &mut eas, false);
        assert!(eas.is_empty(), "thunks must be filtered");
        let mut eas = vec![1];
        filter_noise(&idx, &mut eas, true);
        assert_eq!(eas.len(), 1, "include_noise keeps everything");
    }

    #[test]
    fn trace_call_path_finds_route() {
        let mut idx = AnalysisIndex::default();
        for (ea, callees, name) in [
            (0x1000u64, vec![0x2000u64], "main"),
            (0x2000, vec![0x3000], "mid"),
            (0x3000, vec![], "sink"),
        ] {
            idx.functions.insert(
                ea,
                FunctionFacts {
                    ea_start: ea,
                    callees,
                    name: name.into(),
                    ..Default::default()
                },
            );
        }
        let req = WorkflowRequest {
            workflow: "trace_call_path".into(),
            ea: Some(0x1000),
            target_ea: Some(0x3000),
            name: None,
            roots: vec![0x3000],
            budgets: Budgets::default(),
        };
        let out = run(&MockBackend::new(), &idx, &req).unwrap();
        assert_eq!(out["found"], true);
        let path = out["path"].as_array().unwrap();
        assert_eq!(path.len(), 3, "path: {out}");
    }

    #[test]
    fn unknown_workflow_rejected() {
        let idx = AnalysisIndex::default();
        let req = WorkflowRequest {
            workflow: "explode".into(),
            ea: None,
            target_ea: None,
            name: None,
            roots: vec![],
            budgets: Budgets::default(),
        };
        let err = run(&MockBackend::new(), &idx, &req).unwrap_err();
        assert!(err.to_string().contains("unknown workflow"));
    }
}
