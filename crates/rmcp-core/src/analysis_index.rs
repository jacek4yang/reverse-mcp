//! #14 AnalysisIndex: a database-wide, revision-aware reverse-engineering
//! index with structured evidence queries.
//!
//! Built once per (binary identity, DB revision, index schema version) and
//! persisted under the reverse-mcp cache dir — never inside IDA's own
//! directories. Corrupt or stale cache files fail safely: the index simply
//! rebuilds.
//!
//! Queries are deterministic structured predicates (no embeddings). Every
//! hit carries concrete matched evidence; the score is a count-derived rank
//! (never an opaque number).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Bump when the persisted format changes; caches with a different version
/// are discarded and rebuilt.
pub const INDEX_SCHEMA_VERSION: u32 = 1;

/// One indexed function and the facts we can query against.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionFacts {
    pub ea_start: u64,
    pub ea_end: u64,
    pub name: String,
    /// Normalized demangled name when available (empty otherwise).
    pub demangled: String,
    pub size: u64,
    /// Import names called by this function (direct + resolved PLAT stubs).
    pub imports: Vec<String>,
    /// Strings referenced by this function (deduplicated).
    pub strings: Vec<String>,
    /// Constants (immediates >= 0x10000 or well-known crypto tables members).
    pub constants: Vec<u64>,
    /// Count of indirect calls inside the function.
    pub indirect_calls: u32,
    /// Direct callees (function start EAs).
    pub callees: Vec<u64>,
    /// Callers (function start EAs).
    pub callers: Vec<u64>,
    /// Distinct global data EAs touched.
    pub globals: Vec<u64>,
}

/// The full index for one database.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisIndex {
    pub schema_version: u32,
    /// Identity of the analyzed input (md5 of the input file).
    pub binary_md5: String,
    /// DB revision at build time.
    pub revision: u64,
    /// Keyed by function start EA.
    pub functions: BTreeMap<u64, FunctionFacts>,
    /// Global strings with the functions that reference them.
    pub strings: Vec<IndexedString>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IndexedString {
    pub ea: u64,
    pub text: String,
    /// Functions referencing this string (start EAs).
    pub refs: Vec<u64>,
}

/// Structured predicate. `all` = AND of predicates; `any` = OR; `not` = negation.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Predicate {
    /// Function (or its demangled name) contains this substring.
    NameContains(String),
    /// Function calls this import (exact name, case-insensitive).
    Import(String),
    /// Function references a string containing this substring.
    StringContains(String),
    /// Function contains at least this many indirect calls.
    HasIndirectCalls { min: u32 },
    /// Function references this exact constant.
    Constant(u64),
    /// Function calls a function that matches the inner predicate
    /// (one call level).
    CalleeMatches(Box<Predicate>),
    /// Function is called by a function matching the inner predicate.
    CallerMatches(Box<Predicate>),
    /// AND of the inner predicates.
    All(Vec<Predicate>),
    /// OR of the inner predicates.
    Any(Vec<Predicate>),
    /// Negation.
    Not(Box<Predicate>),
    /// Function is referenced (directly or transitively) from `root_ea`
    /// within `levels` call levels.
    ReachableFrom { root_ea: u64, levels: u32 },
}

impl Predicate {
    fn matches(&self, f: &FunctionFacts, idx: &AnalysisIndex) -> Option<Vec<String>> {
        match self {
            Predicate::NameContains(needle) => {
                let needle = needle.to_lowercase();
                if f.name.to_lowercase().contains(&needle)
                    || f.demangled.to_lowercase().contains(&needle)
                {
                    Some(vec![format!("name:{}", f.name)])
                } else {
                    None
                }
            }
            Predicate::Import(name) => {
                let hits: Vec<String> = f
                    .imports
                    .iter()
                    .filter(|i| i.eq_ignore_ascii_case(name))
                    .map(|i| format!("import:{i}"))
                    .collect();
                (!hits.is_empty()).then_some(hits)
            }
            Predicate::StringContains(needle) => {
                let needle = needle.to_lowercase();
                let hits: Vec<String> = f
                    .strings
                    .iter()
                    .filter(|s| s.to_lowercase().contains(&needle))
                    .map(|s| format!("string:{s}"))
                    .collect();
                (!hits.is_empty()).then_some(hits)
            }
            Predicate::HasIndirectCalls { min } => (f.indirect_calls >= *min)
                .then(|| vec![format!("indirect_calls:{}", f.indirect_calls)]),
            Predicate::Constant(v) => f
                .constants
                .contains(v)
                .then(|| vec![format!("constant:{v:#x}")]),
            Predicate::CalleeMatches(inner) => {
                for callee_ea in &f.callees {
                    if let Some(mut ev) = idx
                        .functions
                        .get(callee_ea)
                        .and_then(|callee| inner.matches(callee, idx))
                    {
                        ev.insert(0, format!("callee:{callee_ea:#x}"));
                        return Some(ev);
                    }
                }
                None
            }
            Predicate::CallerMatches(inner) => {
                for caller_ea in &f.callers {
                    if let Some(mut ev) = idx
                        .functions
                        .get(caller_ea)
                        .and_then(|caller| inner.matches(caller, idx))
                    {
                        ev.insert(0, format!("caller:{caller_ea:#x}"));
                        return Some(ev);
                    }
                }
                None
            }
            Predicate::All(inner) => {
                let mut ev = Vec::new();
                for p in inner {
                    ev.extend(p.matches(f, idx)?);
                }
                Some(ev)
            }
            Predicate::Any(inner) => {
                for p in inner {
                    if let Some(ev) = p.matches(f, idx) {
                        return Some(ev);
                    }
                }
                None
            }
            Predicate::Not(inner) => {
                if inner.matches(f, idx).is_none() {
                    Some(vec!["not:<predicate>".to_string()])
                } else {
                    None
                }
            }
            Predicate::ReachableFrom { root_ea, levels } => {
                if reachable(idx, *root_ea, *levels, f.ea_start) {
                    Some(vec![format!(
                        "reachable_from:{root_ea:#x} within {levels} levels"
                    )])
                } else {
                    None
                }
            }
        }
    }
}

/// Breadth-first reachability from `root` within `levels` call edges.
fn reachable(idx: &AnalysisIndex, root: u64, levels: u32, target: u64) -> bool {
    let mut frontier = vec![root];
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(root);
    for _ in 0..levels {
        let mut next = Vec::new();
        for ea in &frontier {
            if let Some(f) = idx.functions.get(ea) {
                for c in &f.callees {
                    if *c == target {
                        return true;
                    }
                    if seen.insert(*c) {
                        next.push(*c);
                    }
                }
            }
        }
        frontier = next;
    }
    false
}

/// A query: predicate tree + result bounds.
#[derive(Debug, Clone, Deserialize)]
pub struct EvidenceQuery {
    pub all: Option<Vec<Predicate>>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    20
}

/// One search hit with explainable evidence.
#[derive(Debug, Serialize)]
pub struct EvidenceHit {
    pub function: String,
    pub ea_start: u64,
    pub ea_end: u64,
    /// Evidence-derived rank: number of matched evidence items. Not opaque.
    pub score: usize,
    pub matched: Vec<String>,
}

impl AnalysisIndex {
    /// Query the index. The planner enforces the limit; output stays bounded.
    pub fn query(&self, q: &EvidenceQuery) -> Vec<EvidenceHit> {
        let mut hits: Vec<EvidenceHit> = Vec::new();
        let limit = q.limit.clamp(1, 1000);
        let predicates: Vec<Predicate> = q.all.clone().unwrap_or_default();
        for f in self.functions.values() {
            let mut matched = Vec::new();
            let mut ok = true;
            for p in &predicates {
                match p.matches(f, self) {
                    Some(ev) => matched.extend(ev),
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok && !matched.is_empty() {
                hits.push(EvidenceHit {
                    function: f.name.clone(),
                    ea_start: f.ea_start,
                    ea_end: f.ea_end,
                    score: matched.len(),
                    matched,
                });
            }
            if hits.len() >= limit {
                break;
            }
        }
        // Higher evidence count first.
        hits.sort_by_key(|h| std::cmp::Reverse(h.score));
        hits
    }

    /// Persist under `<cache_dir>/analysis-index/`. Keyed by binary identity
    /// + revision + schema version; safe on corrupt files (rebuild).
    pub fn save(&self, cache_dir: &std::path::Path, _md5: &str) -> std::io::Result<PathBuf> {
        let dir = cache_dir.join("analysis-index");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!(
            "{}-rev{}-v{}.json",
            self.binary_md5, self.revision, self.schema_version
        ));
        let data = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        std::fs::write(&path, data)?;
        Ok(path)
    }

    /// Load a cache file. Returns None on any problem (missing, corrupt,
    /// stale schema) so the caller rebuilds — never panics on bad input.
    pub fn load(cache_dir: &std::path::Path, md5: &str, revision: u64) -> Option<Self> {
        let path = cache_dir
            .join("analysis-index")
            .join(format!("{md5}-rev{revision}-v{INDEX_SCHEMA_VERSION}.json"));
        Self::load_from(cache_dir, &path)
    }

    /// Load one specific cache file; None on any problem.
    pub fn load_from(_cache_dir: &std::path::Path, path: &std::path::Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        let idx: AnalysisIndex = serde_json::from_slice(&data).ok()?;
        (idx.schema_version == INDEX_SCHEMA_VERSION).then_some(idx)
    }

    /// Summary for the agent (bounded).
    pub fn summary(&self) -> serde_json::Value {
        json!({
            "schema_version": self.schema_version,
            "binary_md5": self.binary_md5,
            "revision": self.revision,
            "functions": self.functions.len(),
            "strings": self.strings.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture_index() -> AnalysisIndex {
        let mut idx = AnalysisIndex {
            schema_version: INDEX_SCHEMA_VERSION,
            binary_md5: "abc".into(),
            revision: 3,
            functions: BTreeMap::new(),
            strings: Vec::new(),
        };
        idx.functions.insert(
            0x401000,
            FunctionFacts {
                ea_start: 0x401000,
                ea_end: 0x401100,
                name: "crypto_decrypt".into(),
                imports: vec!["VirtualAlloc".into(), "CryptDecrypt".into()],
                strings: vec!["payload".into()],
                constants: vec![0x63636363],
                indirect_calls: 2,
                callees: vec![0x402000],
                ..Default::default()
            },
        );
        idx.functions.insert(
            0x402000,
            FunctionFacts {
                ea_start: 0x402000,
                name: "net_send".into(),
                imports: vec!["send".into()],
                ..Default::default()
            },
        );
        idx.functions.insert(
            0x403000,
            FunctionFacts {
                ea_start: 0x403000,
                name: "main".into(),
                callees: vec![0x401000],
                ..Default::default()
            },
        );
        idx
    }

    fn q(predicates: Vec<Predicate>) -> EvidenceQuery {
        EvidenceQuery {
            all: Some(predicates),
            limit: 20,
        }
    }

    #[test]
    fn import_and_indirect_call_query() {
        let idx = fixture_index();
        let hits = idx.query(&q(vec![
            Predicate::Import("VirtualAlloc".into()),
            Predicate::HasIndirectCalls { min: 1 },
        ]));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function, "crypto_decrypt");
        assert!(hits[0].matched.iter().any(|m| m == "import:VirtualAlloc"));
        assert!(
            hits[0]
                .matched
                .iter()
                .any(|m| m.starts_with("indirect_calls:"))
        );
    }

    #[test]
    fn string_and_two_level_reachability() {
        let idx = fixture_index();
        // "token" does not exist -> empty.
        assert!(
            idx.query(&q(vec![Predicate::StringContains("token".into())]))
                .is_empty()
        );
        // payload string, reachable from main within 2 levels.
        let hits = idx.query(&q(vec![
            Predicate::StringContains("pay".into()),
            Predicate::ReachableFrom {
                root_ea: 0x403000,
                levels: 2,
            },
        ]));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function, "crypto_decrypt");
    }

    #[test]
    fn callee_predicate_and_not() {
        let idx = fixture_index();
        // Functions that call a function importing "send" -> main (via crypto_decrypt).
        let hits = idx.query(&q(vec![Predicate::CalleeMatches(Box::new(
            Predicate::Import("send".into()),
        ))]));
        // crypto_decrypt itself calls net_send.
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].function, "crypto_decrypt");

        // NOT import CryptDecrypt -> everything except crypto_decrypt.
        let hits = idx.query(&q(vec![Predicate::Not(Box::new(Predicate::Import(
            "CryptDecrypt".into(),
        )))]));
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn limit_is_enforced() {
        let mut idx = fixture_index();
        for i in 0..50u64 {
            idx.functions.insert(
                0x500000 + i,
                FunctionFacts {
                    ea_start: 0x500000 + i,
                    name: format!("f{i}"),
                    ..Default::default()
                },
            );
        }
        let hits = idx.query(&EvidenceQuery {
            all: Some(vec![Predicate::Not(Box::new(Predicate::Import(
                "CryptDecrypt".into(),
            )))]),
            limit: 5,
        });
        assert_eq!(hits.len(), 5);
    }

    #[test]
    fn save_and_load_roundtrip_with_reject() {
        let tmp = std::env::temp_dir().join(format!("rmcp-idx-test-{}", std::process::id()));
        let idx = fixture_index();
        idx.save(&tmp, "abc").unwrap();
        // Same md5 + revision -> loads.
        let loaded = AnalysisIndex::load(&tmp, "abc", 3).unwrap();
        assert_eq!(loaded.functions.len(), 3);
        // Different revision -> stale -> None.
        assert!(AnalysisIndex::load(&tmp, "abc", 4).is_none());
        // Corrupt file -> None (fails safely).
        let dir = tmp.join("analysis-index");
        let corrupt = dir.join("bad-rev1-v1.json");
        std::fs::write(&corrupt, b"not json{").unwrap();
        assert!(AnalysisIndex::load_from(&dir, &corrupt).is_none());
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = json!({}); // keep json import used
    }

    #[test]
    fn corrupt_cache_fails_safely() {
        let tmp = std::env::temp_dir().join(format!("rmcp-idx-test2-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("analysis-index")).unwrap();
        std::fs::write(
            tmp.join("analysis-index").join("x-rev1-v1.json"),
            b"\xff\xfe{garbage",
        )
        .unwrap();
        // No panic, returns None.
        assert!(AnalysisIndex::load(&tmp, "x", 1).is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
