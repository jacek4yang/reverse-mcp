//! #13 function signatures, similarity search and cross-IDB comparison.
//!
//! Multi-family fingerprints built on the #14 analysis index 鈥?never a
//! single hash. Families: call-graph shape (callees/callers counts +
//! connectivity), import multiset, string multiset, constant multiset,
//! size. Similarity scores are per-family with explainable evidence, and
//! strict/relaxed thresholds gate auto-rename confidence.
//!
//! The fingerprint index persists as open JSON (`.rsig.json`) next to the
//! database 鈥?no proprietary content. Cross-IDB mapping produces transfer
//! PROPOSALS (names/comments); nothing is applied without an explicit
//! mutation carrying `expected_revision`.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// One function's multi-family fingerprint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionSig {
    pub ea: u64,
    pub name: String,
    pub size: u64,
    /// Sorted, deduplicated import names.
    pub imports: Vec<String>,
    /// Sorted, deduplicated referenced strings.
    pub strings: Vec<String>,
    /// Sorted, deduplicated 64-bit constants.
    pub constants: Vec<u64>,
    /// Direct callee count and caller count (shape, not identity).
    pub callee_count: usize,
    pub caller_count: usize,
}

/// A persisted signature index for one database.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigIndex {
    pub format: u32,
    /// md5 of the binary the index was built from.
    pub binary_md5: String,
    pub functions: Vec<FunctionSig>,
}

pub const SIG_FORMAT: u32 = 1;

/// Build a signature index from the (already built) analysis index.
pub fn build_sig_index(backend: &dyn IdaBackend, idx: &AnalysisIndex) -> Result<SigIndex> {
    let _ = backend;
    let mut functions = Vec::new();
    for (ea, f) in &idx.functions {
        functions.push(FunctionSig {
            ea: *ea,
            name: f.name.clone(),
            size: f.size,
            imports: {
                let mut v: Vec<String> = f.imports.to_vec();
                v.sort();
                v.dedup();
                v
            },
            strings: {
                let mut v: Vec<String> = f.strings.to_vec();
                v.sort();
                v.dedup();
                v
            },
            constants: {
                let mut v: Vec<u64> = f.constants.to_vec();
                v.sort();
                v.dedup();
                v
            },
            callee_count: f.callees.len(),
            caller_count: f.callers.len(),
        });
    }
    functions.sort_by_key(|f| f.ea);
    Ok(SigIndex {
        format: SIG_FORMAT,
        binary_md5: idx.binary_md5.clone(),
        functions,
    })
}

/// Persist the signature index as open JSON next to the database file.
pub fn save_sig_index(backend: &dyn IdaBackend, sig: &SigIndex) -> Result<PathBuf> {
    let path = sig_path(backend)?;
    let json = serde_json::to_vec_pretty(sig).map_err(|e| Error::Ipc(e.to_string()))?;
    std::fs::write(&path, json).map_err(|e| Error::Ipc(format!("write sig index: {e}")))?;
    Ok(path)
}

/// Load a persisted signature index (path form returned by save).
pub fn load_sig_index(path: &PathBuf) -> Result<SigIndex> {
    let raw = std::fs::read(path).map_err(|e| Error::Ipc(format!("read sig index: {e}")))?;
    let sig: SigIndex =
        serde_json::from_slice(&raw).map_err(|e| Error::Ipc(format!("parse sig index: {e}")))?;
    if sig.format != SIG_FORMAT {
        return Err(Error::Worker(format!(
            "sig index format {} != supported {SIG_FORMAT}",
            sig.format
        )));
    }
    Ok(sig)
}

fn sig_path(backend: &dyn IdaBackend) -> Result<PathBuf> {
    let info = backend.db_info()?;
    let path = info["path"]
        .as_str()
        .ok_or_else(|| Error::Worker("no db path for sig index".into()))?;
    Ok(PathBuf::from(format!("{path}.rsig.json")))
}

/// Per-family similarity between two fingerprints, each in [0,1].
pub struct FamilyScores {
    pub imports: f64,
    pub strings: f64,
    pub constants: f64,
    pub calls: f64,
    pub size: f64,
}

impl FamilyScores {
    /// Weighted overall score; the weights favor content families (imports/
    /// constants/strings) over coarse shape so single-family flukes stay
    /// low-confidence.
    pub fn overall(&self) -> f64 {
        0.30 * self.imports
            + 0.25 * self.constants
            + 0.20 * self.strings
            + 0.15 * self.calls
            + 0.10 * self.size
    }

    pub fn to_json(&self) -> Value {
        json!({
            "imports": round2(self.imports),
            "constants": round2(self.constants),
            "strings": round2(self.strings),
            "calls": round2(self.calls),
            "size": round2(self.size),
        })
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

/// Jaccard-style similarity over two sorted sets. Both empty means the
/// same (missing) evidence and scores 1.0; one empty scores 0.25.
fn set_sim<T: Ord>(a: &[T], b: &[T]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.25;
    }
    let sa: BTreeSet<_> = a.iter().collect();
    let sb: BTreeSet<_> = b.iter().collect();
    let inter = sa.intersection(&sb).count();
    let union = sa.union(&sb).count();
    if union == 0 {
        0.5
    } else {
        inter as f64 / union as f64
    }
}

fn size_sim(a: u64, b: u64) -> f64 {
    let big = a.max(b);
    let small = a.min(b);
    if big == 0 {
        return 0.5;
    }
    small as f64 / big as f64
}

/// Similarity of two function fingerprints.
pub fn similarity(a: &FunctionSig, b: &FunctionSig) -> FamilyScores {
    FamilyScores {
        imports: set_sim(&a.imports, &b.imports),
        strings: set_sim(&a.strings, &b.strings),
        constants: set_sim(&a.constants, &b.constants),
        calls: call_sim(a, b),
        size: size_sim(a.size, b.size),
    }
}

/// Call-shape similarity: callee/caller counts compared with tolerance.
/// Both zero = same shape (1.0).
fn call_sim(a: &FunctionSig, b: &FunctionSig) -> f64 {
    let c = if a.callee_count.max(b.callee_count) == 0 {
        1.0
    } else {
        a.callee_count.min(b.callee_count) as f64 / a.callee_count.max(b.callee_count) as f64
    };
    let r = if a.caller_count.max(b.caller_count) == 0 {
        1.0
    } else {
        a.caller_count.min(b.caller_count) as f64 / a.caller_count.max(b.caller_count) as f64
    };
    0.6 * c + 0.4 * r
}

/// Identification policy thresholds.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// >= this overall score and no family below floor => strict match
    /// > (safe for auto-rename proposals).
    pub strict: f64,
    /// >= this overall score => relaxed match (hint only).
    pub relaxed: f64,
    /// No single family may fall below this for a strict match.
    pub strict_family_floor: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            strict: 0.85,
            relaxed: 0.60,
            strict_family_floor: 0.50,
        }
    }
}

/// One ranked candidate.
pub struct Candidate {
    pub ea: u64,
    pub name: String,
    pub scores: FamilyScores,
    pub match_kind: &'static str, // strict | relaxed | weak
}

/// Identify the function at `target` against a reference signature index.
pub fn identify_function(
    idx: &AnalysisIndex,
    reference: &SigIndex,
    target: u64,
    thresholds: &Thresholds,
    max_candidates: usize,
) -> Result<Value> {
    let Some(f) = idx.functions.get(&target) else {
        return Err(Error::Worker(format!("no function at {target:#x}")));
    };
    let probe = to_sig(ea_of(f), f);
    let mut candidates: Vec<Candidate> = Vec::new();
    for rf in &reference.functions {
        let s = similarity(&probe, rf);
        let overall = s.overall();
        let kind = if overall >= thresholds.strict
            && s.imports >= thresholds.strict_family_floor
            && s.constants >= thresholds.strict_family_floor
            && s.strings >= thresholds.strict_family_floor
        {
            "strict"
        } else if overall >= thresholds.relaxed {
            "relaxed"
        } else {
            "weak"
        };
        candidates.push(Candidate {
            ea: rf.ea,
            name: rf.name.clone(),
            scores: s,
            match_kind: kind,
        });
    }
    candidates.sort_by(|a, b| {
        b.scores
            .overall()
            .total_cmp(&a.scores.overall())
            .then(a.ea.cmp(&b.ea))
    });
    candidates.truncate(max_candidates);

    let ranked: Vec<Value> = candidates
        .iter()
        .map(|c| {
            json!({
                "candidate": {"ea": format!("{:#x}", c.ea), "name": c.name},
                "score": round2(c.scores.overall()),
                "match_kind": c.match_kind,
                "evidence": c.scores.to_json(),
            })
        })
        .collect();

    Ok(json!({
        "target": format!("{target:#x}"),
        "name": probe.name,
        "reference_binary_md5": reference.binary_md5,
        "candidates": ranked,
        "thresholds": {
            "strict": thresholds.strict,
            "relaxed": thresholds.relaxed,
            "family_floor": thresholds.strict_family_floor,
        },
        "note": "strict matches are rename-proposal material; relaxed are hints only",
    }))
}

fn ea_of(f: &rmcp_core::analysis_index::FunctionFacts) -> u64 {
    f.ea_start
}

fn to_sig(ea: u64, f: &rmcp_core::analysis_index::FunctionFacts) -> FunctionSig {
    FunctionSig {
        ea,
        name: f.name.clone(),
        size: f.size,
        imports: {
            let mut v: Vec<String> = f.imports.to_vec();
            v.sort();
            v.dedup();
            v
        },
        strings: {
            let mut v: Vec<String> = f.strings.to_vec();
            v.sort();
            v.dedup();
            v
        },
        constants: {
            let mut v: Vec<u64> = f.constants.to_vec();
            v.sort();
            v.dedup();
            v
        },
        callee_count: f.callees.len(),
        caller_count: f.callers.len(),
    }
}

/// Cross-IDB function map: proposals only. Returns pairs whose similarity
/// clears the relaxed threshold, with conflict detection against the
/// target DB's existing names (never silently overwritten).
pub fn map_functions(
    idx_from: &AnalysisIndex,
    idx_to: &AnalysisIndex,
    thresholds: &Thresholds,
    max_transfers: usize,
) -> Result<Value> {
    let sig_from = build_sig_index_no_backend(idx_from)?;
    let sig_to = build_sig_index_no_backend(idx_to)?;
    let mut transfers: Vec<Value> = Vec::new();
    let mut conflicts = 0usize;
    let mut truncated = false;

    for f in &sig_from.functions {
        // Skip tiny/no-evidence functions: mapping them is noise.
        if f.size < 16 && f.imports.is_empty() && f.constants.is_empty() {
            continue;
        }
        let mut best: Option<(&FunctionSig, FamilyScores)> = None;
        for g in &sig_to.functions {
            let s = similarity(f, g);
            if best
                .as_ref()
                .map(|(_, bs)| s.overall() > bs.overall())
                .unwrap_or(true)
                && s.overall() >= thresholds.relaxed
            {
                best = Some((g, s));
            }
        }
        if let Some((g, s)) = best {
            let overall = s.overall();
            let kind = if overall >= thresholds.strict
                && s.imports >= thresholds.strict_family_floor
                && s.constants >= thresholds.strict_family_floor
                && s.strings >= thresholds.strict_family_floor
            {
                "strict"
            } else {
                "relaxed"
            };
            // Conflict detection: the target already has a meaningful name
            // (not a sub_XXXX auto-name) that differs from the source name.
            let auto_named =
                g.name.starts_with("sub_") || !g.name.starts_with('?') && g.name.starts_with("j_");
            let conflict = !auto_named && g.name != f.name;
            if conflict {
                conflicts += 1;
            }
            transfers.push(json!({
                "from": {"ea": format!("{:#x}", f.ea), "name": f.name},
                "to": {"ea": format!("{:#x}", g.ea), "name": g.name},
                "score": round2(overall),
                "match_kind": kind,
                "evidence": s.to_json(),
                "proposal": {
                    "rename_to": f.name,
                    "conflict": conflict,
                    "note": if conflict {
                        "target has a meaningful name; transfer requires explicit approval"
                    } else {
                        "safe to apply (target is auto-named)"
                    },
                },
            }));
            if transfers.len() >= max_transfers {
                truncated = true;
                break;
            }
        }
    }

    transfers.sort_by(|a, b| {
        let sa: f64 = a["score"].as_f64().unwrap_or(0.0);
        let sb: f64 = b["score"].as_f64().unwrap_or(0.0);
        sb.total_cmp(&sa)
    });

    Ok(json!({
        "from_binary_md5": idx_from.binary_md5,
        "to_binary_md5": idx_to.binary_md5,
        "transfers": transfers,
        "conflicts": conflicts,
        "truncated": truncated,
        "note": "PROPOSALS ONLY: apply via explicit rename mutations with expected_revision; nothing is applied here",
    }))
}

fn build_sig_index_no_backend(idx: &AnalysisIndex) -> Result<SigIndex> {
    Ok(SigIndex {
        format: SIG_FORMAT,
        binary_md5: idx.binary_md5.clone(),
        functions: idx.functions.iter().map(|(ea, f)| to_sig(*ea, f)).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(
        ea: u64,
        name: &str,
        size: u64,
        imports: &[&str],
        constants: &[u64],
        strings: &[&str],
    ) -> FunctionSig {
        FunctionSig {
            ea,
            name: name.into(),
            size,
            imports: imports.iter().map(|s| s.to_string()).collect(),
            strings: strings.iter().map(|s| s.to_string()).collect(),
            constants: constants.to_vec(),
            callee_count: 2,
            caller_count: 1,
        }
    }

    #[test]
    fn identical_fingerprints_score_one() {
        let a = sig(0x1000, "f", 64, &["Sleep"], &[0x1234], &["hello"]);
        let b = sig(0x2000, "f", 64, &["Sleep"], &[0x1234], &["hello"]);
        let s = similarity(&a, &b);
        assert!(s.overall() >= 0.99, "identical: {:?}", s.to_json());
    }

    #[test]
    fn disjoint_fingerprints_score_low() {
        let a = sig(0x1000, "f", 64, &["Sleep"], &[0x1234], &["hello"]);
        let b = sig(0x2000, "g", 400, &["WriteFile"], &[0x9999], &["world"]);
        let s = similarity(&a, &b);
        assert!(s.overall() <= 0.35, "disjoint: {:?}", s.to_json());
    }

    #[test]
    fn identify_ranks_true_match_first() {
        let probe_idx = AnalysisIndex {
            schema_version: 1,
            binary_md5: "a".into(),
            revision: 0,
            functions: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    0x1000,
                    rmcp_core::analysis_index::FunctionFacts {
                        ea_start: 0x1000,
                        ea_end: 0x1100,
                        name: "decrypt".into(),
                        size: 256,
                        imports: vec!["CryptDecrypt".into()],
                        constants: vec![0x1234, 0x5678],
                        ..Default::default()
                    },
                );
                m
            },
            strings: Vec::new(),
        };
        let mut reference = SigIndex {
            format: SIG_FORMAT,
            binary_md5: "b".into(),
            functions: Vec::new(),
        };
        // True match plus decoys.
        reference.functions.push(sig(
            0x9000,
            "decrypt",
            256,
            &["CryptDecrypt"],
            &[0x1234, 0x5678],
            &[],
        ));
        reference
            .functions
            .push(sig(0x9100, "other", 100, &["ReadFile"], &[0x42], &[]));
        let t = identify_function(&probe_idx, &reference, 0x1000, &Default::default(), 5).unwrap();
        let cands = t["candidates"].as_array().unwrap();
        assert!(!cands.is_empty());
        assert_eq!(cands[0]["candidate"]["name"], "decrypt");
        assert!(cands[0]["score"].as_f64().unwrap() >= 0.85);
    }

    #[test]
    fn map_functions_flags_name_conflicts() {
        let mk = |md5: &str, ea: u64, name: &str| AnalysisIndex {
            schema_version: 1,
            binary_md5: md5.into(),
            revision: 0,
            functions: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    ea,
                    rmcp_core::analysis_index::FunctionFacts {
                        ea_start: ea,
                        ea_end: ea + 256,
                        name: name.into(),
                        size: 256,
                        imports: vec!["Sleep".into()],
                        constants: vec![0x7777],
                        ..Default::default()
                    },
                );
                m
            },
            strings: Vec::new(),
        };
        let from = mk("a", 0x1000, "my_decrypt");
        let to = mk("b", 0x2000, "my_decrypt");
        let out = map_functions(&from, &to, &Default::default(), 10).unwrap();
        let t = out["transfers"].as_array().unwrap();
        assert_eq!(t.len(), 1, "out: {out}");
        assert_eq!(
            t[0]["proposal"]["conflict"],
            false,
            "same name: {}",
            serde_json::to_string(&t[0]).unwrap_or_default()
        );

        // Conflicting target name must be flagged.
        let to2 = mk("b", 0x2000, "manual_name");
        let out2 = map_functions(&from, &to2, &Default::default(), 10).unwrap();
        let t2 = out2["transfers"].as_array().unwrap();
        assert_eq!(
            t2[0]["proposal"]["conflict"],
            true,
            "conflict: {}",
            serde_json::to_string(&t2[0]).unwrap_or_default()
        );
    }

    #[test]
    fn sig_index_roundtrips_through_json() {
        let idx = AnalysisIndex {
            schema_version: 1,
            binary_md5: "x".into(),
            revision: 0,
            functions: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    0x1000,
                    rmcp_core::analysis_index::FunctionFacts {
                        ea_start: 0x1000,
                        ea_end: 0x1100,
                        name: "f".into(),
                        size: 256,
                        imports: vec!["Sleep".into()],
                        ..Default::default()
                    },
                );
                m
            },
            strings: Vec::new(),
        };
        let sig = build_sig_index_no_backend(&idx).unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let back: SigIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.functions.len(), 1);
        assert_eq!(back.functions[0].name, "f");
    }
}
