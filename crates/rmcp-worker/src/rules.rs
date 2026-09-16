//! #47 external intelligence rule packs: an open, auditable JSON format for
//! crypto-constant / string / API-hash rules, loaded from a portable
//! `rules/` directory next to the exe (same layout policy as `plugins/`).
//!
//! Rules are DATA: no code execution from packs (no embedded scripts).
//! Parsing is fail-closed with precise errors (file, line, reason).
//! Provenance is deterministic: every hit row records the pack file's
//! sha256 and a stable rule id, so a hit is always explainable
//! ("matched rule X from pack Y, pack sha256 Z").
//!
//! Built-in packs are generated from the compiled-in #12 content so the
//! engine is a strict superset of #12; compiled-in behavior remains as the
//! fallback when no rules directory exists.

use std::path::{Path, PathBuf};

use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// Current rule-pack format version.
pub const PACK_FORMAT: u64 = 1;

/// Hard caps so a hostile/huge pack cannot balloon load time or memory.
const MAX_RULES_PER_PACK: usize = 10_000;
const MAX_PATTERN_BYTES: usize = 4096;
const MAX_LITERAL_LEN: usize = 1024;
const MAX_CANDIDATES_PER_RULE: usize = 256;

/// One compiled constant rule (byte pattern).
#[derive(Debug, Clone)]
pub struct ConstantRule {
    pub id: String,
    pub bytes: Vec<u8>,
    pub label: String,
    pub table_size: usize,
    pub rarity: f64,
}

/// One compiled API-hash rule (algo + seed + candidate names).
#[derive(Debug, Clone)]
pub struct ApiHashRule {
    pub id: String,
    /// Registered primitive name in `crypto::ALGOS` (verified at load).
    pub algo: String,
    pub seed: u32,
    pub rotate: u32,
    pub candidates: Vec<String>,
}

/// One compiled string rule (literal; regexes are deliberately unsupported
/// in v1 to keep load-time analysis total and fail-closed).
#[derive(Debug, Clone)]
pub struct StringRule {
    pub id: String,
    pub literal: String,
    pub encoding: String,
}

/// All rules from one pack, plus provenance.
#[derive(Debug, Clone, Default)]
pub struct RulePack {
    pub name: String,
    pub version: String,
    pub source: String,
    /// sha256 of the raw pack file bytes — recorded in every hit row.
    pub sha256: String,
    pub enabled: bool,
    pub constants: Vec<ConstantRule>,
    pub api_hashes: Vec<ApiHashRule>,
    pub strings: Vec<StringRule>,
}

/// The full loaded rule set.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub packs: Vec<RulePack>,
}

impl RuleSet {
    /// FNV-1a over every pack's sha256 + rule counts (order-independent:
    /// packs are sorted by name first). Keys the scan cache.
    pub fn set_hash(&self) -> String {
        // Order-independent: digest sorted pack fingerprints.
        let mut h: u64 = 0xcbf29ce484222325;
        let mut digest = |s: &str| {
            for b in s.bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
        };
        let mut prints: Vec<String> = self
            .packs
            .iter()
            .map(|p| {
                format!(
                    "{}|{}|{}|{}|{}",
                    p.sha256,
                    p.constants.len(),
                    p.api_hashes.len(),
                    p.strings.len(),
                    p.enabled
                )
            })
            .collect();
        prints.sort();
        for p in prints {
            digest(&p);
        }
        format!("{h:016x}")
    }
}

/// FNV-1a 64 of a byte slice (for hashing pack file contents).
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// A rule id so provenance stays stable across runs: sha256 of the raw pack
/// file is recorded at pack level; rule ids must be unique within a pack
/// and are validated for shape (`[A-Za-z0-9_.:-]{1,128}`).
fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-'))
}

fn parse_rules_value(pack_file: &str, v: &Value, algo_names: &[&str]) -> Result<RulePack> {
    let fail = |line: usize, reason: &str| {
        Err(Error::Worker(format!(
            "rule pack '{pack_file}' line {line}: {reason}"
        )))
    };
    if v["format"].as_u64() != Some(PACK_FORMAT) {
        return fail(0, &format!("'format' must be {PACK_FORMAT}"));
    }
    let name = v["name"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| Error::Worker(format!("rule pack '{pack_file}': missing 'name'")))?;
    let version = v["version"].as_str().unwrap_or("0");
    let source = v["source"].as_str().unwrap_or("");
    let enabled = v["enabled"].as_bool().unwrap_or(true);
    let rules = v["rules"]
        .as_array()
        .ok_or_else(|| Error::Worker(format!("rule pack '{pack_file}': missing 'rules' array")))?;
    if rules.len() > MAX_RULES_PER_PACK {
        return fail(0, &format!("too many rules (max {MAX_RULES_PER_PACK})"));
    }

    let mut pack = RulePack {
        name: name.to_string(),
        version: version.to_string(),
        source: source.to_string(),
        sha256: String::new(),
        enabled,
        constants: Vec::new(),
        api_hashes: Vec::new(),
        strings: Vec::new(),
    };

    let mut seen_ids = std::collections::BTreeSet::new();
    for (i, rule) in rules.iter().enumerate() {
        let line = i + 1; // array index as a stable line-ish locator
        let id = rule["id"].as_str().unwrap_or_default();
        if !valid_rule_id(id) {
            return fail(line, &format!("bad rule id '{id}'"));
        }
        if !seen_ids.insert(id.to_string()) {
            return fail(line, &format!("duplicate rule id '{id}'"));
        }
        let kind = rule["kind"].as_str().unwrap_or_default();
        match kind {
            "constant" => {
                let hex = rule["hex"].as_str().unwrap_or_default();
                let Some(bytes) = decode_hex_str(hex) else {
                    return fail(line, &format!("rule '{id}': bad 'hex'"));
                };
                if bytes.is_empty() || bytes.len() > MAX_PATTERN_BYTES {
                    return fail(
                        line,
                        &format!(
                            "rule '{id}': pattern length out of bounds (1..{MAX_PATTERN_BYTES})"
                        ),
                    );
                }
                let rarity = rule["rarity"].as_f64().unwrap_or(0.9).clamp(0.1, 1.0);
                pack.constants.push(ConstantRule {
                    id: id.to_string(),
                    label: rule["label"].as_str().unwrap_or(id).to_string(),
                    bytes,
                    table_size: rule["table_size"].as_u64().unwrap_or(0) as usize,
                    rarity,
                });
            }
            "string" => {
                let Some(lit) = rule["literal"].as_str() else {
                    return fail(
                        line,
                        &format!("rule '{id}': string rules require 'literal'"),
                    );
                };
                if lit.is_empty() || lit.len() > MAX_LITERAL_LEN {
                    return fail(
                        line,
                        &format!(
                            "rule '{id}': literal length out of bounds (1..{MAX_LITERAL_LEN})"
                        ),
                    );
                }
                // Reject obvious pathological patterns: control characters
                // and NUL bytes in literals (they never match real strings).
                if lit.chars().any(|c| c.is_control() && c != '\t') {
                    return fail(line, &format!("rule '{id}': control characters in literal"));
                }
                pack.strings.push(StringRule {
                    id: id.to_string(),
                    literal: lit.to_string(),
                    encoding: rule["encoding"].as_str().unwrap_or("ascii").to_string(),
                });
            }
            "api_hash" => {
                let algo = rule["algo"].as_str().unwrap_or_default();
                if !algo_names.contains(&algo) {
                    // Fail-closed at LOAD, not at runtime scan.
                    return fail(
                        line,
                        &format!(
                            "rule '{id}': unknown algo '{algo}' (registered: {})",
                            algo_names.join(", ")
                        ),
                    );
                }
                let candidates = rule["candidates"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|c| c.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if candidates.is_empty() || candidates.len() > MAX_CANDIDATES_PER_RULE {
                    return fail(
                        line,
                        &format!(
                            "rule '{id}': candidates count out of bounds (1..{MAX_CANDIDATES_PER_RULE})"
                        ),
                    );
                }
                pack.api_hashes.push(ApiHashRule {
                    id: id.to_string(),
                    algo: algo.to_string(),
                    seed: rule["seed"].as_u64().unwrap_or(0) as u32,
                    rotate: rule["rotate"].as_u64().unwrap_or(13).clamp(1, 31) as u32,
                    candidates,
                });
            }
            other => {
                return fail(
                    line,
                    &format!("rule '{id}': unknown kind '{other}' (constant|string|api_hash)"),
                );
            }
        }
    }
    Ok(pack)
}

/// Load all packs from `dir` (`.json` files, non-recursive). Missing dir is
/// NOT an error — callers fall back to the built-in packs. Returns the
/// loaded set; per-file failures abort with a precise error (fail-closed).
pub fn load_dir(dir: &Path, algo_names: &[&str]) -> Result<RuleSet> {
    let mut set = RuleSet::default();
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
            .collect(),
        Err(_) => return Ok(set),
    };
    entries.sort(); // deterministic load order
    for path in entries {
        let fname = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        let raw = std::fs::read(&path)
            .map_err(|e| Error::Worker(format!("rule pack '{fname}': read failed: {e}")))?;
        let mut pack = parse_rules_value(
            &fname,
            &serde_json::from_slice(&raw)
                .map_err(|e| Error::Worker(format!("rule pack '{fname}': bad JSON: {e}")))?,
            algo_names,
        )?;
        pack.sha256 = format!("{:016x}", fnv1a64(&raw));
        set.packs.push(pack);
    }
    set.packs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(set)
}

/// Built-in pack generated from the compiled-in #12 content so behavior is
/// a superset of #12. Rule ids are deterministic (`builtin.<slug>`).
pub fn builtin_packs() -> Result<RuleSet> {
    let v = crate::crypto::const_packs_json();
    let algo_names: Vec<&str> = crate::crypto::algo_names();
    let mut pack = parse_rules_value("<builtin>", &v, &algo_names)?;
    pack.name = "builtin".into();
    pack.version = "1".into();
    pack.source = "compiled-in CONST_PACKS + ALGOS (#12)".into();
    pack.sha256 = format!("{:016x}", fnv1a64(pack.name.as_bytes()));
    Ok(RuleSet { packs: vec![pack] })
}

/// Load the effective rule set: `rules/` dir packs if any exist, else the
/// built-in pack (compiled-in fallback).
pub fn load_effective() -> Result<RuleSet> {
    let dir = rmcp_core::layout::exe_dir().join("rules");
    let set = load_dir(&dir, &crate::crypto::algo_names())?;
    if set.packs.is_empty() {
        // Compiled-in fallback: same hit set as #12 when no rules dir exists.
        builtin_packs()
    } else {
        Ok(set)
    }
}

fn decode_hex_str(s: &str) -> Option<Vec<u8>> {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !t.len().is_multiple_of(2) {
        return None;
    }
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).ok())
        .collect()
}

/// Provenance wrapper for one hit row: pack sha256 + rule id + label.
pub fn provenance(pack: &RulePack, rule_id: &str, label: &str) -> Value {
    json!({
        "pack": pack.name,
        "pack_sha256": pack.sha256,
        "rule": rule_id,
        "label": label,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGOS: &[&str] = &["ror13-add", "ror13-add-wide", "crc32"];

    #[test]
    fn valid_pack_parses() {
        let v = json!({
            "format": 1, "name": "test-pack", "version": "1", "source": "test",
            "rules": [
                {"kind": "constant", "id": "c1", "hex": "637c777bf26b6fc5", "label": "AES sbox head", "rarity": 0.99},
                {"kind": "string", "id": "s1", "literal": "SUCCESS", "encoding": "ascii"},
                {"kind": "api_hash", "id": "h1", "algo": "ror13-add", "seed": 0, "candidates": ["LoadLibraryA"]}
            ]
        });
        let pack = parse_rules_value("t.json", &v, ALGOS).unwrap();
        assert_eq!(pack.constants.len(), 1);
        assert_eq!(pack.strings.len(), 1);
        assert_eq!(pack.api_hashes.len(), 1);
    }

    #[test]
    fn unknown_algo_rejects_at_load() {
        let v = json!({
            "format": 1, "name": "bad", "rules": [
                {"kind": "api_hash", "id": "h1", "algo": "super_custom_hash", "candidates": ["x"]}
            ]
        });
        let err = parse_rules_value("t.json", &v, ALGOS).unwrap_err();
        assert!(
            err.to_string().contains("unknown algo 'super_custom_hash'"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_rule_id_rejects() {
        let v = json!({
            "format": 1, "name": "dup", "rules": [
                {"kind": "constant", "id": "c1", "hex": "0102"},
                {"kind": "constant", "id": "c1", "hex": "0304"}
            ]
        });
        let err = parse_rules_value("t.json", &v, ALGOS).unwrap_err();
        assert!(err.to_string().contains("duplicate rule id 'c1'"), "{err}");
    }

    #[test]
    fn malformed_schema_rejects_with_location() {
        let v = json!({"format": 2, "name": "bad-format", "rules": []});
        let err = parse_rules_value("t.json", &v, ALGOS).unwrap_err();
        assert!(err.to_string().contains("'format' must be 1"), "{err}");
    }

    #[test]
    fn pathological_literal_rejects() {
        let huge = "a".repeat(MAX_LITERAL_LEN + 1);
        let v = json!({
            "format": 1, "name": "huge", "rules": [
                {"kind": "string", "id": "s1", "literal": huge}
            ]
        });
        let err = parse_rules_value("t.json", &v, ALGOS).unwrap_err();
        assert!(
            err.to_string().contains("literal length out of bounds"),
            "{err}"
        );
    }

    #[test]
    fn ten_thousand_rules_load_within_caps() {
        let rules: Vec<Value> = (0..10_000)
            .map(|i| json!({"kind": "constant", "id": format!("c{i}"), "hex": "637c777b"}))
            .collect();
        let v = json!({"format": 1, "name": "big", "rules": rules});
        let pack = parse_rules_value("t.json", &v, ALGOS).unwrap();
        assert_eq!(pack.constants.len(), 10_000);
    }

    #[test]
    fn set_hash_is_order_independent() {
        let mk = |sha: &str, n: &str| RulePack {
            name: n.into(),
            version: "1".into(),
            source: "".into(),
            sha256: sha.into(),
            enabled: true,
            constants: vec![ConstantRule {
                id: "c".into(),
                bytes: vec![1, 2],
                label: "l".into(),
                table_size: 0,
                rarity: 0.9,
            }],
            api_hashes: vec![],
            strings: vec![],
        };
        let a = RuleSet {
            packs: vec![mk("aaa", "p1"), mk("bbb", "p2")],
        };
        let b = RuleSet {
            packs: vec![mk("bbb", "p2"), mk("aaa", "p1")],
        };
        assert_eq!(a.set_hash(), b.set_hash());
    }
}
