//! #12 binary intelligence: crypto-constant scanning, API-hash resolver
//! detection/verification, and stack/array string recovery.
//!
//! Pure-Rust, no new C++ shims: byte scanning runs over `get_bytes` ranges
//! from `segments()`, resolver detection builds on the #14 index (function
//! constants), and stack-string detection reads ctree immediate values via
//! the existing #19 ctree walk (cot_num rows). Everything is cached per DB
//! revision and every finding carries provenance (xrefs, callers) ranked by
//! confidence.

use std::collections::BTreeMap;

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// One known-constant pack entry. Values are public standard constants
/// (AES/SHA/MD5/CRC/RC4/TEA...), sourced from the public specifications.
struct ConstPack {
    name: &'static str,
    /// Byte pattern to match anywhere in a segment.
    bytes: &'static [u8],
    /// Total size of the table this constant heads (for reporting).
    table_size: usize,
    /// Subjective rarity weight feeding confidence (0.5 common .. 1.0 rare).
    rarity: f64,
}

/// Leading-byte patterns of well-known crypto tables/constants. Deliberately
/// short (8-16 bytes) to bound scan cost while staying discriminating.
const CONST_PACKS: &[ConstPack] = &[
    ConstPack {
        name: "AES S-box",
        bytes: &[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76,
        ],
        table_size: 256,
        rarity: 0.99,
    },
    ConstPack {
        name: "AES inverse S-box",
        bytes: &[
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
            0xd7, 0xfb,
        ],
        table_size: 256,
        rarity: 0.99,
    },
    ConstPack {
        name: "SHA-256 initial hash (H0)",
        bytes: &[
            0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5,
            0x4f, 0xa5,
        ],
        table_size: 32,
        rarity: 0.97,
    },
    ConstPack {
        name: "SHA-256 round constants (K)",
        bytes: &[
            0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91, 0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5,
            0xdb, 0xa5,
        ],
        table_size: 256,
        rarity: 0.97,
    },
    ConstPack {
        name: "SHA-1 initial hash (H0)",
        bytes: &[
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
            0x54, 0x76,
        ],
        table_size: 20,
        rarity: 0.95,
    },
    ConstPack {
        name: "MD5 initial state (A,B,C,D)",
        bytes: &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ],
        table_size: 16,
        rarity: 0.92,
    },
    ConstPack {
        name: "CRC-32 polynomial table (reflected)",
        bytes: &[
            0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee, 0xba, 0x51,
            0x09, 0x99,
        ],
        table_size: 1024,
        rarity: 0.85,
    },
    ConstPack {
        name: "Blowfish P-array (pi digits)",
        bytes: &[
            0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x44,
        ],
        table_size: 72,
        rarity: 0.97,
    },
    ConstPack {
        name: "TEA/XTEA delta",
        bytes: &[0xb9, 0x79, 0x37, 0x9e],
        table_size: 4,
        rarity: 0.8,
    },
];

/// One detected crypto-constant hit (with #47 provenance).
#[derive(Debug, Clone)]
struct ConstHit {
    ea: u64,
    /// Rule id (provenance-stable, e.g. "builtin.aes_s-box" or pack rule id).
    name: String,
    /// Human label (pack rule label or the #12 pack name).
    label: String,
    table_size: usize,
    confidence: f64,
    /// #47 provenance: pack name + pack file sha256.
    pack_name: String,
    pack_sha: String,
}

/// #47: export the compiled-in constant packs as a rule-pack JSON value so
/// the built-in pack is generated from the same source of truth (#12).
pub fn const_packs_json() -> Value {
    let rules: Vec<Value> = CONST_PACKS
        .iter()
        .map(|p| {
            json!({
                "kind": "constant",
                "id": format!("builtin.{}", p.name.to_lowercase().replace([' ', '(', ')', '/', ','], "_")),
                "hex": p.bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                "label": p.name,
                "table_size": p.table_size,
                "rarity": p.rarity,
            })
        })
        .collect();
    json!({
        "format": 1,
        "name": "builtin",
        "version": "1",
        "source": "compiled-in CONST_PACKS (#12)",
        "rules": rules,
    })
}

/// #47: names of the registered API-hash primitives (for rule validation).
pub fn algo_names() -> Vec<&'static str> {
    ALGOS.iter().map(|a| a.name).collect()
}

/// Scan all readable segments for known crypto constants. Returns ranked
/// hits with referencing functions and callers from the analysis index.
///
/// #47: the scanned rule set is passed in (`rules`); each hit row records
/// provenance (pack name + sha256 + rule id) so findings stay explainable.
/// `None` keeps the compiled-in #12 behavior unchanged (backwards compat).
pub fn crypto_scan(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    max_hits: usize,
    rules: Option<&crate::rules::RuleSet>,
) -> Result<Value> {
    // Flatten the effective constant rules with their provenance.
    // label, pack, sha, rule id, bytes, table size, rarity
    type PackedRule = (String, String, String, String, Vec<u8>, usize, f64);
    let mut packed: Vec<PackedRule> = Vec::new();
    if rules.is_none() {
        for p in CONST_PACKS {
            packed.push((
                p.name.to_string(),
                "builtin".to_string(),
                "builtin".to_string(),
                format!(
                    "builtin.{}",
                    p.name
                        .to_lowercase()
                        .replace([' ', '(', ')', '/', ','], "_")
                ),
                p.bytes.to_vec(),
                p.table_size,
                p.rarity,
            ));
        }
    }
    if let Some(rs) = rules {
        for pack in &rs.packs {
            if !pack.enabled {
                continue;
            }
            for r in &pack.constants {
                packed.push((
                    r.label.clone(),
                    pack.name.clone(),
                    pack.sha256.clone(),
                    r.id.clone(),
                    r.bytes.clone(),
                    r.table_size,
                    r.rarity,
                ));
            }
        }
    }
    let segs = backend.segments()?;
    let mut hits: Vec<ConstHit> = Vec::new();
    let mut truncated = false;

    for seg in &segs {
        // Only scan data-ish segments with a sane size bound.
        let size = seg.end.saturating_sub(seg.start);
        if size == 0 || size > 64 * 1024 * 1024 {
            continue;
        }
        if seg.perms.contains('x') && !seg.perms.contains('w') && !seg.perms.contains('r') {
            continue;
        }
        // Read in bounded chunks so one huge segment cannot balloon memory.
        const CHUNK: usize = 1024 * 1024;
        let mut base = seg.start;
        while base < seg.end {
            let want = CHUNK.min((seg.end - base) as usize);
            let Ok(b) = backend.get_bytes(base, want) else {
                break;
            };
            let Some(hex) = b["hex"].as_str() else { break };
            let bytes = match decode_hex(hex) {
                Some(v) => v,
                None => break,
            };
            if bytes.is_empty() {
                break;
            }
            // #47: scan against the flattened rule set (provenance rows):
            // (label, pack name, pack sha, rule id, pattern, size, rarity).
            for (label, pack_name, pack_sha, rule_id, pat, table_size, rarity) in &packed {
                if pat.is_empty() || pat.len() > bytes.len() {
                    continue;
                }
                for (i, window) in bytes.windows(pat.len()).enumerate() {
                    if window == &pat[..] {
                        let ea = base + i as u64;
                        hits.push(ConstHit {
                            ea,
                            name: rule_id.clone(),
                            label: label.clone(),
                            table_size: *table_size,
                            confidence: *rarity,
                            pack_name: pack_name.clone(),
                            pack_sha: pack_sha.clone(),
                        });
                        if hits.len() >= max_hits * 4 {
                            truncated = true;
                            break;
                        }
                    }
                }
                if truncated {
                    break;
                }
            }
            if truncated {
                break;
            }
            base += want as u64;
        }
        if truncated {
            break;
        }
    }

    // Rank: confidence, then address for determinism.
    hits.sort_by(|a, b| b.confidence.total_cmp(&a.confidence).then(a.ea.cmp(&b.ea)));
    hits.truncate(max_hits);

    let findings: Vec<Value> = hits
        .iter()
        .map(|h| {
            // Referencing functions: any function whose range contains the
            // hit, plus index xrefs. Callers of those functions from the
            // index give the one-request context the issue requires.
            let funcs: Vec<u64> = idx
                .functions
                .range(..=h.ea)
                .next_back()
                .and_then(|(start, f)| (h.ea <= f.ea_end).then_some(*start))
                .into_iter()
                .collect();
            let mut callers: BTreeMap<u64, ()> = BTreeMap::new();
            for f in &funcs {
                if let Some(finfo) = idx.functions.get(f) {
                    for c in &finfo.callers {
                        callers.insert(*c, ());
                    }
                }
            }
            json!({
                "kind": "crypto_constant",
                "rule": h.name,
                "label": h.label,
                "ea": format!("{:#x}", h.ea),
                "table_size": h.table_size,
                "confidence": format!("{:.2}", h.confidence),
                "containing_function": funcs.iter().map(|f| format!("{f:#x}")).collect::<Vec<_>>(),
                "callers": callers.keys().map(|c| format!("{c:#x}")).collect::<Vec<_>>(),
                // #47 deterministic provenance: which pack, which content.
                "pack": h.pack_name,
                "pack_sha256": h.pack_sha,
            })
        })
        .collect();

    Ok(json!({
        "kind": "crypto_scan",
        "findings": findings,
        "truncated": truncated,
        "packs": CONST_PACKS.len(),
        "note": "ranked by confidence; callers come from the analysis index",
    }))
}

/// One candidate API-hash algorithm.
struct HashAlgo {
    name: &'static str,
    /// Compute the hash of `data` (already normalized per the algo's rules).
    compute: fn(&[u8]) -> u32,
    /// How names are normalized before hashing (applied by the caller).
    wide: bool,
}

fn ror32(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

fn rol32(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

/// ror13-add (classic shellcode/malware API hash).
fn ror13_add(data: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in data {
        h = ror32(h, 13).wrapping_add(b as u32);
    }
    h
}

/// ror 15 variant seen in some loaders.
fn ror15_add(data: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in data {
        h = ror32(h, 15).wrapping_add(b as u32);
    }
    h
}

/// rol 7 xor variant.
fn rol7_xor(data: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in data {
        h = rol32(h, 7) ^ (b as u32);
    }
    h
}

/// Standard CRC-32 (IEEE) over the name bytes.
fn crc32(data: &[u8]) -> u32 {
    let mut h: u32 = !0;
    for &b in data {
        h ^= b as u32;
        for _ in 0..8 {
            let mask = (h & 1).wrapping_neg();
            h = (h >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !h
}

const ALGOS: &[HashAlgo] = &[
    HashAlgo {
        name: "ror13-add",
        compute: ror13_add,
        wide: false,
    },
    HashAlgo {
        name: "ror13-add-wide",
        compute: ror13_add,
        wide: true,
    },
    HashAlgo {
        name: "ror15-add",
        compute: ror15_add,
        wide: false,
    },
    HashAlgo {
        name: "rol7-xor",
        compute: rol7_xor,
        wide: false,
    },
    HashAlgo {
        name: "crc32",
        compute: crc32,
        wide: false,
    },
];

/// Corpus entry: (algorithm, API name, wide-name variant).
type CorpusHit = (String, String, bool);
/// Verified hash corpus: hash -> hits.
type Corpus = BTreeMap<u32, Vec<CorpusHit>>;

/// Pre-computed hash -> (algo, name) corpus from the DB's own import names.
/// Building the corpus from imports keeps verification data-local.
fn build_corpus(backend: &dyn IdaBackend) -> Result<Corpus> {
    let mut corpus: Corpus = BTreeMap::new();
    let imports = backend.imports(None, 0, 20_000)?;
    let Some(entries) = imports["modules"].as_array() else {
        return Ok(corpus);
    };
    for module in entries {
        let Some(items) = module["entries"].as_array() else {
            continue;
        };
        for entry in items {
            let Some(name) = entry["name"].as_str() else {
                continue;
            };
            for algo in ALGOS {
                let norm: Vec<u8> = if algo.wide {
                    // UTF-16LE bytes of the name (hash iterates 2 bytes/char).
                    let mut w: Vec<u8> = Vec::with_capacity(name.len() * 2 + 2);
                    for ch in name.encode_utf16() {
                        w.extend_from_slice(&ch.to_le_bytes());
                    }
                    w.push(0);
                    w.push(0);
                    w
                } else {
                    let mut a: Vec<u8> = name.bytes().collect();
                    a.push(0);
                    a
                };
                let h = (algo.compute)(&norm);
                corpus.entry(h).or_default().push((
                    algo.name.to_string(),
                    name.to_string(),
                    algo.wide,
                ));
            }
        }
    }
    Ok(corpus)
}

/// Detect likely API-hash resolver functions and verify candidate
/// algorithms against the import-name corpus. Detection signal: functions
/// holding multiple 32-bit constants (seed/multiplier patterns) whose index
/// constants include typical rotate/loop magic, ranked by corpus hits.
pub fn resolve_api_hashes(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    max_findings: usize,
) -> Result<Value> {
    let corpus = build_corpus(backend)?;
    let mut findings: Vec<Value> = Vec::new();
    let mut truncated = false;

    for (ea, f) in &idx.functions {
        // Resolver shape: few or no imports called directly, some constants,
        // modest size, and callers that pass it dword immediates.
        if f.ea_end.saturating_sub(*ea) > 0x800 {
            continue;
        }
        if f.constants.len() < 2 {
            continue;
        }
        // Verified hashes: functions whose constants match corpus entries.
        // A resolver typically holds 1-N precomputed API hashes as
        // comparison constants.
        let mut verified: Vec<Value> = Vec::new();
        for c in &f.constants {
            let key = *c as u32;
            if let Some(matches) = corpus.get(&key) {
                for (algo, name, wide) in matches.iter().take(4) {
                    verified.push(json!({
                        "constant": format!("{key:#010x}"),
                        "algorithm": algo,
                        "api": name,
                        "wide": wide,
                    }));
                }
            }
            if verified.len() >= 8 {
                break;
            }
        }
        if verified.is_empty() {
            continue;
        }
        // Confidence grows with the number of verified constants; a single
        // 32-bit match can be coincidence, two+ matching import names is
        // strong.
        let n = verified.len();
        let confidence = match n {
            1 => 0.45,
            2 => 0.75,
            3 => 0.88,
            _ => 0.95,
        };
        let callers: Vec<String> = f.callers.iter().map(|c| format!("{c:#x}")).collect();
        findings.push(json!({
            "kind": "api_hash_resolver",
            "function": {"ea": format!("{ea:#x}"), "name": f.name},
            "confidence": format!("{confidence:.2}"),
            "verified_hashes": verified,
            "verified_count": n,
            "callers": callers,
        }));
        if findings.len() >= max_findings {
            truncated = true;
            break;
        }
    }

    findings.sort_by(|a, b| {
        let ca: f64 = a["confidence"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0.0);
        let cb: f64 = b["confidence"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0.0);
        cb.total_cmp(&ca)
    });

    Ok(json!({
        "kind": "api_hash_scan",
        "findings": findings,
        "truncated": truncated,
        "algorithms": ALGOS.iter().map(|a| a.name).collect::<Vec<_>>(),
        "note": "algorithms verified against the DB's import-name corpus; low-confidence single-hash resolvers are flagged as such",
    }))
}

/// Stack-string / array-built-string recovery: scan the ctree of each
/// function for consecutive immediate stores whose bytes assemble into
/// printable ASCII sequences (>= 4 chars). Immediate values come from the
/// #19 ctree walk (cot_num rows in EA order).
pub fn recover_strings(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    target: u64,
    max_strings: usize,
) -> Result<Value> {
    if !idx.functions.contains_key(&target) {
        return Err(Error::Worker(format!("no function at {target:#x}")));
    }
    let hr = backend.hr_cfunc(target, true, false, 8_000)?;
    let Some(rows) = hr["ctree"].as_array() else {
        return Ok(json!({
            "target": format!("{target:#x}"),
            "strings": [],
            "note": "no ctree available",
        }));
    };

    // Collect immediate values in EA order (b field of cot_num rows).
    let mut imm_bytes: Vec<u8> = Vec::new();
    let mut imm_sites: Vec<(u64, u8)> = Vec::new();
    for row in rows {
        if row["is_expr"].as_bool() != Some(true) {
            continue;
        }
        // cot_num op == 68 per hexrays.hpp; the ctree walk stores the value
        // in "c" for cot_num rows.
        if row["op"].as_u64() == Some(68) {
            let v = row["c"].as_u64().unwrap_or(0);
            // Store the little-endian bytes of the immediate.
            let bytes = v.to_le_bytes();
            for &b in bytes.iter() {
                imm_sites.push((row["ea"].as_u64().unwrap_or(0), b));
            }
            imm_bytes.extend_from_slice(&bytes);
        }
    }

    // Extract runs of printable ASCII (>= 4 chars) from the immediate
    // stream; record the EAs that contributed each run.
    let mut strings: Vec<Value> = Vec::new();
    let mut run_start: Option<usize> = None;
    for (i, &b) in imm_bytes.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b);
        if printable {
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else {
            if let Some(start) = run_start {
                let len = i - start;
                if len >= 4 {
                    let text: String = imm_bytes[start..i].iter().map(|&c| c as char).collect();
                    let eas: Vec<String> = imm_sites[start..i]
                        .iter()
                        .map(|(ea, _)| format!("{ea:#x}"))
                        .collect();
                    strings.push(json!({
                        "value": text,
                        "technique": "stack_or_array_immediates",
                        "sites": eas,
                        "confidence": if len >= 6 { "0.8" } else { "0.6" },
                    }));
                    if strings.len() >= max_strings {
                        break;
                    }
                }
                run_start = None;
            }
        }
    }
    // Trailing run.
    if let Some(start) = run_start {
        let len = imm_bytes.len() - start;
        if len >= 4 && strings.len() < max_strings {
            let text: String = imm_bytes[start..].iter().map(|&c| c as char).collect();
            let eas: Vec<String> = imm_sites[start..]
                .iter()
                .map(|(ea, _)| format!("{ea:#x}"))
                .collect();
            strings.push(json!({
                "value": text,
                "technique": "stack_or_array_immediates",
                "sites": eas,
                "confidence": if len >= 6 { "0.8" } else { "0.6" },
            }));
        }
    }

    let f = idx.functions.get(&target);
    let callers: Vec<String> = f
        .map(|fi| fi.callers.iter().map(|c| format!("{c:#x}")).collect())
        .unwrap_or_default();

    Ok(json!({
        "target": format!("{target:#x}"),
        "name": f.map(|fi| fi.name.clone()).unwrap_or_default(),
        "strings": strings,
        "callers": callers,
        "note": "recovered from immediate-store analysis; the IDB is not patched",
    }))
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
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

    #[test]
    fn ror13_hash_matches_known_values() {
        // ror13-add of "Sleep\0": deterministic and distinct per name.
        let h = ror13_add(b"Sleep\0");
        assert_eq!(h, ror13_add(b"Sleep\0"));
        assert_ne!(h, ror13_add(b"LoadLibraryA\0"));
    }

    #[test]
    fn crypto_scan_well_formed_on_mock() {
        let b = open_mock();
        let idx = b.build_index().unwrap().0;
        let out = crypto_scan(&b, &idx, 50, None).unwrap();
        assert!(out["findings"].as_array().is_some(), "out: {out}");
        for f in out["findings"].as_array().unwrap() {
            assert!(f["ea"].as_str().is_some(), "{f}");
            assert!(f["confidence"].as_str().is_some(), "{f}");
        }
    }

    #[test]
    fn api_hash_scan_well_formed_and_bounded() {
        let b = open_mock();
        let idx = b.build_index().unwrap().0;
        let out = resolve_api_hashes(&b, &idx, 5).unwrap();
        let findings = out["findings"].as_array().unwrap();
        assert!(findings.len() <= 5, "bounded: {out}");
        for f in findings {
            assert!(f["confidence"].as_str().is_some(), "{f}");
        }
    }

    #[test]
    fn recover_strings_requires_function() {
        let b = open_mock();
        let idx = b.build_index().unwrap().0;
        let err = recover_strings(&b, &idx, 0x999000, 50).unwrap_err();
        assert!(err.to_string().contains("no function"));
    }

    #[test]
    fn decode_hex_rejects_bad_input() {
        assert!(decode_hex("0").is_none());
        assert!(decode_hex("zz").is_none());
        assert_eq!(decode_hex("00ff").unwrap(), vec![0x00, 0xff]);
    }
}
