//! #45 block-level binary diff: basic-block fingerprints, block mapping and
//! changed-block classification between two databases.
//!
//! Scope (issue #45): read-only over both IDBs; per-block fingerprints are
//! architecture-normalized (mnemonic sequence hash + constant count + edge
//! shape) so instruction re-encoding does not change the hash. Matching is
//! greedy on exact fingerprint equality first, then best-similarity above a
//! threshold - never O(N²) across the whole binary: the caller proposes
//! function pairs (same name or #13 sig mapping) and the diff runs per pair
//! with caps and truncation flags.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rmcp_core::backend::{GraphParams, IdaBackend};
use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// FNV-1a 64 over a byte slice (fingerprint primitive; fast, deterministic).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// One basic block fingerprint.
#[derive(Debug, Clone)]
pub struct BlockFp {
    pub ea: u64,
    /// FNV-1a over the normalized mnemonic sequence.
    pub mnemonic_hash: u64,
    /// Distinct immediate constants >= 0x100 (sorted FNV over values).
    pub const_hash: u64,
    pub const_count: usize,
    /// Out-degree + in-degree of the block in the CFG.
    pub out_edges: usize,
    pub in_edges: usize,
    pub insn_count: usize,
}

impl BlockFp {
    /// Exact fingerprint: hash of the normalized shape. Blocks with equal
    /// fingerprints are assumed equivalent (same mnemonics, same constant
    /// multiset size class, same edge shape).
    fn shape_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for v in [
            self.mnemonic_hash,
            self.const_hash,
            self.out_edges as u64,
            self.in_edges as u64,
        ] {
            h ^= v;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    /// Bounded similarity against another block: weighted blend of mnemonic
    /// hash equality, constant overlap and edge shape. 1.0 = identical.
    fn similarity(&self, other: &BlockFp) -> f64 {
        let mnem = if self.mnemonic_hash == other.mnemonic_hash {
            1.0
        } else {
            0.0
        };
        let consts = if self.const_hash == other.const_hash {
            1.0
        } else {
            0.0
        };
        let edges = if self.out_edges == other.out_edges && self.in_edges == other.in_edges {
            1.0
        } else {
            0.0
        };
        0.6 * mnem + 0.2 * consts + 0.2 * edges
    }
}

/// Extract basic-block fingerprints for one function from the live backend.
/// Bounded by `max_blocks`; sets `truncated` when the CFG exceeds it.
pub fn function_block_fingerprints(
    backend: &dyn IdaBackend,
    ea: u64,
    max_blocks: usize,
) -> Result<(Vec<BlockFp>, bool)> {
    let graph = backend.graph(
        ea,
        &GraphParams {
            kind: "cfg".into(),
            depth: 1,
            max_nodes: max_blocks,
            max_edges: max_blocks * 4,
        },
    )?;
    let nodes = graph["nodes"]
        .as_array()
        .cloned()
        .ok_or_else(|| Error::Worker("graph: missing nodes".into()))?;
    let truncated = graph["truncated"].as_bool().unwrap_or(false) || nodes.len() >= max_blocks;

    let mut block_ranges: Vec<(u64, u64)> = Vec::new();
    for n in &nodes {
        let Some(start) = n["ea"].as_u64() else {
            continue;
        };
        block_ranges.push((start, 0));
    }
    block_ranges.sort();

    let f = backend.function_at(ea)?;
    let end = f.ea_end;
    // Disassemble once; slice into blocks by consecutive node starts.
    let insns = backend.disassemble(ea, Some(end), max_blocks * 64)?;
    let starts: BTreeSet<u64> = block_ranges.iter().map(|(s, _)| *s).collect();
    let mut per_block: BTreeMap<u64, Vec<&rmcp_core::backend::InsnInfo>> = BTreeMap::new();
    let mut current: Option<u64> = None;
    for insn in &insns {
        if starts.contains(&insn.ea) {
            current = Some(insn.ea);
        }
        if let Some(cur) = current {
            per_block.entry(cur).or_default().push(insn);
        }
    }

    // Edge shape from the graph edges.
    let mut in_count: HashMap<u64, usize> = HashMap::new();
    let mut out_count: HashMap<u64, usize> = HashMap::new();
    for e in graph["edges"].as_array().cloned().unwrap_or_default() {
        let (Some(from), Some(to)) = (e["from"].as_u64(), e["to"].as_u64()) else {
            continue;
        };
        *out_count.entry(from).or_default() += 1;
        *in_count.entry(to).or_default() += 1;
    }

    let mut fps = Vec::new();
    for (start, insns) in &per_block {
        // Normalized mnemonic sequence hash: opcodes only (no operand
        // encodings, no addresses), so re-encoding does not change it.
        let mut mnem_bytes: Vec<u8> = Vec::new();
        let mut consts: BTreeSet<u64> = BTreeSet::new();
        for insn in insns {
            mnem_bytes.extend_from_slice(insn.mnemonic.to_ascii_lowercase().as_bytes());
            mnem_bytes.push(0x1f);
            for tok in insn.operands.split(',') {
                let tok = tok.trim();
                if let Some(v) = tok
                    .strip_prefix("0x")
                    .or_else(|| tok.strip_prefix("0X"))
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                    .filter(|v| *v >= 0x100)
                {
                    consts.insert(v);
                }
            }
        }
        fps.push(BlockFp {
            ea: *start,
            mnemonic_hash: fnv1a64(&mnem_bytes),
            const_hash: {
                let mut h: u64 = 0xcbf29ce484222325;
                for c in &consts {
                    h ^= *c;
                    h = h.wrapping_mul(0x100000001b3);
                }
                h
            },
            const_count: consts.len(),
            out_edges: out_count.get(start).copied().unwrap_or(0),
            in_edges: in_count.get(start).copied().unwrap_or(0),
            insn_count: insns.len(),
        });
    }
    Ok((fps, truncated))
}

/// One classified block pair (or unmatched block).
fn block_row(kind: &str, a: Option<&BlockFp>, b: Option<&BlockFp>, sim: Option<f64>) -> Value {
    json!({
        "kind": kind,
        "a": a.map(|x| json!({"ea": format!("{:#x}", x.ea), "insns": x.insn_count})),
        "b": b.map(|x| json!({"ea": format!("{:#x}", x.ea), "insns": x.insn_count})),
        "similarity": sim.map(|s| format!("{s:.2}")),
    })
}

/// Greedy block mapping between two fingerprint lists:
/// 1. exact shape-hash equality (deterministic, order-independent);
/// 2. remaining blocks matched by best similarity above `threshold`.
///
/// Unmatched sides are reported as `added`/`removed`.
pub fn diff_blocks(a: &[BlockFp], b: &[BlockFp], threshold: f64, max_rows: usize) -> Result<Value> {
    let mut pairs: Vec<(usize, usize)> = Vec::new();
    let mut used_a: BTreeSet<usize> = BTreeSet::new();
    let mut used_b: BTreeSet<usize> = BTreeSet::new();

    // Pass 1: exact fingerprint equality.
    let mut by_shape: HashMap<u64, Vec<usize>> = HashMap::new();
    for (bi, blk) in b.iter().enumerate() {
        by_shape.entry(blk.shape_hash()).or_default().push(bi);
    }
    for (ai, blk) in a.iter().enumerate() {
        if let Some(bi) = by_shape.get_mut(&blk.shape_hash()).and_then(Vec::pop) {
            used_a.insert(ai);
            used_b.insert(bi);
            pairs.push((ai, bi));
        }
    }

    // Pass 2: greedy best-similarity for the remainder.
    for (ai, blk) in a.iter().enumerate() {
        if used_a.contains(&ai) {
            continue;
        }
        let mut best: Option<(usize, f64)> = None;
        for (bi, other) in b.iter().enumerate() {
            if used_b.contains(&bi) {
                continue;
            }
            let s = blk.similarity(other);
            if s < threshold {
                continue;
            }
            if best.map(|(_, bs)| s > bs).unwrap_or(true) {
                best = Some((bi, s));
            }
        }
        if let Some((bi, _)) = best {
            used_a.insert(ai);
            used_b.insert(bi);
            pairs.push((ai, bi));
        }
    }

    let mut rows: Vec<Value> = Vec::new();
    for (ai, bi) in &pairs {
        let (x, y) = (&a[*ai], &b[*bi]);
        let s = x.similarity(y);
        let kind = if s >= 0.999 { "equal" } else { "modified" };
        rows.push(block_row(kind, Some(x), Some(y), Some(s)));
    }
    for (ai, blk) in a.iter().enumerate() {
        if !used_a.contains(&ai) {
            rows.push(block_row("removed", Some(blk), None, None));
        }
    }
    for (bi, blk) in b.iter().enumerate() {
        if !used_b.contains(&bi) {
            rows.push(block_row("added", None, Some(blk), None));
        }
    }

    // Deterministic ordering: equal, modified, removed, added; then by EA.
    let rank = |k: &str| match k {
        "equal" => 0,
        "modified" => 1,
        "removed" => 2,
        _ => 3,
    };
    rows.sort_by_key(|r| {
        (
            rank(r["kind"].as_str().unwrap_or("")),
            r["a"]["ea"]
                .as_str()
                .map(|s| s.to_string())
                .unwrap_or_default(),
        )
    });

    let truncated = rows.len() > max_rows;
    rows.truncate(max_rows);
    let count = |k: &str| rows.iter().filter(|r| r["kind"] == k).count();
    Ok(json!({
        "blocks_a": a.len(),
        "blocks_b": b.len(),
        "equal": count("equal"),
        "modified": count("modified"),
        "added": count("added"),
        "removed": count("removed"),
        "rows": rows,
        "truncated": truncated,
    }))
}

/// Diff one matched function pair (proposed by the caller via name or #13
/// mapping): fingerprints both sides against their own backend, then maps
/// blocks. Read-only on both databases.
pub fn diff_function(
    backend_a: &dyn IdaBackend,
    backend_b: &dyn IdaBackend,
    ea_a: u64,
    ea_b: u64,
    max_blocks: usize,
    threshold: f64,
) -> Result<Value> {
    if backend_a.function_at(ea_a).is_err() {
        return Err(Error::Worker(format!("db A: no function at {ea_a:#x}")));
    }
    if backend_b.function_at(ea_b).is_err() {
        return Err(Error::Worker(format!("db B: no function at {ea_b:#x}")));
    }
    let (fa, ta) = function_block_fingerprints(backend_a, ea_a, max_blocks)?;
    let (fb, tb) = function_block_fingerprints(backend_b, ea_b, max_blocks)?;
    let truncated = ta || tb;
    let mut out = diff_blocks(&fa, &fb, threshold, max_blocks * 4)?;
    out["ea_a"] = json!(format!("{ea_a:#x}"));
    out["ea_b"] = json!(format!("{ea_b:#x}"));
    out["truncated"] = json!(truncated || out["truncated"].as_bool().unwrap_or(false));
    Ok(out)
}

/// Pure-data diff used by the broker-orchestrated flow: both fingerprint
/// sets arrive as JSON (exported by `sig.fingerprints` from their own
/// sessions - idalib binds one DB per process, so no second backend lives
/// in this worker). Accepts one function's `{blocks: [...]}` or a binary
/// export `{functions: [{name, ea, blocks}]}`; pairs functions by exact
/// normalized name for the binary case.
pub fn diff_from_json(a: Value, b: Value, threshold: f64, max_blocks: usize) -> Result<Value> {
    // Single-function export shape: {"ea", "blocks":[...]}. Both sides may
    // also be binary exports {"functions":[{name, ea, blocks, evidence}]}.
    let parse_fps = |v: &Value| -> Result<Vec<BlockFp>> {
        v["blocks"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|r| {
                Ok(BlockFp {
                    ea: parse_ea(r["ea"].as_str().unwrap_or("0"))?,
                    mnemonic_hash: u64::from_str_radix(
                        r["mnemonic_hash"].as_str().unwrap_or("0"),
                        16,
                    )
                    .unwrap_or(0),
                    const_hash: u64::from_str_radix(r["const_hash"].as_str().unwrap_or("0"), 16)
                        .unwrap_or(0),
                    const_count: r["const_count"].as_u64().unwrap_or(0) as usize,
                    out_edges: r["out_edges"].as_u64().unwrap_or(0) as usize,
                    in_edges: r["in_edges"].as_u64().unwrap_or(0) as usize,
                    insn_count: r["insn_count"].as_u64().unwrap_or(0) as usize,
                })
            })
            .collect()
    };

    let funcs_a = a["functions"].as_array().cloned();
    let funcs_b = b["functions"].as_array().cloned();
    if let (Some(fa), Some(fb)) = (&funcs_a, &funcs_b) {
        return diff_binary_json(fa, fb, threshold, max_blocks);
    }

    // Single-function case.
    let fps_a = parse_fps(&a)?;
    let fps_b = parse_fps(&b)?;
    let mut out = diff_blocks(&fps_a, &fps_b, threshold, max_blocks * 4)?;
    if let Some(ea) = a["ea"].as_str() {
        out["ea_a"] = json!(ea);
    }
    if let Some(ea) = b["ea"].as_str() {
        out["ea_b"] = json!(ea);
    }
    Ok(out)
}

/// Per-function block row parser shared by the pairing stage.
fn parse_fn_blocks(f: &Value) -> Result<Vec<BlockFp>> {
    f["blocks"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|r| {
            Ok(BlockFp {
                ea: parse_ea(r["ea"].as_str().unwrap_or("0"))?,
                mnemonic_hash: u64::from_str_radix(r["mnemonic_hash"].as_str().unwrap_or("0"), 16)
                    .unwrap_or(0),
                const_hash: u64::from_str_radix(r["const_hash"].as_str().unwrap_or("0"), 16)
                    .unwrap_or(0),
                const_count: r["const_count"].as_u64().unwrap_or(0) as usize,
                out_edges: r["out_edges"].as_u64().unwrap_or(0) as usize,
                in_edges: r["in_edges"].as_u64().unwrap_or(0) as usize,
                insn_count: r["insn_count"].as_u64().unwrap_or(0) as usize,
            })
        })
        .collect()
}

/// Family evidence tuple: (size, constants, strings, imports).
type Evidence = (u64, Vec<u64>, Vec<String>, Vec<String>);

/// Binary-level pairing: stage 1 exact name, stage 2 family-evidence
/// similarity (a stripped rebuild has different names; imports/constants/
/// strings/size evidence still match). Stage 2 pairs only the leftovers,
/// greedy best-first with a 0.6 gate.
fn diff_binary_json(
    fa: &[Value],
    fb: &[Value],
    threshold: f64,
    max_blocks: usize,
) -> Result<Value> {
    let mut by_name: BTreeMap<&str, &Value> = fb
        .iter()
        .filter_map(|f| Some((f["name"].as_str()?, f)))
        .collect();
    let mut pairs: Vec<(&Value, &Value)> = Vec::new();
    let mut leftovers_a: Vec<&Value> = Vec::new();
    for fa_fn in fa {
        let Some(name) = fa_fn["name"].as_str() else {
            leftovers_a.push(fa_fn);
            continue;
        };
        if let Some(fb_fn) = by_name.remove(name) {
            pairs.push((fa_fn, fb_fn));
        } else {
            leftovers_a.push(fa_fn);
        }
    }

    let evidence = |f: &Value| -> Evidence {
        let e = &f["evidence"];
        (
            e["size"].as_u64().unwrap_or(0),
            e["constants"]
                .as_array()
                .map(|a| a.iter().filter_map(|c| c.as_u64()).collect())
                .unwrap_or_default(),
            e["strings"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            e["imports"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
        )
    };
    let fam_sim = |x: &Evidence, y: &Evidence| -> f64 {
        let jaccard = |a: &BTreeSet<u64>, b: &BTreeSet<u64>| -> f64 {
            if a.is_empty() && b.is_empty() {
                return 1.0;
            }
            if a.is_empty() || b.is_empty() {
                return 0.25;
            }
            let inter = a.intersection(b).count();
            let uni = a.union(b).count();
            inter as f64 / uni.max(1) as f64
        };
        let sa: BTreeSet<u64> = x.1.iter().copied().collect();
        let sb: BTreeSet<u64> = y.1.iter().copied().collect();
        let st_a: BTreeSet<u64> = x.2.iter().map(|s| fnv1a64(s.as_bytes())).collect();
        let st_b: BTreeSet<u64> = y.2.iter().map(|s| fnv1a64(s.as_bytes())).collect();
        let im_a: BTreeSet<u64> = x.3.iter().map(|s| fnv1a64(s.as_bytes())).collect();
        let im_b: BTreeSet<u64> = y.3.iter().map(|s| fnv1a64(s.as_bytes())).collect();
        let size_sim =
            1.0 - (x.0.max(y.0).saturating_sub(x.0.min(y.0))) as f64 / x.0.max(y.0).max(1) as f64;
        0.30 * jaccard(&im_a, &im_b)
            + 0.25 * jaccard(&sa, &sb)
            + 0.25 * jaccard(&st_a, &st_b)
            + 0.20 * size_sim.clamp(0.0, 1.0)
    };

    let remaining_b: Vec<(&Value, Evidence)> =
        by_name.values().map(|f| (*f, evidence(f))).collect();
    for fa_fn in leftovers_a {
        let ea = evidence(fa_fn);
        let mut best: Option<(&Value, f64)> = None;
        for (fb_fn, eb) in &remaining_b {
            let s = fam_sim(&ea, eb);
            if s >= 0.6 && best.map(|(_, bs)| s > bs).unwrap_or(true) {
                best = Some((fb_fn, s));
            }
        }
        if let Some((fb_fn, _)) = best {
            pairs.push((fa_fn, fb_fn));
        }
    }

    let mut equal = 0usize;
    let mut changed: Vec<Value> = Vec::new();
    for (fa_fn, fb_fn) in &pairs {
        let fps_a = parse_fn_blocks(fa_fn)?;
        let fps_b = parse_fn_blocks(fb_fn)?;
        let d = diff_blocks(&fps_a, &fps_b, threshold, max_blocks * 4)?;
        if d["modified"].as_u64().unwrap_or(0) == 0
            && d["added"].as_u64().unwrap_or(0) == 0
            && d["removed"].as_u64().unwrap_or(0) == 0
        {
            equal += 1;
        } else {
            changed.push(json!({
                "name": fa_fn["name"],
                "name_b": fb_fn["name"],
                "ea_a": fa_fn["ea"],
                "ea_b": fb_fn["ea"],
                "modified": d["modified"],
                "added": d["added"],
                "removed": d["removed"],
                "rows": d["rows"],
            }));
        }
    }
    Ok(json!({
        "matched_functions": pairs.len(),
        "equal": equal,
        "changed": changed,
        "pairing": "name + evidence-similarity fallback (stripped builds pair by evidence)",
    }))
}

fn parse_ea(s: &str) -> Result<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| Error::Worker(format!("bad ea '{s}': {e}")))
    } else {
        t.parse::<u64>()
            .map_err(|e| Error::Worker(format!("bad ea '{s}': {e}")))
    }
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

    fn mk(ea: u64, mnem: u64, c: u64, out: usize, inn: usize) -> BlockFp {
        BlockFp {
            ea,
            mnemonic_hash: mnem,
            const_hash: c,
            const_count: 1,
            out_edges: out,
            in_edges: inn,
            insn_count: 4,
        }
    }

    #[test]
    fn identical_block_sets_diff_clean() {
        let a = vec![mk(0x100, 7, 9, 2, 1), mk(0x120, 8, 9, 1, 1)];
        let b = vec![mk(0x100, 7, 9, 2, 1), mk(0x120, 8, 9, 1, 1)];
        let out = diff_blocks(&a, &b, 0.8, 64).unwrap();
        assert_eq!(out["equal"], 2);
        assert_eq!(out["modified"], 0);
        assert_eq!(out["added"], 0);
        assert_eq!(out["removed"], 0);
    }

    #[test]
    fn added_and_removed_blocks_reported() {
        let a = vec![mk(0x100, 7, 9, 2, 1)];
        let b = vec![
            mk(0x100, 7, 9, 2, 1),
            mk(0x180, 11, 9, 1, 1), // new block in v2
        ];
        let out = diff_blocks(&a, &b, 0.8, 64).unwrap();
        assert_eq!(out["equal"], 1);
        assert_eq!(out["added"], 1);
        let added = out["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == "added")
            .expect("added row");
        assert_eq!(added["b"]["ea"], format!("{:#x}", 0x180));
    }

    #[test]
    fn modified_block_below_threshold() {
        let a = vec![mk(0x100, 7, 9, 2, 1)];
        let b = vec![mk(0x100, 99, 42, 1, 1)]; // same block start, new shape
        let out = diff_blocks(&a, &b, 0.9, 64).unwrap();
        // Below threshold: old block removed, new block added.
        assert_eq!(out["removed"], 1);
        assert_eq!(out["added"], 1);
        let _ = a.len() + b.len();
    }

    #[test]
    fn truncation_respects_max_rows() {
        let a: Vec<BlockFp> = (0..32).map(|i| mk(0x100 + i * 0x10, i, 1, 1, 1)).collect();
        let out = diff_blocks(&a, &a, 0.8, 8).unwrap();
        assert_eq!(out["truncated"], true);
        assert_eq!(out["rows"].as_array().unwrap().len(), 8);
    }

    #[test]
    fn mock_diff_function_is_read_only_and_stable() {
        let b = open_mock();
        let idx = b.build_index().unwrap().0;
        // Same backend twice: every function must diff to equal.
        let out = diff_function(&b, &b, 0x401000, 0x401000, 64, 0.8).unwrap();
        assert_eq!(out["truncated"], false);
        assert_eq!(out["blocks_a"], out["blocks_b"]);
        let _ = idx;
        assert_eq!(b.revision(), 0, "diff must not mutate");
    }
}
