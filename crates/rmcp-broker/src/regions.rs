//! #72 §2: virtual region partitioning.
//!
//! Builds an analysis-only region graph over a function's CFG. The real
//! IDA function is NEVER mutated: regions are pure bookkeeping keyed by
//! block EAs, stable within a DB revision.
//!
//! Partition strategy (deterministic):
//! 1. Tarjan SCCs over the CFG. Multi-node SCCs (loops / flattened
//!    dispatchers) become loop regions; big SCCs (>= min_dispatcher_scc)
//!    are marked role=dispatcher.
//! 2. Remaining single-node SCCs are grouped into bounded linear chunks of
//!    `max_chunk_blocks` in flow-chart order (fallback chunking, issue §2).
//! 3. Every region records entry/exit blocks, predecessor/successor
//!    regions, counts, and the reason it exists.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::preflight::CfgIndex;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionRole {
    /// Loop / SCC region.
    Loop,
    /// Flattened-dispatcher-like SCC (large, many in-edges).
    Dispatcher,
    /// Linear fallback chunk.
    Chunk,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub region_id: String,
    pub role: RegionRole,
    /// Constituent block start EAs (flow-chart order).
    pub block_eas: Vec<u64>,
    /// Block indices into the CfgIndex (stable within revision).
    pub block_ids: Vec<usize>,
    /// Entry block EAs (blocks with a predecessor outside the region).
    pub entry_blocks: Vec<u64>,
    /// Exit block EAs (blocks with a successor outside the region).
    pub exit_blocks: Vec<u64>,
    pub pred_regions: Vec<String>,
    pub succ_regions: Vec<String>,
    pub partition_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    /// Partition algorithm version - part of every cache key: a partition
    /// upgrade must never serve stale region results.
    pub version: u32,
    pub function_ea: u64,
    pub regions: Vec<Region>,
    /// Block index -> region id.
    pub block_region: BTreeMap<usize, String>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PartitionOptions {
    /// Max blocks per fallback chunk.
    pub max_chunk_blocks: usize,
    /// SCCs at or above this size are dispatchers.
    pub min_dispatcher_scc: usize,
}

impl Default for PartitionOptions {
    fn default() -> Self {
        Self {
            max_chunk_blocks: 64,
            min_dispatcher_scc: 8,
        }
    }
}

/// Partition a CFG index into the virtual region graph.
pub fn partition(idx: &CfgIndex, opts: &PartitionOptions) -> Partition {
    let mut p = Partition {
        version: 1,
        function_ea: idx.block_eas.first().copied().unwrap_or(0),
        regions: vec![],
        block_region: BTreeMap::new(),
        diagnostics: vec![],
    };

    let sccs = idx.tarjan_sccs();
    // Block index -> SCC slot (single-node SCCs will be re-bucketed).
    let mut in_loop = vec![false; idx.block_eas.len()];
    let mut loop_of_block: BTreeMap<usize, usize> = BTreeMap::new();
    for (slot, scc) in sccs.iter().enumerate() {
        if scc.len() > 1 {
            for &b in scc {
                in_loop[b] = true;
                loop_of_block.insert(b, slot);
            }
        }
    }

    // 1. Loop/dispatcher regions from multi-node SCCs.
    let mut region_counter = 0usize;
    let mut next_id = || {
        region_counter += 1;
        format!("R{region_counter}")
    };
    for scc in &sccs {
        if scc.len() <= 1 {
            continue;
        }
        let id = next_id();
        let mut blocks_sorted: Vec<usize> = scc.clone();
        blocks_sorted.sort_unstable();
        for &b in &blocks_sorted {
            p.block_region.insert(b, id.clone());
        }
        let role = if scc.len() >= opts.min_dispatcher_scc {
            RegionRole::Dispatcher
        } else {
            RegionRole::Loop
        };
        let (entry, exit) = entry_exit_blocks(idx, &blocks_sorted);
        p.regions.push(Region {
            region_id: id,
            role,
            block_eas: blocks_sorted.iter().map(|&b| idx.block_eas[b]).collect(),
            block_ids: blocks_sorted,
            entry_blocks: entry,
            exit_blocks: exit,
            pred_regions: vec![],
            succ_regions: vec![],
            partition_reason: format!("SCC of {} blocks (loop/dispatcher structure)", scc.len()),
        });
    }

    // 2. Fallback chunks over the remaining single-node blocks, in
    //    flow-chart order.
    let singles: Vec<usize> = (0..idx.block_eas.len()).filter(|&b| !in_loop[b]).collect();
    for chunk in singles.chunks(opts.max_chunk_blocks) {
        let id = next_id();
        let blocks: Vec<usize> = chunk.to_vec();
        for &b in &blocks {
            p.block_region.insert(b, id.clone());
        }
        let (entry, exit) = entry_exit_blocks(idx, &blocks);
        p.regions.push(Region {
            region_id: id,
            role: RegionRole::Chunk,
            block_eas: blocks.iter().map(|&b| idx.block_eas[b]).collect(),
            block_ids: blocks.clone(),
            entry_blocks: entry,
            exit_blocks: exit,
            pred_regions: vec![],
            succ_regions: vec![],
            partition_reason: format!(
                "linear chunk of {} blocks (fallback bucketing)",
                blocks.len()
            ),
        });
    }

    // 3. Cross-region edges from block-level successors.
    let region_of = |b: usize| -> Option<&String> { p.block_region.get(&b) };
    let mut pred: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut succ: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for b in 0..idx.block_eas.len() {
        let Some(rb) = region_of(b).cloned() else {
            continue;
        };
        for &s in &idx.succs[b] {
            let Some(rs) = region_of(s).cloned() else {
                continue;
            };
            if rs == rb {
                continue;
            }
            succ.entry(rb.clone()).or_default().push(rs.clone());
            pred.entry(rs.clone()).or_default().push(rb.clone());
        }
    }
    for r in &mut p.regions {
        if let Some(ps) = pred.get(&r.region_id) {
            r.pred_regions = dedup_sorted(ps);
        }
        if let Some(ss) = succ.get(&r.region_id) {
            r.succ_regions = dedup_sorted(ss);
        }
    }

    p.diagnostics.push(format!(
        "{} regions from {} blocks ({} loop/dispatcher, {} chunks)",
        p.regions.len(),
        idx.block_eas.len(),
        p.regions
            .iter()
            .filter(|r| r.role != RegionRole::Chunk)
            .count(),
        p.regions
            .iter()
            .filter(|r| r.role == RegionRole::Chunk)
            .count(),
    ));
    p
}

fn dedup_sorted(v: &[String]) -> Vec<String> {
    let mut out: Vec<String> = v.to_vec();
    out.sort();
    out.dedup();
    out
}

/// Entry blocks: have a pred outside the set (or no preds). Exit blocks:
/// have a succ outside the set (or no succs).
fn entry_exit_blocks(idx: &CfgIndex, blocks: &[usize]) -> (Vec<u64>, Vec<u64>) {
    let set: std::collections::BTreeSet<usize> = blocks.iter().copied().collect();
    let mut entry = Vec::new();
    let mut exit = Vec::new();
    for &b in blocks {
        let external_pred = idx
            .succs
            .iter()
            .enumerate()
            .filter(|(p, _)| !set.contains(p))
            .any(|(_, ss)| ss.contains(&b));
        let has_external_succ = idx.succs[b].iter().any(|s| !set.contains(s));
        let internal_succ = idx.succs[b].iter().any(|s| set.contains(s));
        let isolated = !internal_succ && !external_pred;
        if external_pred || isolated || blocks.len() == 1 {
            entry.push(idx.block_eas[b]);
        }
        if has_external_succ || idx.succs[b].is_empty() {
            exit.push(idx.block_eas[b]);
        }
    }
    entry.sort_unstable();
    exit.sort_unstable();
    (entry, exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx_from(succs: Vec<Vec<usize>>) -> CfgIndex {
        let n = succs.len();
        CfgIndex {
            block_eas: (0..n as u64).map(|i| 0x1000 + i * 0x10).collect(),
            block_ends: (0..n as u64).map(|i| 0x1000 + i * 0x10 + 0xF).collect(),
            succs,
            indirect: vec![false; n],
            direct_calls: 0,
            indirect_calls: 0,
            switches: 0,
        }
    }

    #[test]
    fn linear_chain_partitions_into_bounded_chunks() {
        // 100 blocks in a chain -> 2 chunks of 64.
        let succs: Vec<Vec<usize>> = (0..100)
            .map(|i| if i < 99 { vec![i + 1] } else { vec![] })
            .collect();
        let idx = idx_from(succs);
        let p = partition(&idx, &PartitionOptions::default());
        assert_eq!(p.regions.len(), 2);
        assert!(p.regions.iter().all(|r| r.role == RegionRole::Chunk));
        assert_eq!(p.block_region.len(), 100);
        // Region adjacency: chunk 0 -> chunk 1.
        let r0 = &p.regions[0];
        let r1 = &p.regions[1];
        assert!(r0.succ_regions.contains(&r1.region_id));
        assert!(r1.pred_regions.contains(&r0.region_id));
    }

    #[test]
    fn loop_scc_becomes_loop_region() {
        // 0 -> 1 -> 2 -> 1 (loop), 2 -> 3 -> 4 (tail chain)
        let idx = idx_from(vec![vec![1], vec![2], vec![1, 3], vec![4], vec![]]);
        let p = partition(&idx, &PartitionOptions::default());
        let loop_region = p
            .regions
            .iter()
            .find(|r| r.role == RegionRole::Loop)
            .expect("loop region");
        assert_eq!(loop_region.block_ids, vec![1, 2]);
        // Loop's succs include the tail chunk (3,4 in another region).
        assert!(!loop_region.succ_regions.is_empty());
        assert_eq!(p.block_region.len(), 5);
    }

    #[test]
    fn dispatcher_scc_flagged() {
        // 10-node SCC -> dispatcher.
        let mut succs: Vec<Vec<usize>> = (0..10).map(|i| vec![(i + 1) % 10]).collect();
        succs.push(vec![]);
        succs.push(vec![]);
        succs[9] = vec![0, 10]; // ring close + exit edge
        succs[10] = vec![11];
        let idx = idx_from(succs);
        let p = partition(&idx, &PartitionOptions::default());
        let d = p
            .regions
            .iter()
            .find(|r| r.role == RegionRole::Dispatcher)
            .expect("dispatcher region");
        assert_eq!(d.block_ids.len(), 10);
    }

    #[test]
    fn stable_identity_for_same_input() {
        let idx = idx_from(vec![vec![1], vec![2], vec![]]);
        let a = partition(&idx, &PartitionOptions::default());
        let b = partition(&idx, &PartitionOptions::default());
        assert_eq!(a.regions.len(), b.regions.len());
        for (ra, rb) in a.regions.iter().zip(&b.regions) {
            assert_eq!(ra.region_id, rb.region_id);
            assert_eq!(ra.block_eas, rb.block_eas);
        }
    }
}
