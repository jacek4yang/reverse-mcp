//! #72: broker-side adapters from worker JSON responses (function_at /
//! graph kind=cfg) to the complexity preflight and the virtual region
//! partition. Pure functions over JSON - unit-testable without IDA.

use serde_json::Value;

use crate::preflight::{CfgIndex, FunctionComplexity};
use crate::regions::{Partition, PartitionOptions, partition};

/// Build the complexity profile from the worker's `function_at` response
/// plus its `graph kind=cfg` response. No Hex-Rays involved: preflight must
/// stay cheap even for pathological functions.
pub fn complexity_from_function_graph(
    func: &Value,
    graph: &Value,
    decompiler_available: bool,
) -> FunctionComplexity {
    let start = func["ea_start"].as_u64().unwrap_or(0);
    let end = func["ea_end"].as_u64().unwrap_or(0);

    let mut c = FunctionComplexity {
        byte_size: end.saturating_sub(start),
        decompiler_available,
        ..Default::default()
    };

    let nodes = graph["nodes"].as_array();
    let edges = graph["edges"].as_array();
    c.blocks = nodes.map(|a| a.len()).unwrap_or(0);
    c.edges = edges.map(|a| a.len()).unwrap_or(0);
    c.cyclomatic = c.edges.saturating_sub(c.blocks) + 2;

    // Per-node flags when present (backend may enrich the cfg graph).
    if let Some(ns) = nodes {
        c.indirect_blocks = ns
            .iter()
            .filter(|n| n["indirect"].as_bool().unwrap_or(false))
            .count();
        c.chunks = ns
            .iter()
            .filter(|n| n["chunk"].as_bool().unwrap_or(false))
            .count();
    }
    c
}

/// Build the CfgIndex (block adjacency) from the worker's `graph kind=cfg`
/// response: nodes give block starts, edges give successor pairs.
pub fn cfg_index_from_graph(graph: &Value) -> CfgIndex {
    let mut eas: Vec<u64> = graph["nodes"]
        .as_array()
        .map(|ns| ns.iter().filter_map(|n| n["ea"].as_u64()).collect())
        .unwrap_or_default();
    eas.sort_unstable();
    eas.dedup();

    let mut ea_index: std::collections::HashMap<u64, usize> =
        std::collections::HashMap::with_capacity(eas.len());
    for (i, &e) in eas.iter().enumerate() {
        ea_index.insert(e, i);
    }

    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); eas.len()];
    let mut indirect = vec![false; eas.len()];
    for e in graph["edges"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
    {
        let (Some(&fi), Some(ti)) = (
            ea_index.get(&e["from"].as_u64().unwrap_or(0)),
            ea_index.get(&e["to"].as_u64().unwrap_or(0)).copied(),
        ) else {
            continue;
        };
        if ti >= succs.len() {
            continue;
        }
        if !succs[fi].contains(&ti) {
            succs[fi].push(ti);
        }
    }
    // Indirect-transfer blocks: successors the backend could not resolve to
    // a node in this function (edge target outside the block set was
    // dropped above; backend marks such blocks explicitly when it can).
    for (i, n) in graph["nodes"]
        .as_array()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        if i < indirect.len() {
            indirect[i] = n["indirect"].as_bool().unwrap_or(false);
        }
    }

    CfgIndex {
        block_eas: eas.clone(),
        // Ends are next-block starts - close enough for region bookkeeping.
        block_ends: eas
            .iter()
            .skip(1)
            .copied()
            .chain(std::iter::once(u64::MAX))
            .collect(),
        succs,
        indirect,
        direct_calls: 0,
        indirect_calls: 0,
        switches: 0,
    }
}

/// Partition the function CFG (worker graph JSON) into virtual regions.
pub fn partition_from_graph(graph: &Value, ea: u64, opts: &PartitionOptions) -> Partition {
    let mut p = partition(&cfg_index_from_graph(graph), opts);
    // The partitioner keys function_ea off the first block; anchor it to the
    // requested function entry for stable cache keys / diagnostics.
    p.function_ea = ea;
    p
}
