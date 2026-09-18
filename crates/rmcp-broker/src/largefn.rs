//! #72 worker-side bridge: build the CfgIndex + complexity preflight +
//! region partition from the real backend, then drive per-region analysis
//! through the disposable worker with the documented fallback chain.

use serde_json::{json, Value};

use rmcp_core::error::{Error, Result};
use rmcp_core::backend::IdaBackend;

use crate::preflight::{AnalysisMode, CfgIndex, FunctionComplexity, Thresholds};
use crate::regions::{partition, Partition, PartitionOptions};

/// One-shot preflight report for a function (used by the hierarchical
/// action). Falls back to size-only classification when the flow chart is
/// unavailable (e.g. decompiler-less modules).
pub fn preflight(backend: &dyn IdaBackend, ea: u64, thresholds: &Thresholds) -> Result<(FunctionComplexity, AnalysisMode)> {
    let fns = backend.functions(0, 0)?;
    let func = fns
        .iter()
        .find(|f| {
            let s = f["ea_start"].as_u64().unwrap_or(0);
            let e = f["ea_end"].as_u64().unwrap_or(0);
            ea >= s && ea < e
        })
        .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))?
        .clone();
    let start = func["ea_start"].as_u64().unwrap_or(0);
    let end = func["ea_end"].as_u64().unwrap_or(0);
    let size = end.saturating_sub(start);

    // Blocks/edges from the backend graph (cfg kind) - bounded caps well
    // above any real giant (the #72 audit fixture: 3005 nodes).
    let mut c = FunctionComplexity {
        byte_size: size,
        decompiler_available: backend
            .capabilities()
            .get("decompile")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        ..Default::default()
    };

    if let Ok(graph) = backend.graph(
        ea,
        &rmcp_core::types::GraphParams {
            kind: "cfg".into(),
            depth: 1,
            max_nodes: 200_000,
            max_edges: 400_000,
        },
    ) {
        c.blocks = graph["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
        c.edges = graph["edges"].as_array().map(|a| a.len()).unwrap_or(0);
        c.cyclomatic = c.edges.saturating_sub(c.blocks) + 2;
    }

    let mode = c.mode(thresholds);
    Ok((c, mode))
}

/// Partition the function's CFG into virtual regions via the backend graph.
pub fn partition_function(backend: &dyn IdaBackend, ea: u64, opts: &PartitionOptions) -> Result<Partition> {
    let graph = backend.graph(
        ea,
        &rmcp_core::types::GraphParams {
            kind: "cfg".into(),
            depth: 1,
            max_nodes: 200_000,
            max_edges: 400_000,
        },
    )?;
    let nodes = graph["nodes"]
        .as_array()
        .cloned()
        .ok_or_else(|| Error::Worker("graph nodes missing".into()))?;
    let edges = graph["edges"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut eas: Vec<u64> = nodes
        .iter()
        .filter_map(|n| n["ea"].as_u64())
        .collect();
    eas.sort_unstable();
    let mut ea_index: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
    for (i, &e) in eas.iter().enumerate() {
        ea_index.insert(e, i);
    }

    let mut succs: Vec<Vec<usize>> = vec![vec![]; eas.len()];
    for e in &edges {
        let from = e["from"].as_u64().unwrap_or(0);
        let to = e["to"].as_u64().unwrap_or(0);
        if let (Some(&fi), Some(&ti)) = (ea_index.get(&from), ea_index.get(&to)) {
            if !succs[fi].contains(&ti) {
                succs[fi].push(ti);
            }
        }
    }

    let idx = CfgIndex {
        block_eas: eas.clone(),
        // Ends are next-block starts - close enough for region bookkeeping.
        block_ends: eas.iter().skip(1).copied().chain(std::iter::once(u64::MAX)).collect(),
        indirect: vec![false; eas.len()],
        direct_calls: 0,
        indirect_calls: 0,
        switches: 0,
        succs,
    };
    Ok(partition(&idx, opts))
}

/// Hierarchical analysis result for a whole giant function.
#[derive(Debug)]
pub struct HierarchicalReport {
    pub complexity: FunctionComplexity,
    pub mode: AnalysisMode,
    pub partition: Partition,
    /// Per-region outcome summaries (JSON, engine-filled).
    pub region_outcomes: Vec<Value>,
    pub dataflow: crate::dataflow::DataflowResult,
}

/// Drive hierarchical analysis of one function. Uses the caller-provided
/// async closure for per-region risky work (executed via the isolation
/// layer by the caller); this keeps broker-layer engine logic testable
/// without IDA.
pub async fn analyze_hierarchical<F, Fut>(
    backend: &dyn IdaBackend,
    ea: u64,
    thresholds: &Thresholds,
    partition_opts: &PartitionOptions,
    limits: &crate::dataflow::DataflowLimits,
    mut region_worker: F,
) -> Result<HierarchicalReport>
where
    F: FnMut(String, Vec<u64>) -> Fut,
    Fut: std::future::Future<Output = Result<(Value, Vec<crate::dataflow::Fact>)>>,
{
    let (complexity, mode) = preflight(backend, ea, thresholds)?;
    let partition = partition_function(backend, ea, partition_opts)?;

    let mut region_outcomes = Vec::new();
    let mut facts: std::collections::BTreeMap<String, crate::dataflow::RegionFacts> =
        std::collections::BTreeMap::new();

    for r in &partition.regions {
        let (summary, out_facts) = region_worker(r.region_id.clone(), r.block_eas.clone()).await?;
        region_outcomes.push(json!({
            "region_id": r.region_id,
            "role": r.role,
            "blocks": r.block_eas.len(),
            "status": "complete",
            "summary": summary,
        }));
        facts.insert(
            r.region_id.clone(),
            crate::dataflow::RegionFacts {
                region_id: r.region_id.clone(),
                out_facts,
                in_requests: vec![],
            },
        );
    }

    let dataflow = crate::dataflow::run_dataflow(&partition, &facts, limits, |_, _| vec![]);

    Ok(HierarchicalReport {
        complexity,
        mode,
        partition,
        region_outcomes,
        dataflow,
    })
}
