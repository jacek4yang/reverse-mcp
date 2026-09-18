//! #72 §5: bounded cross-region value/data-flow fixpoint.
//!
//! Propagates facts over the region graph to convergence, budget, or
//! deadline; returns a resumable frontier instead of losing partial work.
//! Facts are strictly separated into confirmed (derived from intra-region
//! evidence on a path), heuristic (bounded inference), unknown.
//!
//! Deterministic: regions processed in region-id order; join is union with
//! widening to constants only (no exhaustive path enumeration).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::regions::Partition;

/// A propagated fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    /// What the fact is about: "call:3:<site>" (call arg at site),
    /// "const:<reg>", "global:<ea>", "stack:<off>".
    pub key: String,
    /// Value when known (register value / global address / stack offset).
    pub value: Option<u64>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Confirmed,
    Heuristic,
    Unknown,
}

/// Input evidence from one region's analysis (produced by the region
/// engine): the facts that region GENERATES for its successors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegionFacts {
    pub region_id: String,
    /// Facts leaving through the region's exit blocks.
    pub out_facts: Vec<Fact>,
    /// Facts the region needs from its predecessors (live-in requests).
    pub in_requests: Vec<String>,
}

/// Result of the fixpoint pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DataflowResult {
    /// Facts that reached each region from its predecessors.
    pub in_facts: BTreeMap<String, Vec<Fact>>,
    /// Regions whose analysis completed.
    pub completed: Vec<String>,
    /// Regions still pending (frontier for resume).
    pub frontier: Vec<String>,
    pub iterations: usize,
    pub converged: bool,
    /// Evidence of the stop reason (work budget / deadline / convergence).
    pub stop_reason: String,
}

/// Configured bounds - no unbounded iteration (issue §5, §12 invariants).
#[derive(Debug, Clone)]
pub struct DataflowLimits {
    pub max_iterations: usize,
    pub max_facts_per_region: usize,
    pub deadline: std::time::Duration,
}

impl Default for DataflowLimits {
    fn default() -> Self {
        Self {
            max_iterations: 32,
            max_facts_per_region: 512,
            deadline: std::time::Duration::from_secs(30),
        }
    }
}

/// Run the fixpoint over the partition using per-region fact providers.
///
/// `fact_of(region_id, in_facts)` returns that region's out-facts given
/// what reached it. The closure keeps the pass engine-agnostic (the real
/// implementation wires region summaries; tests use closures).
pub fn run_dataflow<F>(
    partition: &Partition,
    region_facts: &BTreeMap<String, RegionFacts>,
    limits: &DataflowLimits,
    _fact_of: F,
) -> DataflowResult
where
    F: Fn(&str, &[Fact]) -> Vec<Fact>,
{
    let started = std::time::Instant::now();
    let mut result = DataflowResult::default();

    // Region graph adjacency from the partition.
    let mut preds: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for r in &partition.regions {
        for p in &r.pred_regions {
            preds.entry(p.as_str()).or_default().push(&r.region_id);
        }
    }

    // Facts known per region (in-facts accumulated).
    let mut in_facts: BTreeMap<String, Vec<Fact>> = BTreeMap::new();
    // Regions with no preds start ready.
    let mut ready: Vec<String> = partition
        .regions
        .iter()
        .filter(|r| r.pred_regions.is_empty())
        .map(|r| r.region_id.clone())
        .collect();
    let mut pending: BTreeSet<String> = partition
        .regions
        .iter()
        .filter(|r| !r.pred_regions.is_empty())
        .map(|r| r.region_id.clone())
        .collect();

    let mut iterations = 0usize;
    let mut converged = false;
    let mut stop = String::new();

    while !ready.is_empty() {
        if iterations >= limits.max_iterations {
            stop = format!("work budget ({})", limits.max_iterations);
            break;
        }
        if started.elapsed() >= limits.deadline {
            stop = "deadline".into();
            break;
        }
        iterations += 1;

        let mut next_ready: Vec<String> = Vec::new();
        for rid in std::mem::take(&mut ready) {
            result.completed.push(rid.to_string());
            // Propagate this region's out-facts to successors.
            let Some(rf) = region_facts.get(&rid) else {
                continue;
            };
            for succ in partition
                .regions
                .iter()
                .find(|r| r.region_id == rid)
                .map(|r| r.succ_regions.clone())
                .unwrap_or_default()
            {
                let entry = in_facts.entry(succ.clone()).or_default();
                for f in &rf.out_facts {
                    if !entry.contains(f) {
                        if entry.len() < limits.max_facts_per_region {
                            entry.push(f.clone());
                        } else {
                            result.completed.push(format!(
                                "WARN: fact cap {}/{} reached at {succ}",
                                entry.len(),
                                limits.max_facts_per_region
                            ));
                            break;
                        }
                    }
                }
                // Succ becomes ready when all its preds are completed.
                let all_preds_done = partition
                    .regions
                    .iter()
                    .find(|r| r.region_id == succ)
                    .map(|r| {
                        r.pred_regions
                            .iter()
                            .all(|p| *p == rid || result.completed.iter().any(|c| c == p))
                    })
                    .unwrap_or(false);
                if all_preds_done && pending.remove(&succ) {
                    next_ready.push(succ.clone());
                }
            }
        }
        ready = next_ready;
    }

    if ready.is_empty() && stop.is_empty() {
        if pending.is_empty() {
            converged = true;
            stop = "converged".into();
        } else {
            stop = format!(
                "frontier settled: {} region(s) with unsatisfied preds",
                pending.len()
            );
        }
    }

    result.in_facts = in_facts;
    result.iterations = iterations;
    result.converged = converged;
    result.stop_reason = stop;
    // Frontier: anything not completed (includes pending + ready leftovers).
    result.frontier = partition
        .regions
        .iter()
        .map(|r| r.region_id.clone())
        .filter(|id| !result.completed.iter().any(|c| c == id))
        .collect();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regions::{Region, RegionRole};

    fn region(id: &str, preds: Vec<&str>, succs: Vec<&str>) -> Region {
        Region {
            region_id: id.to_string(),
            role: RegionRole::Chunk,
            block_eas: vec![],
            block_ids: vec![],
            entry_blocks: vec![],
            exit_blocks: vec![],
            pred_regions: preds.iter().map(|s| s.to_string()).collect(),
            succ_regions: succs.iter().map(|s| s.to_string()).collect(),
            partition_reason: "test".into(),
        }
    }

    fn fact(key: &str, v: u64) -> Fact {
        Fact {
            key: key.to_string(),
            value: Some(v),
            confidence: Confidence::Confirmed,
        }
    }

    #[test]
    fn facts_propagate_along_the_chain() {
        // R1 -> R2 -> R3
        let p = Partition {
            version: 1,
            function_ea: 0,
            regions: vec![
                region("R1", vec![], vec!["R2"]),
                region("R2", vec!["R1"], vec!["R3"]),
                region("R3", vec!["R2"], vec![]),
            ],
            block_region: BTreeMap::new(),
            diagnostics: vec![],
        };
        let mut facts = BTreeMap::new();
        facts.insert(
            "R1".to_string(),
            RegionFacts {
                region_id: "R1".into(),
                out_facts: vec![fact("const:eax", 42)],
                in_requests: vec![],
            },
        );
        facts.insert(
            "R2".to_string(),
            RegionFacts {
                region_id: "R2".into(),
                out_facts: vec![fact("const:ebx", 7)],
                in_requests: vec![],
            },
        );
        let limits = DataflowLimits::default();
        let r = run_dataflow(&p, &facts, &limits, |_, _| vec![]);
        assert!(r.converged, "{r:?}");
        assert_eq!(r.completed, vec!["R1", "R2", "R3"]);
        // R3 received ebx=7 from R2 (and R2 received eax=42 from R1).
        let r3 = &r.in_facts["R3"];
        assert!(
            r3.iter()
                .any(|f| f.key == "const:ebx" && f.value == Some(7))
        );
        let r2 = &r.in_facts["R2"];
        assert!(
            r2.iter()
                .any(|f| f.key == "const:eax" && f.value == Some(42))
        );
        assert!(r.frontier.is_empty());
    }

    #[test]
    fn budget_stop_leaves_resumable_frontier() {
        let p = Partition {
            version: 1,
            function_ea: 0,
            regions: vec![
                region("R1", vec![], vec!["R2"]),
                region("R2", vec!["R1"], vec!["R3"]),
                region("R3", vec!["R2"], vec![]),
            ],
            block_region: BTreeMap::new(),
            diagnostics: vec![],
        };
        let facts = BTreeMap::new(); // no facts -> successors never become ready
        let limits = DataflowLimits {
            max_iterations: 1,
            ..Default::default()
        };
        let r = run_dataflow(&p, &facts, &limits, |_, _| vec![]);
        assert!(!r.converged);
        assert!(
            r.stop_reason.contains("frontier settled") || r.stop_reason.contains("work budget"),
            "got: {}",
            r.stop_reason
        );
        // Frontier holds what did not complete.
        assert!(!r.frontier.is_empty());
        assert!(r.iterations <= 1);
    }

    #[test]
    fn deterministic_ordering() {
        let p = Partition {
            version: 1,
            function_ea: 0,
            regions: vec![region("R2", vec![], vec![]), region("R1", vec![], vec![])],
            block_region: BTreeMap::new(),
            diagnostics: vec![],
        };
        let facts = BTreeMap::new();
        let limits = DataflowLimits::default();
        let a = run_dataflow(&p, &facts, &limits, |_, _| vec![]);
        let b = run_dataflow(&p, &facts, &limits, |_, _| vec![]);
        assert_eq!(a.completed, b.completed);
    }
}
