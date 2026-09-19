//! #72 §1: complexity preflight. A cheap, deterministic complexity profile
//! computed from IDA-native facts (flow chart + instruction scan) WITHOUT
//! whole-function Hex-Rays. Selects the analysis mode; thresholds are
//! configurable and echoed in output.

use serde::{Deserialize, Serialize};

/// Analysis mode selected by the preflight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisMode {
    /// Whole-function Hex-Rays (existing fast path).
    Normal,
    /// Region-first hierarchical analysis.
    Large,
    /// Low-level-first; whole-function Hex-Rays optional/last.
    Pathological,
}

/// Configurable, bounded thresholds. Defaults chosen from the #72 audit
/// (3000-state dispatcher: 3005 blocks => Large; 20k+ blocks would be
/// pathological).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub large_blocks: usize,
    pub large_edges: usize,
    pub large_bytes: u64,
    pub pathological_blocks: usize,
    pub pathological_edges: usize,
    pub pathological_bytes: u64,
    /// Max SCC count before forcing pathological (flattening signature).
    pub pathological_sccs: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            large_blocks: 1_500,
            large_edges: 2_500,
            large_bytes: 100_000,
            pathological_blocks: 10_000,
            pathological_edges: 20_000,
            pathological_bytes: 500_000,
            pathological_sccs: 50,
        }
    }
}

/// Cheap complexity profile from IDA-native facts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionComplexity {
    pub byte_size: u64,
    pub blocks: usize,
    pub edges: usize,
    pub cyclomatic: usize,
    /// Basic blocks that end in an indirect transfer (indjump/switch).
    pub indirect_blocks: usize,
    pub direct_calls: usize,
    pub indirect_calls: usize,
    /// Switch/jump-table sites (switch_info hits).
    pub switches: usize,
    /// Function chunks (entry + tails).
    pub chunks: usize,
    /// SCC count over the CFG (loop/dispatcher structure indicator).
    pub sccs: usize,
    /// Max SCC size (a single huge dispatcher SCC => pathological).
    pub max_scc_size: usize,
    /// Approximate loop count = back edges found by SCC over blocks.
    pub loops: usize,
    /// Per-byte instruction density (decoded instruction count / size KiB).
    pub instruction_density: f64,
    pub decompiler_available: bool,
}

impl FunctionComplexity {
    /// Classify with documented, bounded thresholds. Deterministic: the same
    /// facts always produce the same mode. A hint, not a confidence claim.
    pub fn mode(&self, t: &Thresholds) -> AnalysisMode {
        if self.blocks >= t.pathological_blocks
            || self.edges >= t.pathological_edges
            || self.byte_size >= t.pathological_bytes
            || self.sccs >= t.pathological_sccs
        {
            return AnalysisMode::Pathological;
        }
        if self.blocks >= t.large_blocks
            || self.edges >= t.large_edges
            || self.byte_size >= t.large_bytes
        {
            return AnalysisMode::Large;
        }
        AnalysisMode::Normal
    }
}

/// Raw CFG facts needed by both the preflight and the region partitioner:
/// a compact block adjacency list (start EA, successors as indices).
#[derive(Debug, Clone, Default)]
pub struct CfgIndex {
    /// Block start EAs in flow-chart order.
    pub block_eas: Vec<u64>,
    pub block_ends: Vec<u64>,
    /// Successor indices per block.
    pub succs: Vec<Vec<usize>>,
    /// Indirect-transfer flags per block.
    pub indirect: Vec<bool>,
    pub direct_calls: usize,
    pub indirect_calls: usize,
    pub switches: usize,
}

impl CfgIndex {
    pub fn edge_count(&self) -> usize {
        self.succs.iter().map(|s| s.len()).sum()
    }

    /// SCCs via iterative Tarjan (no recursion: giant CFGs must not blow
    /// the stack). Returns SCCs as block-index vectors, largest first.
    pub fn tarjan_sccs(&self) -> Vec<Vec<usize>> {
        let n = self.block_eas.len();
        let mut index = vec![usize::MAX; n];
        let mut low = vec![0usize; n];
        let mut on_stack = vec![false; n];
        let mut stack: Vec<usize> = Vec::new();
        let mut next_index = 0usize;
        let mut out: Vec<Vec<usize>> = Vec::new();

        // Iterative Tarjan: explicit call stack of (node, succ cursor).
        let mut call: Vec<(usize, usize)> = Vec::new();
        for start in 0..n {
            if index[start] != usize::MAX {
                continue;
            }
            call.push((start, 0));
            index[start] = next_index;
            low[start] = next_index;
            next_index += 1;
            stack.push(start);
            on_stack[start] = true;
            while let Some(&mut (v, ref mut ci)) = call.last_mut() {
                if *ci < self.succs[v].len() {
                    let w = self.succs[v][*ci];
                    *ci += 1;
                    if index[w] == usize::MAX {
                        index[w] = next_index;
                        low[w] = next_index;
                        next_index += 1;
                        stack.push(w);
                        on_stack[w] = true;
                        call.push((w, 0));
                    } else if on_stack[w] {
                        low[v] = low[v].min(index[w]);
                    }
                } else {
                    // v finished: propagate to parent, pop SCC if root.
                    call.pop();
                    if let Some(&mut (p, ref mut pci)) = call.last_mut() {
                        low[p] = low[p].min(low[v]);
                        let _ = pci;
                    }
                    if low[v] == index[v] {
                        let mut scc = Vec::new();
                        while let Some(w) = stack.pop() {
                            on_stack[w] = false;
                            scc.push(w);
                            if w == v {
                                break;
                            }
                        }
                        out.push(scc);
                    }
                }
            }
        }
        out.sort_by_key(|s| std::cmp::Reverse(s.len()));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_classification_matches_thresholds() {
        let t = Thresholds::default();
        let mut c = FunctionComplexity {
            byte_size: 10_000,
            blocks: 100,
            edges: 150,
            ..Default::default()
        };
        assert_eq!(c.mode(&t), AnalysisMode::Normal);
        c.blocks = 2_000;
        assert_eq!(c.mode(&t), AnalysisMode::Large);
        c.blocks = 20_000;
        assert_eq!(c.mode(&t), AnalysisMode::Pathological);
        c.blocks = 100;
        c.byte_size = 600_000;
        assert_eq!(c.mode(&t), AnalysisMode::Pathological);
        c.byte_size = 10_000;
        c.sccs = 60;
        assert_eq!(c.mode(&t), AnalysisMode::Pathological);
    }

    #[test]
    fn tarjan_sccs_finds_cycle() {
        // 0 -> 1 -> 2 -> 1 (cycle), 2 -> 3
        let idx = CfgIndex {
            block_eas: vec![0, 1, 2, 3],
            block_ends: vec![1, 2, 3, 4],
            succs: vec![vec![1], vec![2], vec![1, 3], vec![]],
            indirect: vec![false; 4],
            direct_calls: 0,
            indirect_calls: 0,
            switches: 0,
        };
        let sccs = idx.tarjan_sccs();
        let cyclic: Vec<_> = sccs.iter().filter(|s| s.len() > 1).collect();
        assert_eq!(cyclic.len(), 1, "one multi-node SCC: {sccs:?}");
        assert_eq!(cyclic[0].len(), 2, "nodes 1,2 form the SCC");
    }

    #[test]
    fn tarjan_sccs_handles_self_loop_and_disconnected() {
        let idx = CfgIndex {
            block_eas: vec![0, 1, 2],
            block_ends: vec![1, 2, 3],
            succs: vec![vec![0], vec![2], vec![]],
            indirect: vec![false; 3],
            direct_calls: 0,
            indirect_calls: 0,
            switches: 0,
        };
        let sccs = idx.tarjan_sccs();
        let cyclic: Vec<_> = sccs.iter().filter(|s| s.len() > 1).collect();
        assert_eq!(cyclic.len(), 0, "self-loop is a 1-node SCC");
        assert_eq!(sccs.len(), 3);
    }
}
