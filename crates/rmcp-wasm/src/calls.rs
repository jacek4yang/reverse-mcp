//! Direct + indirect call resolution (#71 §5). Direct calls map exactly to
//! function indices; indirect calls combine table/element/type constraints
//! into confirmed / bounded-candidate / unresolved with evidence.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::module::ModuleModel;

/// Resolution confidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Exactly one target, backed by constant index + element coverage.
    Confirmed,
    /// Bounded candidate set (type-compatible, present in element segments).
    Candidate,
    /// Cannot resolve; carries the reason.
    Unresolved,
}

/// Resolution result for one indirect call site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectTarget {
    pub site_offset: u64,
    pub table_index: u32,
    pub type_index: u32,
    pub confidence: Confidence,
    /// Confirmed/candidate function indices (deduped, ascending).
    pub targets: Vec<u32>,
    /// Evidence: element segments consulted, constants seen.
    pub evidence: Vec<String>,
    pub reason: String,
}

/// Resolve indirect call sites against the module model.
///
/// `const_indices`: per-site constant table index facts proven by the SSA
/// layer (site offset -> index). Sites absent from the map are resolved as
/// bounded candidates (never fabricated certainty).
pub fn resolve_indirect(
    model: &ModuleModel,
    sites: &[(u64, u32, u32)],
    const_indices: &BTreeMap<u64, u64>,
) -> Vec<IndirectTarget> {
    let mut out = Vec::new();
    for (site, tidx, table_index) in sites {
        let mut evidence = vec![];

        // Type-compatible candidates: functions whose type matches tidx.
        let compatible: Vec<u32> = model
            .functions
            .iter()
            .filter(|f| f.type_index == *tidx)
            .map(|f| f.index)
            .collect();

        for seg in &model.elements {
            if &seg.table_index == table_index {
                evidence.push(format!(
                    "elem {} feeds table {} at offset {:?} ({} entries)",
                    seg.index,
                    seg.table_index,
                    seg.offset,
                    seg.func_indices.len()
                ));
            }
        }

        match const_indices.get(site) {
            Some(idx) => {
                // Constant index: confirm when exactly one element segment
                // covers the slot with a function.
                let covering = model
                    .elements
                    .iter()
                    .filter(|s| &s.table_index == table_index)
                    .find(|s| {
                        s.offset.map(|o| o <= *idx).unwrap_or(false)
                            && (idx - s.offset.unwrap()) < s.func_indices.len() as u64
                    });
                match covering {
                    Some(seg) => {
                        let slot = (idx - seg.offset.unwrap()) as usize;
                        let target = seg.func_indices[slot];
                        // Cross-check the type constraint; a mismatch is
                        // evidence of dead/never-taken dispatch, not certainty.
                        let type_ok = model
                            .functions
                            .iter()
                            .find(|f| f.index == target)
                            .map(|f| f.type_index == *tidx)
                            .unwrap_or(false);
                        if type_ok {
                            evidence.push(format!(
                                "constant index {idx} -> elem {} slot {slot}",
                                seg.index
                            ));
                            out.push(IndirectTarget {
                                site_offset: *site,
                                table_index: *table_index,
                                type_index: *tidx,
                                confidence: Confidence::Confirmed,
                                targets: vec![target],
                                evidence,
                                reason: "constant index proven by SSA; element segment covers it"
                                    .into(),
                            });
                        } else {
                            out.push(IndirectTarget {
                                site_offset: *site,
                                table_index: *table_index,
                                type_index: *tidx,
                                confidence: Confidence::Unresolved,
                                targets: compatible,
                                evidence,
                                reason: format!(
                                    "constant index {idx} resolves to fn {target} with a \
                                     mismatched type (dead dispatch path?)"
                                ),
                            });
                        }
                    }
                    None => {
                        out.push(IndirectTarget {
                            site_offset: *site,
                            table_index: *table_index,
                            type_index: *tidx,
                            confidence: Confidence::Unresolved,
                            targets: compatible,
                            evidence,
                            reason: format!(
                                "constant index {idx} not covered by any element segment"
                            ),
                        });
                    }
                }
            }
            None => {
                // Non-constant: bounded to type-compatible functions actually
                // present in the table's element segments.
                let in_table: Vec<u32> = model
                    .elements
                    .iter()
                    .filter(|s| &s.table_index == table_index)
                    .flat_map(|s| s.func_indices.iter().copied())
                    .filter(|i| compatible.contains(i))
                    .collect();
                let deduped: std::collections::BTreeSet<u32> = in_table.into_iter().collect();
                let targets: Vec<u32> = deduped.into_iter().collect();
                let conf = if targets.is_empty() {
                    Confidence::Unresolved
                } else {
                    Confidence::Candidate
                };
                out.push(IndirectTarget {
                    site_offset: *site,
                    table_index: *table_index,
                    type_index: *tidx,
                    confidence: conf,
                    targets,
                    evidence,
                    reason: "runtime index; bounded to type-compatible entries in element segments"
                        .into(),
                });
            }
        }
    }
    out
}
