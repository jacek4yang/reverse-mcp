//! Structured control-flow recovery (#71 搂3): CFG that preserves WASM's
//! structured block/loop/if nesting instead of flattening it into a
//! native-style graph. Each block carries its identity; `br`/`br_if`/
//! `br_table` edges resolve to the innermost matching label with provenance.

use serde::{Deserialize, Serialize};

use crate::Result;

/// Structured construct kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockKind {
    Function,
    Block,
    Loop,
    If {
        has_else: bool,
    },
    /// try/try_table when the exception-handling proposal is present.
    Try,
}

/// One structured region (block/loop/if...).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: u32,
    pub kind: BlockKind,
    /// Instruction offset of the construct's start.
    pub start_offset: u64,
    /// Offsets of branch instructions targeting this region.
    pub branch_sources: Vec<u64>,
    /// Offset of the region's End instruction (0 until closed).
    pub end_offset: u64,
    /// Region id of the parent (None for the function root).
    pub parent: Option<u32>,
}

/// Recovered structured CFG for one function body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StructuredCfg {
    pub regions: Vec<Region>,
    /// Direct calls: (call site offset, callee function index).
    pub calls: Vec<(u64, u32)>,
    /// Indirect calls: (site offset, declared type index, table index).
    pub indirect_calls: Vec<(u64, u32, u32)>,
    /// `br_table` sites with their resolved target region ids.
    pub br_tables: Vec<(u64, Vec<u32>)>,
    /// Diagnostics: mismatches/unusual structure - evidence, never silent.
    pub diagnostics: Vec<String>,
    pub operator_count: u64,
}

impl StructuredCfg {
    fn resolve_label(&self, stack: &[u32], depth: u32) -> Option<u32> {
        let idx = stack.len().checked_sub(1 + depth as usize)?;
        stack.get(idx).copied()
    }
}

/// Analyze one function body from its raw operators bytes (locals already
/// consumed; pass `ops` from `get_operators_reader`).
pub fn analyze_body(body: &[u8]) -> Result<StructuredCfg> {
    let mut cfg = StructuredCfg::default();
    let mut stack: Vec<u32> = vec![0]; // region id stack; 0 = function root
    let mut next_id = 1u32;
    let mut open_regions: Vec<(u32, u64)> = vec![(0, 0)]; // (id, start)

    let mut ops = wasmparser::OperatorsReader::new(wasmparser::BinaryReader::new(body, 0));

    while !ops.eof() {
        let pos = ops.original_position() as u64;
        let op = ops.read().map_err(|e| crate::Error::Parse {
            offset: e.offset() as u64,
            message: e.message().to_string(),
        })?;
        cfg.operator_count += 1;
        if cfg.operator_count > 5_000_000 {
            return Err(crate::Error::Budget("operators per function"));
        }
        use wasmparser::Operator::*;
        match op {
            Block { .. } => {
                let id = next_id;
                next_id += 1;
                if next_id > 1_000_000 {
                    return Err(crate::Error::Budget("region count"));
                }
                cfg.regions.push(Region {
                    id,
                    kind: BlockKind::Block,
                    start_offset: pos,
                    branch_sources: vec![],
                    end_offset: 0,
                    parent: stack.last().copied(),
                });
                stack.push(id);
                open_regions.push((id, pos));
            }
            Loop { .. } => {
                let id = next_id;
                next_id += 1;
                cfg.regions.push(Region {
                    id,
                    kind: BlockKind::Loop,
                    start_offset: pos,
                    branch_sources: vec![],
                    end_offset: 0,
                    parent: stack.last().copied(),
                });
                stack.push(id);
                open_regions.push((id, pos));
            }
            If { .. } => {
                let id = next_id;
                next_id += 1;
                cfg.regions.push(Region {
                    id,
                    kind: BlockKind::If { has_else: false },
                    start_offset: pos,
                    branch_sources: vec![],
                    end_offset: 0,
                    parent: stack.last().copied(),
                });
                stack.push(id);
                open_regions.push((id, pos));
            }
            Else => {
                if let Some(&id) = stack.last()
                    && let Some(r) = cfg.regions.iter_mut().find(|r| r.id == id)
                    && let BlockKind::If { has_else } = &mut r.kind
                {
                    *has_else = true;
                }
            }
            Try { .. } | TryTable { .. } => {
                let id = next_id;
                next_id += 1;
                cfg.regions.push(Region {
                    id,
                    kind: BlockKind::Try,
                    start_offset: pos,
                    branch_sources: vec![],
                    end_offset: 0,
                    parent: stack.last().copied(),
                });
                stack.push(id);
                open_regions.push((id, pos));
                cfg.diagnostics.push(format!(
                    "try construct at {pos:#x}: exception-handling proposal"
                ));
            }
            Br { relative_depth } => match cfg.resolve_label(&stack, relative_depth) {
                Some(t) => record_branch(&mut cfg, t, pos),
                None => cfg.diagnostics.push(format!(
                    "br at {pos:#x}: depth {relative_depth} out of range"
                )),
            },
            BrIf { relative_depth } => match cfg.resolve_label(&stack, relative_depth) {
                Some(t) => record_branch(&mut cfg, t, pos),
                None => cfg.diagnostics.push(format!(
                    "br_if at {pos:#x}: depth {relative_depth} out of range"
                )),
            },
            BrTable { targets: ref br } => {
                let mut resolved = vec![];
                for d in br.targets().flatten() {
                    if let Some(id) = cfg.resolve_label(&stack, d) {
                        resolved.push(id);
                    }
                }
                if let Some(id) = cfg.resolve_label(&stack, br.default()) {
                    resolved.push(id);
                }
                cfg.br_tables.push((pos, resolved.clone()));
                for id in resolved {
                    record_branch(&mut cfg, id, pos);
                }
            }
            Call { function_index } => {
                cfg.calls.push((pos, function_index));
            }
            CallIndirect {
                type_index,
                table_index,
                ..
            } => {
                cfg.indirect_calls.push((pos, type_index, table_index));
            }
            ReturnCall { function_index } => {
                cfg.calls.push((pos, function_index));
                cfg.diagnostics
                    .push(format!("tail call at {pos:#x}: tail-call proposal"));
            }
            ReturnCallIndirect { .. } => {
                cfg.diagnostics
                    .push(format!("tail call_indirect at {pos:#x}"));
            }
            Return | Unreachable | Drop => {}
            End => {
                stack.pop();
                if let Some((id, _start)) = open_regions.pop()
                    && let Some(r) = cfg.regions.iter_mut().find(|r| r.id == id)
                {
                    r.end_offset = pos;
                }
                if stack.is_empty() {
                    break; // function end
                }
            }
            _ => {}
        }
    }

    // Regions never closed = malformed nesting (bounded diagnostic).
    let unclosed = stack.len();
    if unclosed > 1 {
        cfg.diagnostics.push(format!(
            "{unclosed} region(s) left unclosed at function end"
        ));
    }
    Ok(cfg)
}

fn record_branch(cfg: &mut StructuredCfg, region: u32, at: u64) {
    if let Some(r) = cfg.regions.iter_mut().find(|r| r.id == region) {
        r.branch_sources.push(at);
    }
}
