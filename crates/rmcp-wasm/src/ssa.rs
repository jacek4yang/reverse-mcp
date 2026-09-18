//! Operand-stack-to-SSA value analysis (#71 搂4): a bounded single-pass
//! abstract interpreter over the function body that produces SSA names,
//! use-def chains, and constant facts. Never executes the module.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::Result;

/// SSA value reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SsaName {
    /// Producing instruction offset (0 for params/entry state).
    pub def_offset: u64,
    /// Unique index in def order.
    pub version: u32,
}

/// What we know about a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueFact {
    pub name: SsaName,
    pub ty: String,
    /// Constant value when the producing instruction is a const.
    pub constant: Option<i128>,
    /// Offsets of instructions that consumed this value (use chain).
    pub uses: Vec<u64>,
    /// Short producer description ("i32.const", "local.get 3", "i32.add").
    pub produced_by: String,
}

/// Result of the stack-to-SSA pass over one function.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsaBody {
    /// Values in def order.
    pub values: Vec<ValueFact>,
    /// (site offset, local index, value written).
    pub local_stores: Vec<(u64, u32, SsaName)>,
    /// (site offset, local index, value read).
    pub local_loads: Vec<(u64, u32, SsaName)>,
    /// (site offset, global index, value read).
    pub global_loads: Vec<(u64, u32, SsaName)>,
    /// (site offset, global index, value written).
    pub global_stores: Vec<(u64, u32, SsaName)>,
    /// (site offset, address value, byte width, is_store).
    pub memory_ops: Vec<(u64, SsaName, u32, bool)>,
    /// (site offset, table index value).
    pub table_index_ops: Vec<(u64, SsaName)>,
    /// Branch conditions: (site, condition value).
    pub branch_conditions: Vec<(u64, SsaName)>,
    /// (site, callee, arg SSA names in call order).
    pub call_args: Vec<(u64, u32, Vec<SsaName>)>,
    /// Diagnostics (opaque ops, malformed stack usage under our model).
    pub diagnostics: Vec<String>,
    pub operator_count: u64,
}

/// Analyze one function body. `n_params` seeds the local slots.
pub fn analyze_values(body: &[u8], n_params: usize) -> Result<SsaBody> {
    let mut out = SsaBody::default();
    let mut stack: Vec<SsaName> = vec![];
    let mut version = 0u32;
    let mut locals: BTreeMap<u32, SsaName> = BTreeMap::new();
    for i in 0..n_params {
        let name = SsaName {
            def_offset: 0,
            version,
        };
        version += 1;
        out.values.push(ValueFact {
            name: name.clone(),
            ty: "param".into(),
            constant: None,
            uses: vec![],
            produced_by: format!("param {i}"),
        });
        locals.insert(i as u32, name);
    }

    let mut ops = wasmparser::OperatorsReader::new(wasmparser::BinaryReader::new(body, 0));

    macro_rules! def_val {
        ($ty:expr, $by:expr, $const:expr) => {{
            let name = SsaName {
                def_offset: ops.original_position() as u64,
                version,
            };
            version += 1;
            out.values.push(ValueFact {
                name: name.clone(),
                ty: $ty.to_string(),
                constant: $const,
                uses: vec![],
                produced_by: $by.to_string(),
            });
            stack.push(name);
        }};
    }

    macro_rules! pop_use {
        () => {{
            let at = ops.original_position() as u64;
            match stack.pop() {
                Some(v) => {
                    if let Some(f) = out.values.iter_mut().find(|f| f.name == v) {
                        f.uses.push(at);
                    }
                    Some(v)
                }
                None => {
                    out.diagnostics.push(format!("stack underflow at {at:#x}"));
                    None
                }
            }
        }};
    }

    fn const_of(out: &SsaBody, v: &Option<SsaName>) -> Option<i128> {
        v.as_ref()
            .and_then(|n| out.values.iter().find(|f| f.name == *n))
            .and_then(|f| f.constant)
    }

    while !ops.eof() {
        let pos = ops.original_position() as u64;
        let op = ops.read().map_err(|e| crate::Error::Parse {
            offset: e.offset() as u64,
            message: e.message().to_string(),
        })?;
        out.operator_count += 1;
        if out.operator_count > 5_000_000 {
            return Err(crate::Error::Budget("operators per function (ssa)"));
        }
        use wasmparser::Operator::*;
        match op {
            I32Const { value } => def_val!("i32", "i32.const", Some(value as i128)),
            I64Const { value } => def_val!("i64", "i64.const", Some(value as i128)),
            F32Const { value } => def_val!("f32", "f32.const", Some(value.bits() as i128)),
            F64Const { value } => def_val!("f64", "f64.const", Some(value.bits() as i128)),
            LocalGet { local_index } => {
                if let Some(v) = locals.get(&local_index).cloned() {
                    if let Some(f) = out.values.iter_mut().find(|f| f.name == v) {
                        f.uses.push(pos);
                    }
                    out.local_loads.push((pos, local_index, v.clone()));
                    stack.push(v);
                }
            }
            LocalSet { local_index } => {
                if let Some(v) = pop_use!() {
                    out.local_stores.push((pos, local_index, v.clone()));
                    locals.insert(local_index, v);
                }
            }
            LocalTee { local_index } => {
                if let Some(v) = pop_use!() {
                    out.local_stores.push((pos, local_index, v.clone()));
                    locals.insert(local_index, v.clone());
                    stack.push(v);
                }
            }
            GlobalGet { global_index } => {
                def_val!("global", format!("global.get {global_index}"), None);
                if let Some(v) = stack.last().cloned() {
                    out.global_loads.push((pos, global_index, v));
                }
            }
            GlobalSet { global_index } => {
                if let Some(v) = pop_use!() {
                    out.global_stores.push((pos, global_index, v));
                }
            }
            I32Load { memarg } | I64Load { memarg } => {
                let width = matches!(op, I32Load { .. }).then_some(4).unwrap_or(8);
                let addr = pop_use!();
                def_val!(
                    if width == 4 { "i32" } else { "i64" },
                    format!("load +{}", memarg.offset),
                    None
                );
                if let Some(a) = addr {
                    out.memory_ops.push((pos, a, width, false));
                }
            }
            I32Store { memarg } | I64Store { memarg } => {
                let width = matches!(op, I32Store { .. }).then_some(4).unwrap_or(8);
                let val = pop_use!();
                let addr = pop_use!();
                if let (Some(a), Some(v)) = (addr, val) {
                    if let Some(f) = out.values.iter_mut().find(|f| f.name == v) {
                        f.uses.push(pos);
                    }
                    out.memory_ops.push((pos, a, width, true));
                }
                let _ = memarg;
            }
            I32Add | I32Sub | I32Mul | I32And | I32Or | I32Xor => {
                let b = pop_use!();
                let a = pop_use!();
                let mnemonic = match op {
                    I32Add => "i32.add",
                    I32Sub => "i32.sub",
                    I32Mul => "i32.mul",
                    I32And => "i32.and",
                    I32Or => "i32.or",
                    _ => "i32.xor",
                };
                // Single-step constant folding (bounded, no loops).
                let folded = match (const_of(&out, &a), const_of(&out, &b)) {
                    (Some(x), Some(y)) => match op {
                        I32Add => Some(((x + y) as i32) as i128),
                        I32Sub => Some(((x - y) as i32) as i128),
                        I32Mul => Some(((x * y) as i32) as i128),
                        _ => None,
                    },
                    _ => None,
                };
                def_val!("i32", mnemonic, folded);
            }
            I32Eqz => {
                pop_use!();
                def_val!("i32", "i32.eqz", None);
            }
            I32Eq | I32Ne | I32LtU | I32GeU => {
                pop_use!();
                pop_use!();
                let mnemonic = match op {
                    I32Eq => "i32.eq",
                    I32Ne => "i32.ne",
                    I32LtU => "i32.lt_u",
                    _ => "i32.ge_u",
                };
                def_val!("i32", mnemonic, None);
            }
            BrIf { relative_depth } => {
                if let Some(c) = pop_use!() {
                    out.branch_conditions.push((pos, c));
                }
                let _ = relative_depth;
            }
            BrTable { targets: ref br } => {
                if let Some(i) = pop_use!() {
                    out.table_index_ops.push((pos, i));
                }
                let _ = br;
            }
            Call { function_index } => {
                // Arg stack effect needs the callee type; the calls layer
                // supplies it. Here we record the site; args patched there.
                out.call_args.push((pos, function_index, vec![]));
            }
            Return => {
                pop_use!();
            }
            Drop => {
                pop_use!();
            }
            End => break,
            other => {
                out.diagnostics.push(format!(
                    "opaque op at {pos:#x}: {:?}",
                    std::mem::discriminant(&other)
                ));
            }
        }
    }

    Ok(out)
}
