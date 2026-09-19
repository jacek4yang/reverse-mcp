//! WASM-native C-like pseudocode (#71 搂7): deterministic, evidence-backed,
//! built from the structured CFG + SSA layers. Explicitly NOT Hex-Rays
//! output and never labeled as such.

use std::collections::BTreeMap;

use crate::Result;
use crate::cfg::StructuredCfg;
use crate::module::ModuleModel;

/// Render pseudocode for one function.
///
/// Deterministic: same module bytes + same options = byte-identical output.
pub fn render(
    model: &ModuleModel,
    func_index: u32,
    body: &[u8],
    cfg: &StructuredCfg,
) -> Result<String> {
    let mut out = String::new();
    let func = model
        .functions
        .iter()
        .find(|f| f.index == func_index)
        .ok_or_else(|| crate::Error::Ambiguous(format!("function {func_index} not in model")))?;
    let ty = model
        .types
        .get(func.type_index as usize)
        .cloned()
        .unwrap_or(crate::module::FuncType {
            params: vec![],
            results: vec![],
        });

    let fname = func
        .name
        .clone()
        .unwrap_or_else(|| format!("wasm_fn_{}", func.index));
    let params = ty
        .params
        .iter()
        .enumerate()
        .map(|(i, t)| format!("{t} a{i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let ret = match ty.results.len() {
        0 => "void".to_string(),
        1 => ty.results[0].clone(),
        n => format!("(multi {n})"), // multi-value kept explicit
    };
    out.push_str("// WASM-native pseudocode (reverse-mcp; not Hex-Rays output)\n");
    out.push_str(&format!(
        "// func {func_index} @ code {:#x} ({} bytes)\n",
        func.code_offset, func.code_size
    ));
    out.push_str(&format!("{ret} {fname}({params}) {{\n"));

    // Straight rendering of the structured semantics - NOT a native-style
    // CFG flattening; block/loop/if nesting maps to braces.
    let mut ops = wasmparser::OperatorsReader::new(wasmparser::BinaryReader::new(body, 0));
    let mut indent = 1usize;
    let mut estack: Vec<String> = vec![];
    let mut names: BTreeMap<u32, String> = BTreeMap::new();
    let mut locals_decl = String::new();
    for i in 0..ty.params.len() {
        names.insert(i as u32, format!("a{i}"));
    }
    for (i, t) in func.local_types.iter().enumerate() {
        let idx = (ty.params.len() + i) as u32;
        names.entry(idx).or_insert_with(|| format!("l{idx}"));
        locals_decl.push_str(&format!("  {t} l{idx};\n"));
    }
    if !locals_decl.is_empty() {
        out.push_str(&locals_decl);
    }

    while !ops.eof() {
        let pos = ops.original_position() as u64;
        let op = ops.read().map_err(|e| crate::Error::Parse {
            offset: e.offset() as u64,
            message: e.message().to_string(),
        })?;
        use wasmparser::Operator::*;
        match op {
            I32Const { value } => estack.push(format!("{value}")),
            I64Const { value } => estack.push(format!("{value}L")),
            LocalGet { local_index } => {
                let n = names
                    .get(&local_index)
                    .cloned()
                    .unwrap_or_else(|| format!("l{local_index}"));
                estack.push(n);
            }
            LocalSet { local_index } => {
                let v = estack.pop().unwrap_or_default();
                let n = names
                    .get(&local_index)
                    .cloned()
                    .unwrap_or_else(|| format!("l{local_index}"));
                out.push_str(&format!("{}{} = {};\n", "  ".repeat(indent), n, v));
            }
            LocalTee { local_index } => {
                let v = estack.pop().unwrap_or_default();
                let n = names
                    .get(&local_index)
                    .cloned()
                    .unwrap_or_else(|| format!("l{local_index}"));
                out.push_str(&format!("{}{} = {};\n", "  ".repeat(indent), n, v));
                estack.push(n);
            }
            GlobalGet { global_index } => estack.push(format!("g{global_index}")),
            GlobalSet { global_index } => {
                let v = estack.pop().unwrap_or_default();
                out.push_str(&format!(
                    "{}g{global_index} = {};\n",
                    "  ".repeat(indent),
                    v
                ));
            }
            I32Load { memarg } => {
                let a = estack.pop().unwrap_or_default();
                estack.push(format!("*(i32*)(mem+{a}+{})", memarg.offset));
            }
            I64Load { memarg } => {
                let a = estack.pop().unwrap_or_default();
                estack.push(format!("*(i64*)(mem+{a}+{})", memarg.offset));
            }
            I32Store { memarg } => {
                let v = estack.pop().unwrap_or_default();
                let a = estack.pop().unwrap_or_default();
                out.push_str(&format!(
                    "{}*(i32*)(mem+{a}+{}) = {v};\n",
                    "  ".repeat(indent),
                    memarg.offset
                ));
            }
            I64Store { memarg } => {
                let v = estack.pop().unwrap_or_default();
                let a = estack.pop().unwrap_or_default();
                out.push_str(&format!(
                    "{}*(i64*)(mem+{a}+{}) = {v};\n",
                    "  ".repeat(indent),
                    memarg.offset
                ));
            }
            I32Add => binop(&mut estack, "+"),
            I32Sub => binop(&mut estack, "-"),
            I32Mul => binop(&mut estack, "*"),
            I32And => binop(&mut estack, "&"),
            I32Or => binop(&mut estack, "|"),
            I32Xor => binop(&mut estack, "^"),
            I32Eqz => {
                let a = estack.pop().unwrap_or_default();
                estack.push(format!("({a} == 0)"));
            }
            I32Eq => binop(&mut estack, "=="),
            I32Ne => binop(&mut estack, "!="),
            I32LtU => binop(&mut estack, "<u"),
            I32GeU => binop(&mut estack, ">=u"),
            Block { .. } => {
                out.push_str(&format!("{}{{ // block @ {pos:#x}\n", "  ".repeat(indent)));
                indent += 1;
            }
            Loop { .. } => {
                out.push_str(&format!(
                    "{}do {{ // loop @ {pos:#x}\n",
                    "  ".repeat(indent)
                ));
                indent += 1;
            }
            If { .. } => {
                let cond = estack.pop().unwrap_or_else(|| "<cond>".into());
                out.push_str(&format!(
                    "{}if ({cond}) {{ // if @ {pos:#x}\n",
                    "  ".repeat(indent)
                ));
                indent += 1;
            }
            Else => {
                indent = indent.saturating_sub(1);
                out.push_str(&format!("{}}} else {{\n", "  ".repeat(indent)));
                indent += 1;
            }
            Br { relative_depth } => {
                out.push_str(&format!(
                    "{}goto label_m{relative_depth}; // br @ {pos:#x}\n",
                    "  ".repeat(indent)
                ));
            }
            BrIf { relative_depth } => {
                let c = estack.pop().unwrap_or_else(|| "<cond>".into());
                out.push_str(&format!(
                    "{}if ({c}) goto label_m{relative_depth}; // br_if @ {pos:#x}\n",
                    "  ".repeat(indent)
                ));
            }
            BrTable { targets: _ } => {
                let targets = cfg
                    .br_tables
                    .iter()
                    .find(|(o, _)| *o == pos)
                    .map(|(_, t)| t.len())
                    .unwrap_or(0);
                out.push_str(&format!(
                    "{}switch (<idx>) {{ /* br_table @ {pos:#x}: {targets} labeled targets */ }}\n",
                    "  ".repeat(indent)
                ));
            }
            Call { function_index } => {
                let callee_ty = model
                    .functions
                    .iter()
                    .find(|f| f.index == function_index)
                    .map(|f| f.type_index)
                    .and_then(|t| model.types.get(t as usize).cloned());
                let n_args = callee_ty.as_ref().map(|t| t.params.len()).unwrap_or(0);
                let mut args = Vec::with_capacity(n_args);
                for _ in 0..n_args {
                    args.push(estack.pop().unwrap_or_else(|| "<arg>".into()));
                }
                args.reverse();
                let callee = model
                    .functions
                    .iter()
                    .find(|f| f.index == function_index)
                    .and_then(|f| f.name.clone())
                    .unwrap_or_else(|| format!("wasm_fn_{function_index}"));
                let call = format!("{}({})", callee, args.join(", "));
                let has_ret = callee_ty.map(|t| !t.results.is_empty()).unwrap_or(false);
                if has_ret {
                    estack.push(call);
                } else {
                    out.push_str(&format!("{}{};\n", "  ".repeat(indent), call));
                }
            }
            CallIndirect {
                type_index,
                table_index,
                ..
            } => {
                let a = estack.pop().unwrap_or_default();
                estack.push(format!(
                    "table{table_index}[{a}] /* type {type_index}; targets: indirect_targets */"
                ));
            }
            Return => {
                let n = model
                    .types
                    .get(func.type_index as usize)
                    .map(|t| t.results.len())
                    .unwrap_or(0);
                if n > 0 {
                    let vals = (0..n)
                        .filter_map(|_| estack.pop())
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("{}return {vals};\n", "  ".repeat(indent)));
                } else {
                    out.push_str(&format!("{}return;\n", "  ".repeat(indent)));
                }
            }
            Unreachable => {
                out.push_str(&format!("{}unreachable;\n", "  ".repeat(indent)));
            }
            Drop => {
                estack.pop();
            }
            End => {
                if indent > 1 {
                    indent -= 1;
                    out.push_str(&format!("{}}}\n", "  ".repeat(indent)));
                } else {
                    out.push_str("}\n");
                    break;
                }
            }
            _ => {
                out.push_str(&format!(
                    "{}/* opaque op @ {pos:#x} */\n",
                    "  ".repeat(indent)
                ));
            }
        }
    }

    Ok(out)
}

fn binop(estack: &mut Vec<String>, sym: &str) {
    let b = estack.pop().unwrap_or_default();
    let a = estack.pop().unwrap_or_default();
    estack.push(format!("({a} {sym} {b})"));
}
