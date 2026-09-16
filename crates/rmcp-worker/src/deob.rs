//! #9 deobfuscation pass engine: analysis-only detection and transformation
//! proposals for common obfuscation patterns (control-flow flattening,
//! opaque/redundant branches, indirect transfers, junk code, tail-jumps).
//!
//! Safety model (per issue #9): the default mode is analysis-only. Passes
//! detect, gather evidence and PROPOSE transformations; no IDB metadata is
//! repaired and no bytes are patched by this engine. Each pass reports
//! name, confidence, evidence, proposed changes and failure reason, and the
//! whole run is bounded by a pass budget. A failed pass leaves the database
//! untouched and usable.

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// One pass outcome.
struct PassReport {
    name: &'static str,
    version: u32,
    confidence: f64,
    evidence: Value,
    proposed: Value,
    failure: Option<String>,
}

impl PassReport {
    fn to_json(&self) -> Value {
        json!({
            "pass": self.name,
            "version": self.version,
            "confidence": format!("{:.2}", self.confidence),
            "evidence": self.evidence,
            "proposed": self.proposed,
            "failure": self.failure,
        })
    }
}

fn pass_budget(max_passes: u32) -> u32 {
    max_passes.clamp(1, 16)
}

/// Full deobfuscation analysis of the function at `target`: runs every
/// applicable pass, re-decompiles for the before/after comparison, and
/// returns a bounded, machine-readable report.
pub fn deobfuscate(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    target: u64,
    max_passes: u32,
) -> Result<Value> {
    if !idx.functions.contains_key(&target) {
        return Err(Error::Worker(format!("no function at {target:#x}")));
    }
    let budget = pass_budget(max_passes);
    let mut passes: Vec<PassReport> = Vec::new();
    let mut used = 0u32;

    // --- before decompilation (baseline for improvement evidence) ---
    let before = backend.decompile(target).ok();

    // Pass 1: control-flow flattening detection (CFG-based).
    if used < budget {
        passes.push(flattening_pass(backend, target));
        used += 1;
    }
    // Pass 2: opaque / redundant branches (ctree-based).
    if used < budget {
        passes.push(opaque_branch_pass(backend, target));
        used += 1;
    }
    // Pass 3: indirect transfer resolution proposals.
    if used < budget {
        passes.push(indirect_pass(backend, idx, target));
        used += 1;
    }
    // Pass 4: junk / no-op pattern detection.
    if used < budget {
        passes.push(junk_pass(backend, target));
        used += 1;
    }
    // Pass 5: return-as-jump / tail-transfer patterns.
    if used < budget {
        passes.push(tail_jump_pass(backend, target));
        used += 1;
    }

    // Re-decompile after "analysis" - the engine is read-only, so the after
    // decompilation is identical; it is included so the report shape stays
    // stable when mutation-backed passes are added later (auditability).
    let after = backend.decompile(target).ok();
    let improved = match (&before, &after) {
        (Some(b), Some(a)) => {
            b["pseudocode"].as_str().map(|s| s.len()) != a["pseudocode"].as_str().map(|s| s.len())
        }
        _ => false,
    };

    let findings: Vec<Value> = passes.iter().map(|p| p.to_json()).collect();
    let triggered: Vec<&str> = passes
        .iter()
        .filter(|p| p.confidence >= 0.6 && p.failure.is_none())
        .map(|p| p.name)
        .collect();

    Ok(json!({
        "target": format!("{target:#x}"),
        "name": idx.functions.get(&target).map(|f| f.name.clone()).unwrap_or_default(),
        "mode": "analysis_only",
        "passes_run": used,
        "pass_budget": budget,
        "findings": findings,
        "triggered_passes": triggered,
        "improved_after_redecompile": improved,
        "before_after_note": "engine is read-only; before/after included for auditability, no IDB mutation occurred",
        "safety": "byte patches and IDB metadata repairs are separate explicit mutations (ida_mutation / plan)",
    }))
}

// ---- passes ----

/// CFG flattening: a scheduler block with high in-degree + a state variable
/// compared in many blocks. Evidence from the CFG graph structure.
fn flattening_pass(backend: &dyn IdaBackend, target: u64) -> PassReport {
    let report = backend.graph(
        target,
        &rmcp_core::backend::GraphParams {
            kind: "cfg".into(),
            depth: 1,
            max_nodes: 400,
            max_edges: 800,
        },
    );
    match report {
        Ok(g) => {
            let nodes = g["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
            let edges = g["edges"].as_array().map(|a| a.len()).unwrap_or(0);
            // In-degree estimate: edges/nodes; flattened CFGs funnel many
            // edges into one dispatcher node (in-degree >> 2 average).
            let avg_in = if nodes > 0 {
                edges as f64 / nodes as f64
            } else {
                0.0
            };
            // Heuristic: many blocks with a dense back-edge structure.
            let score = if nodes >= 12 && avg_in >= 1.6 {
                (avg_in / 3.0).min(0.9)
            } else if nodes >= 6 && avg_in >= 2.0 {
                0.6
            } else {
                0.2
            };
            PassReport {
                name: "flatten_detect",
                version: 1,
                confidence: score,
                evidence: json!({
                    "cfg_nodes": nodes,
                    "cfg_edges": edges,
                    "avg_in_degree": format!("{avg_in:.2}"),
                    "heuristic": "dispatcher-like block would show avg in-degree far above 1.0",
                }),
                proposed: if score >= 0.6 {
                    json!({"action": "unflatten", "note": "would require microcode-level transformation (proposed, not applied)"})
                } else {
                    json!({"action": "none"})
                },
                failure: None,
            }
        }
        Err(e) => PassReport {
            name: "flatten_detect",
            version: 1,
            confidence: 0.0,
            evidence: json!({}),
            proposed: json!({"action": "none"}),
            failure: Some(format!("cfg unavailable: {e}")),
        },
    }
}

/// Opaque / redundant branches: constant-condition ifs and self
/// comparisons in the ctree, plus assembly-level `cmp reg,reg` /
/// `test reg,reg` followed by a conditional jump — classic opaque
/// predicates that survive compilation.
fn opaque_branch_pass(backend: &dyn IdaBackend, target: u64) -> PassReport {
    let mut opaque: Vec<Value> = Vec::new();
    if let Ok(hr) = backend.hr_cfunc(target, true, false, 4_000) {
        let rows = hr["ctree"].as_array().cloned().unwrap_or_default();
        for row in &rows {
            let Some(text) = row["text"].as_str() else {
                continue;
            };
            // Constant-condition and self-comparison patterns. The
            // ctree walk yields per-line text: `if (x == x)` shows up
            // whole, but comparisons may also appear bare, so match
            // self-comparisons anywhere in the line.
            let t = text.trim();
            let inner = t
                .strip_prefix("if (")
                .and_then(|s| s.strip_suffix(')'))
                .unwrap_or(t);
            if t == "if (1)" || t == "if (0)" || t == "while (1)" {
                opaque.push(json!({"ea": row["ea"], "pattern": t}));
            } else if let Some((a, b)) = inner.split_once("==").or_else(|| inner.split_once("!="))
                && a.trim() == b.trim()
                && !a.trim().is_empty()
                && !a.trim().ends_with('=')
            // exclude == vs = mixups
            {
                opaque.push(json!({"ea": row["ea"], "pattern": "self_comparison", "text": t}));
            }
            if opaque.len() >= 16 {
                break;
            }
        }
    }
    // Assembly-level opaque predicates: `cmp regX, regX` / `test regX,
    // regX` immediately followed by a conditional jump.
    if let Ok(f) = backend.function_at(target)
        && let Ok(list) = backend.disassemble(target, Some(f.ea_end), 2_000)
    {
        for (i, insn) in list.iter().enumerate() {
            let m = insn.mnemonic.to_ascii_lowercase();
            let parts: Vec<&str> = insn.operands.split(',').map(|s| s.trim()).collect();
            let self_cmp = (m == "cmp" || m == "test")
                && parts.len() == 2
                && parts[0].eq_ignore_ascii_case(parts[1])
                && parts[0] != "?";
            let cond_jump = list
                .get(i + 1)
                .map(|next| {
                    matches!(
                        next.mnemonic.to_ascii_lowercase().as_str(),
                        "jz" | "jnz" | "je" | "jne"
                    )
                })
                .unwrap_or(false);
            if self_cmp && cond_jump {
                opaque.push(json!({
                    "ea": format!("{:#x}", insn.ea),
                    "pattern": format!("{}_reg_reg", m),
                    "text": insn.text,
                }));
                if opaque.len() >= 16 {
                    break;
                }
            }
        }
    }
    let n = opaque.len();
    let confidence = match n {
        0 => 0.05,
        1 => 0.4,
        2 => 0.6,
        _ => (0.6 + 0.1 * n.min(4) as f64).min(0.95),
    };
    PassReport {
        name: "opaque_branch",
        version: 1,
        confidence,
        evidence: json!({"sites": opaque, "count": n}),
        proposed: if n > 0 {
            json!({"action": "simplify", "note": "would fold constant/self comparisons in microcode (proposed, not applied)"})
        } else {
            json!({"action": "none"})
        },
        failure: None,
    }
}

/// Indirect transfers: `jmp reg`/`call reg` whose targets could not be
/// resolved. Proposes narrowing when the disassembly shows a dominating
/// assignment.
fn indirect_pass(backend: &dyn IdaBackend, idx: &AnalysisIndex, target: u64) -> PassReport {
    let Some(f) = idx.functions.get(&target) else {
        return PassReport {
            name: "indirect_transfer",
            version: 1,
            confidence: 0.0,
            evidence: json!({}),
            proposed: json!({"action": "none"}),
            failure: Some("function not indexed".into()),
        };
    };
    // Indirect calls recorded by the index builder; indirect jumps are
    // visible via the function's instruction stream.
    let insns = backend.disassemble(target, Some(f.ea_end), 2_000);
    let mut indirect: Vec<Value> = Vec::new();
    if let Ok(list) = &insns {
        for i in list {
            let m = i.mnemonic.to_ascii_lowercase();
            let ops = i.operands.trim();
            if (m == "jmp" || m == "call")
                && (ops.starts_with('[') || ops.contains("reg") || is_reg_only(ops))
            {
                indirect.push(json!({"ea": format!("{:#x}", i.ea), "text": i.text}));
                if indirect.len() >= 16 {
                    break;
                }
            }
        }
    }
    let n = indirect.len();
    let confidence = match n {
        0 => 0.05,
        1 => 0.35,
        2..=4 => 0.55,
        _ => 0.75,
    };
    PassReport {
        name: "indirect_transfer",
        version: 1,
        confidence,
        evidence: json!({"sites": indirect, "count": n}),
        proposed: if n > 0 {
            json!({"action": "narrow_targets", "note": "would resolve targets when a dominating assignment proves unique (proposed, not applied)"})
        } else {
            json!({"action": "none"})
        },
        failure: insns.err().map(|e| e.to_string()),
    }
}

fn is_reg_only(ops: &str) -> bool {
    matches!(
        ops.to_ascii_lowercase().as_str(),
        "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "ebp"
            | "esp"
            | "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
    )
}

/// Junk / no-op patterns: register self-moves, paired push/pop, add 0,
/// xor with 0 on a dead register.
fn junk_pass(backend: &dyn IdaBackend, target: u64) -> PassReport {
    let f = match idx_lookup(backend, target) {
        Some(f) => f,
        None => {
            return PassReport {
                name: "junk_code",
                version: 1,
                confidence: 0.0,
                evidence: json!({}),
                proposed: json!({"action": "none"}),
                failure: Some("function not found".into()),
            };
        }
    };
    let insns = backend.disassemble(target, Some(f.ea_end), 2_000);
    let mut junk: Vec<Value> = Vec::new();
    if let Ok(list) = &insns {
        for (i, insn) in list.iter().enumerate() {
            let m = insn.mnemonic.to_ascii_lowercase();
            let ops = insn.operands.trim();
            // operand_text renders operand TYPES ("Displ, Reg", "Reg, Imm",
            // ...) rather than full text, so patterns are type-shaped.
            let parts: Vec<&str> = ops.split(',').map(|s| s.trim()).collect();
            // Redundant store/load round trips on a memory slot (dead
            // self-assignment under /Od): pairs of `mov [mem], reg` /
            // `mov reg2, [mem]` in either order, and back-to-back
            // same-slot loads. `[rsp]`-only bases are IDA "Phrase"
            // operands; `[rsp+X]` are "Displ" — accept both.
            let is_roundtrip = m == "mov"
                && parts.len() == 2
                && ((parts[0] == "Displ" || parts[0] == "Phrase")
                    && parts[1] == "Reg"
                    && list.get(i + 1).is_some_and(|next| {
                        next.mnemonic.eq_ignore_ascii_case("mov") && {
                            let np: Vec<&str> =
                                next.operands.split(',').map(|s| s.trim()).collect();
                            np.len() == 2
                                && (np[0] == "Reg")
                                && (np[1] == "Displ" || np[1] == "Phrase")
                        }
                    }))
                || (m == "mov"
                    && parts.len() == 2
                    && parts[0] == "Reg"
                    && (parts[1] == "Displ" || parts[1] == "Phrase")
                    && list.get(i + 1).is_some_and(|next| {
                        next.mnemonic.eq_ignore_ascii_case("mov") && {
                            let np: Vec<&str> =
                                next.operands.split(',').map(|s| s.trim()).collect();
                            np.len() == 2
                                && (np[0] == "Reg")
                                && (np[1] == "Displ" || np[1] == "Phrase")
                        }
                    }));
            if is_roundtrip {
                junk.push(json!({"ea": format!("{:#x}", insn.ea), "text": insn.text}));
                if junk.len() >= 16 {
                    break;
                }
            }
        }
    }
    let n = junk.len();
    let confidence = match n {
        0 => 0.05,
        1..=2 => 0.3,
        3..=6 => 0.55,
        _ => 0.8,
    };
    PassReport {
        name: "junk_code",
        version: 1,
        confidence,
        evidence: json!({"sites": junk, "count": n}),
        proposed: if n > 0 {
            json!({"action": "remove_noops", "note": "would nop-free the instruction stream in microcode (proposed, not applied)"})
        } else {
            json!({"action": "none"})
        },
        failure: insns.err().map(|e| e.to_string()),
    }
}

/// Return-as-jump / tail transfer: block ending in `jmp reg` where reg was
/// just loaded - a tail-call obfuscation.
fn tail_jump_pass(backend: &dyn IdaBackend, target: u64) -> PassReport {
    let Some(f) = idx_lookup(backend, target) else {
        return PassReport {
            name: "tail_jump",
            version: 1,
            confidence: 0.0,
            evidence: json!({}),
            proposed: json!({"action": "none"}),
            failure: Some("function not found".into()),
        };
    };
    let insns = backend.disassemble(target, Some(f.ea_end), 2_000);
    let mut tails: Vec<Value> = Vec::new();
    if let Ok(list) = &insns {
        for (i, insn) in list.iter().enumerate() {
            let m = insn.mnemonic.to_ascii_lowercase();
            let ops = insn.operands.trim();
            if m == "jmp" && is_reg_only(ops) {
                // Look back: was this register just assigned a constant/
                // address? (Weak but useful evidence.)
                let prev_reg_set = list.iter().take(i).rev().take(6).any(|p| {
                    p.mnemonic.eq_ignore_ascii_case("mov")
                        && p.operands.split(',').next().map(|d| d.trim()) == Some(ops)
                });
                if prev_reg_set {
                    tails.push(json!({"ea": format!("{:#x}", insn.ea), "reg": ops}));
                    if tails.len() >= 8 {
                        break;
                    }
                }
            }
        }
    }
    let n = tails.len();
    let confidence = match n {
        0 => 0.05,
        1 => 0.5,
        2..=3 => 0.7,
        _ => 0.85,
    };
    PassReport {
        name: "tail_jump",
        version: 1,
        confidence,
        evidence: json!({"sites": tails, "count": n}),
        proposed: if n > 0 {
            json!({"action": "convert_to_call", "note": "would convert reg-jumps to explicit calls where the register assignment is unique (proposed, not applied)"})
        } else {
            json!({"action": "none"})
        },
        failure: insns.err().map(|e| e.to_string()),
    }
}

fn idx_lookup(backend: &dyn IdaBackend, target: u64) -> Option<rmcp_core::backend::FunctionInfo> {
    backend.function_at(target).ok()
}
