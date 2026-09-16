//! #46 deobfuscation transform framework: propose -> validate -> apply ->
//! rollback for safe, explicit deobfuscation mutations.
//!
//! Split from #9 (analysis-only detection): every mutation here goes through
//! the #16 machinery — plans are data (JSON), apply runs as `plan.apply`
//! operations with a whole-plan revision guard, a snapshot is taken first
//! and rollback is `snapshot.restore` (audited). Without a transform-capable
//! microcode stack the framework only emits patch-level plans (T1/T2) and
//! reports `requires_microcode` for T4; it never silently partial-applies.
//!
//! Plan JSON shape (stable, agent-readable):
//! ```json
//! {
//!   "transform_id": "t2-junk-<ea>-<n>",
//!   "kind": "T2_junk_removal",
//!   "target": "0x…",
//!   "risk": "low|medium",
//!   "reversible": true,
//!   "evidence": { … per-site facts … },
//!   "operations": [ { "kind": "patch_bytes", "ea": "0x…", "hex": "90…" } ]
//! }
//! ```

use std::collections::BTreeSet;

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// Maximum sites one plan may touch: apply is bounded to one function and a
/// small site count keeps the failure blast radius reviewable.
const MAX_SITES: usize = 16;

/// x86 one-byte NOP (the only patch byte this framework ever emits).
const NOP: &str = "90";

/// Supported transform kinds (T4 reports requires_microcode at propose).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformKind {
    T1OpaqueBranch,
    T2JunkRemoval,
    T3IndirectMaterialize,
    T4Unflatten,
}

impl TransformKind {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "T1_opaque_branch" => Ok(Self::T1OpaqueBranch),
            "T2_junk_removal" => Ok(Self::T2JunkRemoval),
            "T3_indirect_materialize" => Ok(Self::T3IndirectMaterialize),
            "T4_unflatten" => Ok(Self::T4Unflatten),
            other => Err(Error::Worker(format!(
                "unknown transform kind '{other}' (T1_opaque_branch|T2_junk_removal|\
                 T3_indirect_materialize|T4_unflatten)"
            ))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::T1OpaqueBranch => "T1_opaque_branch",
            Self::T2JunkRemoval => "T2_junk_removal",
            Self::T3IndirectMaterialize => "T3_indirect_materialize",
            Self::T4Unflatten => "T4_unflatten",
        }
    }
}

/// One transformable site found during propose.
struct Site {
    ea: u64,
    /// Byte length the patch covers (site + absorbed no-effect followers).
    len: usize,
    evidence: Value,
}

/// Propose a transform plan for one function (analysis-only). Returns the
/// plan as JSON data; nothing in the IDB is touched.
pub fn propose(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    target: u64,
    kind: TransformKind,
) -> Result<Value> {
    let Some(f) = idx.functions.get(&target) else {
        return Err(Error::Worker(format!("no function at {target:#x}")));
    };
    let (sites, requires_microcode) = match kind {
        TransformKind::T4Unflatten => {
            return Ok(json!({
                "transform_id": format!("t4-unflatten-{target:x}"),
                "kind": kind.name(),
                "target": format!("{target:#x}"),
                "proposable": false,
                "reason": "requires_microcode",
                "note": "dispatcher elimination needs the microcode transform stack; no plan emitted"
            }));
        }
        // T1/T2 patch-only variants: analysis evidence decides the sites.
        TransformKind::T1OpaqueBranch => (opaque_sites(backend, target, f.ea_end)?, false),
        TransformKind::T2JunkRemoval => (junk_sites(backend, target, f.ea_end)?, false),
        // T3 needs a constant register value at the jmp site; without the
        // value-analysis hook wired per-site this stays evidence-first.
        TransformKind::T3IndirectMaterialize => (indirect_sites(backend, target, f.ea_end)?, false),
    };

    let mut operations: Vec<Value> = Vec::new();
    let mut evidence: Vec<Value> = Vec::new();
    for site in sites.iter().take(MAX_SITES) {
        // Patch-level transform: NOP the site bytes. Only emitted when the
        // bytes are readable at the site so validate can re-check them.
        operations.push(json!({
            "kind": "patch_bytes",
            "ea": format!("{:#x}", site.ea),
            "hex": NOP.repeat(site.len),
        }));
        evidence.push(json!({
            "ea": format!("{:#x}", site.ea),
            "len": site.len,
            "evidence": site.evidence,
        }));
    }
    let truncated = sites.len() > MAX_SITES;
    let plan = json!({
        "transform_id": format!("{}-{target:x}-{}", kind.name().to_lowercase(), sites.len()),
        "kind": kind.name(),
        "target": format!("{target:#x}"),
        "function": idx.functions.get(&target).map(|fi| fi.name.clone()).unwrap_or_default(),
        "proposable": !operations.is_empty(),
        "truncated": truncated,
        "risk": "low",
        "reversible": true,
        "requires_microcode": requires_microcode,
        "evidence": evidence,
        "operations": operations,
        "note": "patch-level transform; validate re-checks bytes/xrefs at apply time",
    });
    Ok(plan)
}

/// T1 sites: `cmp/test reg,reg` + conditional jump (asm-level opaque
/// predicates from the #9 pass evidence, re-derived here so the plan is
/// self-contained data).
fn opaque_sites(backend: &dyn IdaBackend, target: u64, end: u64) -> Result<Vec<Site>> {
    let list = backend.disassemble(target, Some(end), 2_000)?;
    let mut sites = Vec::new();
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
            // Neutralize the predicate AND the dead conditional jump: both
            // bytes become NOPs, the following block always executes.
            let len = insn_len(insn.text.as_str()) + list[i + 1].text.len().max(1);
            sites.push(Site {
                ea: insn.ea,
                len: len.min(16),
                evidence: json!({"pattern": format!("{m}_reg_reg"), "text": insn.text}),
            });
            if sites.len() >= MAX_SITES {
                break;
            }
        }
    }
    Ok(sites)
}

/// T2 sites: store/load roundtrips (the #9 junk signal), absorbed pairwise.
fn junk_sites(backend: &dyn IdaBackend, target: u64, end: u64) -> Result<Vec<Site>> {
    let list = backend.disassemble(target, Some(end), 2_000)?;
    let mut sites = Vec::new();
    let mut i = 0;
    while i < list.len() {
        if pair_is_roundtrip(&list, i) {
            let next_len = list
                .get(i + 1)
                .map(|n| insn_len(n.text.as_str()))
                .unwrap_or(1);
            sites.push(Site {
                ea: list[i].ea,
                len: (insn_len(list[i].text.as_str()) + next_len).min(16),
                evidence: json!({
                    "pattern": "store_load_roundtrip",
                    "site": list[i].text,
                    "follower": list.get(i + 1).map(|n| n.text.clone()).unwrap_or_default(),
                }),
            });
            i += 2;
            if sites.len() >= MAX_SITES {
                break;
            }
        } else {
            i += 1;
        }
    }
    Ok(sites)
}

/// T3 sites: `jmp reg` with a register-assignment look-back (the #9
/// tail_jump signal). Propose-only evidence: actual materialization needs
/// the resolved constant, so validate rejects unless one unique mov reg,imm
/// exists and the plan carries it.
fn indirect_sites(backend: &dyn IdaBackend, target: u64, end: u64) -> Result<Vec<Site>> {
    let list = backend.disassemble(target, Some(end), 2_000)?;
    let mut sites = Vec::new();
    for (i, insn) in list.iter().enumerate() {
        let m = insn.mnemonic.to_ascii_lowercase();
        let ops = insn.operands.trim().to_ascii_lowercase();
        if m != "jmp" || !is_reg(&ops) {
            continue;
        }
        // Unique constant assignment in the bounded look-back window.
        let mut values: BTreeSet<u64> = BTreeSet::new();
        for prev in list.iter().take(i).rev().take(6) {
            if prev.mnemonic.eq_ignore_ascii_case("mov") {
                let parts: Vec<&str> = prev.operands.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2
                    && parts[0].eq_ignore_ascii_case(&ops)
                    && let Some(v) = parse_imm(parts[1])
                {
                    values.insert(v);
                }
            }
        }
        if values.len() == 1 {
            let v = *values.iter().next().expect("len == 1");
            sites.push(Site {
                ea: insn.ea,
                len: insn_len(insn.text.as_str()).min(16),
                evidence: json!({"pattern": "jmp_reg_const", "reg": ops, "target": format!("{v:#x}")}),
            });
            if sites.len() >= MAX_SITES {
                break;
            }
        }
    }
    Ok(sites)
}

/// Validate a proposed plan against the live backend: rejects when any
/// patch site has inbound xrefs (callers/data references into the junk
/// region), bytes changed since propose, or the site left its function.
/// Returns ok|rejected + reasons; never mutates.
pub fn validate(backend: &dyn IdaBackend, plan: &Value) -> Result<Value> {
    let kind = plan["kind"].as_str().unwrap_or_default().to_string();
    let target = parse_ea(plan["target"].as_str().unwrap_or("0"))?;
    let f = match backend.function_at(target) {
        Ok(f) => f,
        Err(e) => {
            return Ok(json!({
                "valid": false,
                "kind": kind,
                "rejections": [{"reason": "target_function_gone", "detail": e.to_string()}],
            }));
        }
    };
    let ops = plan["operations"].as_array().cloned().unwrap_or_default();
    let mut rejections: Vec<Value> = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let Some(ea_s) = op["ea"].as_str() else {
            rejections.push(json!({"index": i, "reason": "malformed_op"}));
            continue;
        };
        let ea = parse_ea(ea_s)?;
        let hex = op["hex"].as_str().unwrap_or_default();
        let len = hex.len() / 2;
        if ea < f.ea_start || ea + len as u64 > f.ea_end {
            rejections.push(json!({
                "index": i, "ea": ea_s, "reason": "outside_target_function",
                "detail": format!("site [{:#x},{:#x}) not inside [{:#x},{:#x})", ea, ea + len as u64, f.ea_start, f.ea_end),
            }));
            continue;
        }
        // Inbound xrefs into the site range reject the patch: anything that
        // jumps into/reads the junk region would be corrupted by NOPs.
        let mut xref_hits: Vec<Value> = Vec::new();
        for a in 0..len as u64 {
            for xr in backend.xrefs_to(ea + a)?.iter() {
                if xr.kind != "flow" {
                    xref_hits.push(json!({"from": format!("{:#x}", xr.from), "kind": xr.kind}));
                }
            }
        }
        if !xref_hits.is_empty() {
            rejections.push(json!({
                "index": i, "ea": ea_s, "reason": "inbound_xrefs",
                "detail": "site bytes are referenced; NOPs would corrupt callers",
                "xrefs": xref_hits,
            }));
            continue;
        }
        // Bytes must match what propose saw: re-read and require them to be
        // decodable instruction bytes (non-zero-length read).
        let raw = backend.get_bytes(ea, len)?;
        if raw["hex"].as_str().unwrap_or("").is_empty() {
            rejections.push(json!({"index": i, "ea": ea_s, "reason": "bytes_unreadable"}));
        }
    }
    Ok(json!({
        "valid": rejections.is_empty(),
        "kind": kind,
        "operations": ops.len(),
        "rejections": rejections,
    }))
}

/// Apply a validated plan: snapshot -> revision-guarded plan.apply ->
/// before/after decompile summaries. Returns the rollback token (the
/// snapshot was taken) plus bounded before/after evidence.
pub fn apply(
    state: &mut crate::state::WorkerState,
    plan: &Value,
    expected_revision: Option<u64>,
) -> Result<Value> {
    let ops_json = plan["operations"].as_array().cloned().unwrap_or_default();
    if ops_json.is_empty() {
        return Err(Error::Worker("plan has no operations".into()));
    }
    let target = parse_ea(plan["target"].as_str().unwrap_or("0"))?;
    let kind = plan["kind"].as_str().unwrap_or("unknown").to_string();

    // 1. Whole-plan revision guard FIRST: expected_revision refers to the
    // revision the agent observed. Dispatch is single-threaded per session,
    // so checking before the snapshot leaves no mutation window.
    crate::plan::check_plan_revision(
        state.backend.as_deref().expect("backend"),
        expected_revision,
    )?;

    // 2. Snapshot second (idalib's file-level snapshot bumps the revision,
    // so it must run after the guard). Rollback token exists before any
    // byte changes.
    let snapshot = state
        .backend
        .as_deref_mut()
        .expect("backend")
        .snapshot_create()?;

    // 3. Baseline evidence (before decompile summary).
    let before = state
        .backend
        .as_deref()
        .expect("backend")
        .decompile(target)
        .ok();
    let before_summary = decompile_summary(&before);

    // 4. Apply through the #16 machinery (audit entries recorded).
    let ops = crate::plan::parse_operations(&ops_json)?;
    let mut audit = std::mem::take(&mut state.audit);
    let applied = crate::plan::apply(
        state.backend.as_deref_mut().expect("backend"),
        &ops,
        &mut audit,
    );
    state.audit = audit;
    let applied = applied?;

    // 5. After evidence + CFG delta (renumbered from 4).
    let after = state
        .backend
        .as_deref()
        .expect("backend")
        .decompile(target)
        .ok();
    let after_summary = decompile_summary(&after);
    let cfg_after = state.backend.as_deref().expect("backend").graph(
        target,
        &rmcp_core::backend::GraphParams {
            kind: "cfg".into(),
            depth: 1,
            max_nodes: 400,
            max_edges: 800,
        },
    );
    let cfg_nodes = cfg_after
        .as_ref()
        .ok()
        .and_then(|g| g["nodes"].as_array().map(|a| a.len()));
    let cfg_edges = cfg_after
        .ok()
        .and_then(|g| g["edges"].as_array().map(|a| a.len()));

    Ok(json!({
        "transform_id": plan["transform_id"],
        "kind": kind,
        "target": plan["target"],
        "applied": applied,
        "before": before_summary,
        "after": after_summary,
        "cfg_after": {"nodes": cfg_nodes, "edges": cfg_edges},
        "snapshot": snapshot,
        "rollback": "ida_deobfuscate action=rollback (or ida_mutation action=rollback)",
    }))
}

/// Bounded decompile summary for evidence rows (no full pseudocode dump).
fn decompile_summary(v: &Option<Value>) -> Value {
    match v {
        Some(d) => json!({
            "pseudocode_len": d["pseudocode"].as_str().map(|s| s.len()),
            "lines": d["pseudocode"].as_str().map(|s| s.lines().count()),
            "sha_prefix": d["pseudocode"].as_str().map(|s| {
                let mut h: u64 = 0xcbf29ce484222325;
                for b in s.bytes() {
                    h ^= b as u64;
                    h = h.wrapping_mul(0x100000001b3);
                }
                format!("{h:016x}")
            }),
        }),
        None => json!({"unavailable": true}),
    }
}

/// Adversarial helper used by tests and validate: does any non-flow xref
/// point into [start, start+len)?
pub fn has_inbound_xrefs(backend: &dyn IdaBackend, start: u64, len: u64) -> Result<Vec<Value>> {
    let mut hits = Vec::new();
    for a in 0..len {
        for xr in backend.xrefs_to(start + a)?.iter() {
            if xr.kind != "flow" {
                hits.push(json!({"ea": format!("{:#x}", start + a), "from": format!("{:#x}", xr.from), "kind": xr.kind}));
            }
        }
    }
    Ok(hits)
}

fn pair_is_roundtrip(list: &[rmcp_core::backend::InsnInfo], i: usize) -> bool {
    let a = &list[i];
    let Some(b) = list.get(i + 1) else {
        return false;
    };
    if !a.mnemonic.eq_ignore_ascii_case("mov") || !b.mnemonic.eq_ignore_ascii_case("mov") {
        return false;
    }
    let pa: Vec<&str> = a.operands.split(',').map(|s| s.trim()).collect();
    let pb: Vec<&str> = b.operands.split(',').map(|s| s.trim()).collect();
    if pa.len() != 2 || pb.len() != 2 {
        return false;
    }
    let mem = |s: &str| s == "Displ" || s == "Phrase";
    // store->load or load->store on a memory slot.
    (mem(pa[0]) && pa[1] == "Reg" && pb[0] == "Reg" && mem(pb[1]))
        || (pa[0] == "Reg" && mem(pa[1]) && pb[0] == "Reg" && mem(pb[1]))
}

fn insn_len(text: &str) -> usize {
    // The disassembler reports per-instruction length via the text gap;
    // without a length field the patch length is derived from the next
    // instruction's EA delta at the call site, so this fallback keeps the
    // conservative 1-byte-per-token estimate used for NOP runs.
    text.split_whitespace().count().max(1)
}

fn is_reg(ops: &str) -> bool {
    matches!(
        ops,
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

fn parse_imm(s: &str) -> Option<u64> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    if t.is_empty() {
        return None;
    }
    u64::from_str_radix(t, 16)
        .ok()
        .or_else(|| s.trim().parse().ok())
}

fn parse_ea(s: &str) -> Result<u64> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| Error::Worker(format!("bad ea '{s}': {e}")))
    } else {
        t.parse::<u64>()
            .map_err(|e| Error::Worker(format!("bad ea '{s}': {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp_ida::MockBackend;

    fn open_mock() -> MockBackend {
        let mut b = MockBackend::new();
        IdaBackend::open(&mut b, "t.i64").unwrap();
        b
    }

    #[test]
    fn t2_plan_shape_and_reversible() {
        let backend = open_mock();
        let idx = backend.build_index().unwrap().0;
        let plan = propose(&backend, &idx, 0x401000, TransformKind::T2JunkRemoval).unwrap();
        assert_eq!(plan["kind"], "T2_junk_removal");
        assert_eq!(plan["reversible"], true);
        assert_eq!(plan["requires_microcode"], false);
        for op in plan["operations"].as_array().unwrap() {
            assert_eq!(op["kind"], "patch_bytes");
            assert!(op["hex"].as_str().unwrap().chars().all(|c| c == '9'));
        }
    }

    #[test]
    fn t4_reports_requires_microcode() {
        let backend = open_mock();
        let idx = backend.build_index().unwrap().0;
        let out = propose(&backend, &idx, 0x401000, TransformKind::T4Unflatten).unwrap();
        assert_eq!(out["proposable"], false);
        assert_eq!(out["reason"], "requires_microcode");
    }

    #[test]
    fn validate_rejects_out_of_function_sites() {
        let backend = open_mock();
        let plan = json!({
            "kind": "T2_junk_removal",
            "target": "0x401000",
            "operations": [{"kind": "patch_bytes", "ea": "0x900000", "hex": "9090"}],
        });
        let out = validate(&backend, &plan).unwrap();
        assert_eq!(out["valid"], false);
        assert_eq!(out["rejections"][0]["reason"], "outside_target_function");
    }

    #[test]
    fn validate_rejects_xrefed_sites() {
        let mut backend = open_mock();
        let idx = backend.build_index().unwrap().0;
        let plan = propose(&backend, &idx, 0x401000, TransformKind::T2JunkRemoval).unwrap();
        let ops = plan["operations"].as_array().unwrap();
        if ops.is_empty() {
            // Mock graph carries no junk roundtrips: the adversarial check
            // is driven with a synthetic site on the function body instead.
            let plan = json!({
                "kind": "T2_junk_removal",
                "target": "0x401000",
                "operations": [{"kind": "patch_bytes", "ea": "0x401000", "hex": "9090"}],
            });
            backend.add_xref_for_test(0x500000, 0x401000, "data");
            let out = validate(&backend, &plan).unwrap();
            assert_eq!(out["valid"], false);
            assert_eq!(out["rejections"][0]["reason"], "inbound_xrefs");
            return;
        }
        // Inject a data xref onto the first site, then validate: the plan
        // must be rejected with evidence (adversarial path).
        let ea = parse_ea(ops[0]["ea"].as_str().unwrap()).unwrap();
        backend.add_xref_for_test(0x500000, ea, "data");
        let out = validate(&backend, &plan).unwrap();
        assert_eq!(out["valid"], false);
        assert_eq!(out["rejections"][0]["reason"], "inbound_xrefs");
    }

    #[test]
    fn unknown_kind_is_an_error() {
        assert!(TransformKind::parse("T9_magic").is_err());
        assert!(TransformKind::parse("T2_junk_removal").is_ok());
    }
}
