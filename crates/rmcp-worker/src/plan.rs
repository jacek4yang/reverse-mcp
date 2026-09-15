//! #16 mutation plans: validate/preview a batch of operations, then apply
//! them with a single whole-plan revision guard and a bounded audit trail.
//!
//! Plan semantics (documented honestly in LIMITATIONS):
//! - `plan` validates every operation against the current backend and
//!   returns a preview WITHOUT changing anything. Revision is checked at
//!   plan time so a stale plan is rejected before any state is produced.
//! - `apply` re-checks the revision, then runs the operations sequentially.
//!   Each op bumps the revision; the plan fails at the first operation that
//!   errors (ops already applied are recorded in the result so the agent can
//!   reason about partial state — sequential apply is NOT transactional).

use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// One planned mutation operation (subset of the worker's mutation methods).
#[derive(Debug, Clone)]
pub struct PlannedOp {
    pub kind: PlannedOpKind,
    pub ea: u64,
}

#[derive(Debug, Clone)]
pub enum PlannedOpKind {
    Rename { new_name: String },
    Comment { comment: String, repeatable: bool },
    PatchBytes { bytes_hex: String },
    FuncCreate { end: Option<u64> },
    FuncDelete,
    SetType { decl: String },
}

impl PlannedOp {
    /// Short human/agent-readable description for the preview.
    pub fn describe(&self) -> String {
        match &self.kind {
            PlannedOpKind::Rename { new_name } => format!("rename -> {new_name}"),
            PlannedOpKind::Comment { comment, .. } => {
                format!("comment -> {comment}")
            }
            PlannedOpKind::PatchBytes { bytes_hex } => {
                format!("patch bytes -> {bytes_hex}")
            }
            PlannedOpKind::FuncCreate { .. } => "create function".into(),
            PlannedOpKind::FuncDelete => "delete function".into(),
            PlannedOpKind::SetType { decl } => format!("set type -> {decl}"),
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match &self.kind {
            PlannedOpKind::Rename { .. } => "rename",
            PlannedOpKind::Comment { .. } => "comment",
            PlannedOpKind::PatchBytes { .. } => "patch_bytes",
            PlannedOpKind::FuncCreate { .. } => "func.create",
            PlannedOpKind::FuncDelete => "func.delete",
            PlannedOpKind::SetType { .. } => "set_type",
        }
    }
}

/// Parse the `operations` array of a plan request. Fails on the first
/// malformed op with a stable error so the agent can fix the plan.
pub fn parse_operations(ops: &[Value]) -> Result<Vec<PlannedOp>> {
    ops.iter()
        .enumerate()
        .map(|(i, op)| {
            let ea = op
                .get("ea")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker(format!("op {i}: missing 'ea'")))?;
            let ea = parse_ea(ea).map_err(|e| Error::Worker(format!("op {i}: {e}")))?;
            let kind = op
                .get("kind")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::Worker(format!("op {i}: missing 'kind'")))?;
            let kind = match kind {
                "rename" => {
                    let new_name = op
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::Worker(format!("op {i}: rename requires 'name'")))?
                        .to_string();
                    PlannedOpKind::Rename { new_name }
                }
                "comment" => {
                    let comment = op
                        .get("comment")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            Error::Worker(format!("op {i}: comment requires 'comment'"))
                        })?
                        .to_string();
                    let repeatable = op
                        .get("repeatable")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    PlannedOpKind::Comment {
                        comment,
                        repeatable,
                    }
                }
                "patch_bytes" => {
                    let bytes_hex = op
                        .get("hex")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| {
                            Error::Worker(format!("op {i}: patch_bytes requires 'hex'"))
                        })?
                        .to_string();
                    PlannedOpKind::PatchBytes { bytes_hex }
                }
                "func.create" => {
                    let end = match op.get("end") {
                        Some(v) if !v.is_null() => Some(
                            v.as_str()
                                .map(parse_ea)
                                .transpose()
                                .map_err(|e| Error::Worker(format!("op {i}: {e}")))?
                                .or_else(|| v.as_u64())
                                .ok_or_else(|| Error::Worker(format!("op {i}: bad 'end'")))?,
                        ),
                        _ => None,
                    };
                    PlannedOpKind::FuncCreate { end }
                }
                "func.delete" => PlannedOpKind::FuncDelete,
                "set_type" => {
                    let decl = op
                        .get("decl")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::Worker(format!("op {i}: set_type requires 'decl'")))?
                        .to_string();
                    PlannedOpKind::SetType { decl }
                }
                other => {
                    return Err(Error::Worker(format!(
                        "op {i}: unknown kind '{other}' (supported: rename, comment, \
                         patch_bytes, func.create, func.delete, set_type)"
                    )));
                }
            };
            Ok(PlannedOp { kind, ea })
        })
        .collect()
}

fn parse_ea(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| Error::Worker(format!("bad ea '{s}': {e}")))
    } else {
        s.parse::<u64>()
            .map_err(|e| Error::Worker(format!("bad ea '{s}': {e}")))
    }
}

/// Validate + preview. No mutation happens here; each op is probed for
/// plausibility (address resolves to something) and the whole list is
/// returned as rows for the agent to review.
pub fn plan(backend: &dyn IdaBackend, ops: &[PlannedOp]) -> Result<Value> {
    let mut rows = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        // Plausibility probe: the target address must map to a function or
        // a byte. This catches wrong-address mistakes before any mutation.
        let target_ok = backend.function_at(op.ea).is_ok()
            || {
                matches!(backend.get_bytes(op.ea, 1), Ok(v) if !v["hex"].as_str().unwrap_or("").is_empty())
            };
        rows.push(json!({
            "index": i,
            "kind": op.kind_name(),
            "ea": format!("{:#x}", op.ea),
            "detail": op.describe(),
            "target_resolves": target_ok,
        }));
    }
    let reversible = ops
        .iter()
        .all(|op| !matches!(op.kind, PlannedOpKind::PatchBytes { .. }));
    Ok(json!({
        "operations": ops.len(),
        "reversible": reversible,
        "requires_idb_snapshot": !reversible,
        "rows": rows,
        "hint": if reversible {
            "all ops are name/comment-level and rollback-able via snapshot before apply"
        } else {
            "patch ops write bytes; take a snapshot (ida_mutation action=snapshot) first"
        },
    }))
}

/// Apply the plan sequentially. The revision was validated by the caller
/// (whole-plan guard) before this runs. Every applied op is appended to the
/// audit trail; a failing op stops the plan and reports what was applied.
pub fn apply(
    backend: &mut dyn IdaBackend,
    ops: &[PlannedOp],
    audit: &mut Vec<Value>,
) -> Result<Value> {
    let mut applied = 0usize;
    let mut results = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        let outcome = match &op.kind {
            PlannedOpKind::Rename { new_name } => backend.rename(op.ea, new_name),
            PlannedOpKind::Comment {
                comment,
                repeatable,
            } => backend.set_comment(op.ea, comment, *repeatable),
            PlannedOpKind::PatchBytes { bytes_hex } => backend.patch_bytes(op.ea, bytes_hex),
            PlannedOpKind::FuncCreate { end } => backend.func_create(op.ea, *end),
            PlannedOpKind::FuncDelete => backend.func_delete(op.ea),
            PlannedOpKind::SetType { decl } => backend.set_type(op.ea, decl),
        };
        match outcome {
            Ok(out) => {
                audit.push(json!({
                    "seq": audit.len(),
                    "kind": op.kind_name(),
                    "ea": format!("{:#x}", op.ea),
                    "revision_after": out.revision_after,
                    "detail": out.detail,
                }));
                applied += 1;
                results.push(json!({"index": i, "ok": true}));
            }
            Err(e) => {
                return Ok(json!({
                    "applied": applied,
                    "failed_at": i,
                    "failed_op": op.kind_name(),
                    "error": e.to_string(),
                    "error_code": e.code(),
                    "results": results,
                    "partial": true,
                }));
            }
        }
    }
    Ok(json!({
        "applied": applied,
        "revision_after": backend.revision(),
        "results": results,
        "partial": false,
    }))
}

/// Whole-plan revision guard: reject the plan before ANY op runs when the
/// revision moved since the agent last looked.
pub fn check_plan_revision(backend: &dyn IdaBackend, expected: Option<u64>) -> Result<()> {
    if let Some(expected) = expected {
        check_revision_value(backend, expected)?;
    }
    Ok(())
}

fn check_revision_value(backend: &dyn IdaBackend, expected: u64) -> Result<()> {
    let current = backend.revision();
    if expected != current {
        return Err(Error::RevisionConflict { expected, current });
    }
    Ok(())
}

/// Record a single (non-plan) mutation in the audit trail. Every mutation —
/// standalone or within a plan — must be audited.
pub fn record_audit(
    audit: &mut Vec<Value>,
    kind: &str,
    ea: u64,
    out: &rmcp_core::backend::MutationOutcome,
) {
    audit.push(json!({
        "seq": audit.len(),
        "kind": kind,
        "ea": format!("{ea:#x}"),
        "revision_after": out.revision_after,
        "detail": out.detail,
    }));
}

/// Bounded audit trail read (the worker keeps the tail; broker output is
/// additionally bounded by the result store).
pub fn audit_tail(audit: &[Value], limit: usize) -> Value {
    let start = audit.len().saturating_sub(limit);
    json!({
        "total": audit.len(),
        "entries": &audit[start..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp_ida::MockBackend;

    fn plan_ops() -> Vec<PlannedOp> {
        vec![
            PlannedOp {
                kind: PlannedOpKind::Rename {
                    new_name: "cool_name".into(),
                },
                ea: 0x401100,
            },
            PlannedOp {
                kind: PlannedOpKind::Comment {
                    comment: "hi".into(),
                    repeatable: false,
                },
                ea: 0x401100,
            },
        ]
    }

    #[test]
    fn parse_rejects_unknown_kind() {
        let ops: Vec<Value> = vec![json!({"ea": "0x401100", "kind": "explode"})];
        let err = parse_operations(&ops).unwrap_err();
        assert_eq!(err.code(), "worker_failure");
        assert!(err.to_string().contains("unknown kind"));
    }

    #[test]
    fn plan_reports_targets_without_mutating() {
        let mut b = MockBackend::new();
        b.open("fixture.i64").unwrap();
        b.function_at(0x1000).ok(); // may fail; plan must not panic either way
        let ops = plan_ops();
        let out = plan(&b, &ops).unwrap();
        assert_eq!(out["operations"], 2);
        assert_eq!(out["rows"].as_array().unwrap().len(), 2);
        // plan must not bump the revision
        assert_eq!(b.revision(), 0);
    }

    #[test]
    fn apply_runs_sequentially_and_audits() {
        let mut b = MockBackend::new();
        b.open("fixture.i64").unwrap();
        let mut audit = Vec::new();
        let ops = plan_ops();
        let out = apply(&mut b, &ops, &mut audit).unwrap();
        assert_eq!(out["applied"], 2);
        assert_eq!(out["partial"], false);
        assert_eq!(audit.len(), 2);
        assert_eq!(b.revision(), 2);
    }

    #[test]
    fn stale_plan_revision_rejected_before_apply() {
        let mut b = MockBackend::new();
        b.open("fixture.i64").unwrap();
        b.rename(0x401100, "n1").unwrap(); // revision -> 1
        let err = check_plan_revision(&b, Some(0)).unwrap_err();
        assert_eq!(err.code(), "revision_conflict");
    }
}
