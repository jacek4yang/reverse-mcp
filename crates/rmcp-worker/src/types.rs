//! #11 type-recovery engine: infer structure shapes from member-access
//! evidence, discover vtable candidates, and propose types the agent can
//! preview and then apply through explicit mutations.
//!
//! Evidence model: every proposed field carries observed facts (read/write
//! site counts, candidate width, candidate type) and a confidence score
//! derived from them; observed facts, inference and the applied IDB mutation
//! are reported separately. Proposals are previews — nothing is applied
//! without an explicit agent request.

use std::collections::{BTreeMap, BTreeSet};

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;
use rmcp_core::error::{Error, Result};
use serde_json::{Value, json};

/// One aggregated field proposal.
struct FieldProposal {
    /// Sites observing this field (read / write).
    reads: usize,
    writes: usize,
    /// Candidate widths observed (bytes); the modal value wins.
    widths: Vec<u32>,
    /// Distinct functions that observed this field.
    functions: usize,
    /// True when some site stored a pointer-sized value into it.
    pointer_candidate: bool,
}

impl FieldProposal {
    /// Candidate width: modal observed access size (0 = unknown).
    fn width(&self) -> u32 {
        let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
        for w in &self.widths {
            if *w > 0 {
                *counts.entry(*w).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .max_by_key(|(w, c)| (*c, *w))
            .map(|(w, _)| w)
            .unwrap_or(0)
    }

    /// Confidence in [0,1]: grows with independent sites and functions,
    /// with write evidence, and with a consistent width. Deliberately
    /// conservative: a single read site in one function is weak evidence.
    fn confidence(&self) -> f64 {
        let sites = (self.reads + self.writes) as f64;
        let site_score = (sites / 8.0).min(1.0) * 0.45;
        let fn_score = (self.functions as f64 / 3.0).min(1.0) * 0.25;
        let write_score = if self.writes > 0 { 0.18 } else { 0.0 };
        let width = self.width();
        let width_score = if width > 0 { 0.12 } else { 0.0 };
        (site_score + fn_score + write_score + width_score).clamp(0.05, 0.99)
    }

    fn candidate_type(&self, width: u32) -> &'static str {
        if self.pointer_candidate {
            "pointer"
        } else {
            match width {
                1 => "u8",
                2 => "u16",
                4 => "u32",
                8 => "u64",
                _ => "unknown",
            }
        }
    }
}

/// Aggregate member observations from one or more functions into field
/// proposals grouped by base object (global EA when known, else the
/// rendered base expression).
pub fn recover_structure(
    backend: &dyn IdaBackend,
    idx: &AnalysisIndex,
    function_eas: &[u64],
    max_members_per_fn: usize,
) -> Result<Value> {
    if function_eas.is_empty() {
        return Err(Error::Worker("recover_structure requires functions".into()));
    }
    // (base_key, offset) -> proposal. base_key: "g:<ea>" or "e:<expr>".
    let mut fields: BTreeMap<(String, u64), FieldProposal> = BTreeMap::new();
    let mut per_function: Vec<Value> = Vec::new();
    let mut truncated_any = false;

    for &ea in function_eas {
        let Ok(info) = backend.type_member_evidence(ea, max_members_per_fn) else {
            continue;
        };
        truncated_any |= info["truncated"].as_bool().unwrap_or(false);
        let members = info["members"].as_array().cloned().unwrap_or_default();
        let n_obs = members.len();
        let mut this_fn: BTreeSet<(String, u64)> = BTreeSet::new();
        for m in &members {
            let base_ea = m["base_ea"].as_str().unwrap_or_default();
            let base_text = m["base_text"].as_str().unwrap_or_default();
            let key = if m["is_global"].as_bool().unwrap_or(false) {
                format!("g:{base_ea}")
            } else {
                format!("e:{base_text}")
            };
            let offset = parse_hex(m["offset"].as_str().unwrap_or_default());
            let width = m["access_size"].as_u64().unwrap_or(0) as u32;
            let write = m["is_write"].as_bool().unwrap_or(false);
            let entry = fields
                .entry((key.clone(), offset))
                .or_insert_with(|| FieldProposal {
                    reads: 0,
                    writes: 0,
                    widths: Vec::new(),
                    functions: 0,
                    pointer_candidate: width == 8 && !write,
                });
            if write {
                entry.writes += 1;
            } else {
                entry.reads += 1;
            }
            entry.widths.push(width);
            if width == 8 {
                entry.pointer_candidate = true;
            }
            this_fn.insert((key, offset));
        }
        // Count distinct functions per field.
        for key in &this_fn {
            if let Some(f) = fields.get_mut(key) {
                f.functions += 1;
            }
        }
        per_function.push(json!({
            "function": {"ea": format!("{ea:#x}"), "name": function_name(idx, ea)},
            "observations": n_obs,
        }));
    }

    // Emit proposals with evidence; sorted by offset for readability.
    let mut proposals: Vec<Value> = Vec::new();
    let mut grouped: BTreeMap<String, Vec<(u64, &FieldProposal)>> = BTreeMap::new();
    for ((key, offset), p) in &fields {
        grouped.entry(key.clone()).or_default().push((*offset, p));
    }
    for (base_key, mut fields_of_base) in grouped {
        fields_of_base.sort_by_key(|(o, _)| *o);
        let (kind, base_ea) = if let Some(rest) = base_key.strip_prefix("g:") {
            ("global", rest.to_string())
        } else {
            ("expression", base_key.trim_start_matches("e:").to_string())
        };
        let field_rows: Vec<Value> = fields_of_base
            .iter()
            .map(|(offset, p)| {
                let width = p.width();
                json!({
                    "offset": format!("{offset:#x}"),
                    "read": p.reads,
                    "write": p.writes,
                    "candidate_width": width,
                    "candidate_type": p.candidate_type(width),
                    "confidence": format!("{:.2}", p.confidence()),
                    "functions_observing": p.functions,
                })
            })
            .collect();
        // Struct proposal: consecutive fields define the shape.
        let shape: Vec<(u64, u64)> = fields_of_base
            .iter()
            .map(|(offset, p)| {
                let w = p.width();
                (*offset, if w == 0 { 4 } else { w as u64 })
            })
            .collect();
        let shape_match = backend.type_udt_match(&shape).ok();
        proposals.push(json!({
            "base": {"kind": kind, "ea": base_ea},
            "fields": field_rows,
            "proposed_shape": shape.iter().map(|(o, s)| json!({
                "offset": format!("{o:#x}"), "size": s,
            })).collect::<Vec<_>>(),
            "existing_type_match": shape_match
                .and_then(|m| m["match"].as_str().map(|s| json!(s)))
                .unwrap_or(Value::Null),
        }));
    }

    Ok(json!({
        "functions": per_function,
        "proposals": proposals,
        "truncated": truncated_any,
        "note": "preview only; apply via ida_types task=create_struct (explicit mutation)",
    }))
}

/// Discover vtable candidates: scan the target EA as a vtable and map slots
/// to candidate methods.
pub fn recover_vtable(backend: &dyn IdaBackend, ea: u64, max_entries: usize) -> Result<Value> {
    let scan = backend.type_vtable_scan(ea, max_entries)?;
    let slots = scan["slots"].as_array().cloned().unwrap_or_default();
    let code_slots = slots
        .iter()
        .filter(|s| s["is_code"].as_bool().unwrap_or(false))
        .count();
    // A plausible vtable has >= 2 code pointers in the first slots.
    let plausible = code_slots >= 2;
    Ok(json!({
        "ea": format!("{ea:#x}"),
        "plausible_vtable": plausible,
        "code_slots": code_slots,
        "slots": slots,
        "virtual_calls_note": "slot order maps to the class's method order; verify constructors before trusting",
    }))
}

/// Proposed struct definition the agent reviewed; applying is a separate,
/// explicit mutation (ida_types task=create_struct).
pub fn apply_struct(backend: &mut dyn IdaBackend, name: &str, fields: &[String]) -> Result<Value> {
    if name.trim().is_empty() || fields.is_empty() {
        return Err(Error::Worker(
            "apply_struct needs a non-empty name and at least one field".into(),
        ));
    }
    let out = backend.type_udt_create(name, fields)?;
    Ok(json!({
        "applied": out.changed,
        "revision_after": out.revision_after,
        "detail": out.detail,
    }))
}

fn function_name(idx: &AnalysisIndex, ea: u64) -> String {
    idx.functions
        .get(&ea)
        .map(|f| f.name.clone())
        .unwrap_or_else(|| format!("sub_{ea:x}"))
}

fn parse_hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim().trim_start_matches("0x"), 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp_ida::MockBackend;

    fn open_mock() -> MockBackend {
        let mut b = MockBackend::new();
        b.open("t.i64").unwrap();
        b
    }

    #[test]
    fn recover_structure_aggregates_fields_with_confidence() {
        let b = open_mock();
        let idx = b.build_index().unwrap().0;
        let out = recover_structure(&b, &idx, &[0x401000], 64).unwrap();
        let proposals = out["proposals"].as_array().unwrap();
        assert!(!proposals.is_empty(), "out: {out}");
        let fields = proposals[0]["fields"].as_array().unwrap();
        assert!(fields.len() >= 3, "fields: {fields:?}");
        for f in fields {
            let conf: f64 = f["confidence"].as_str().unwrap().parse().unwrap();
            assert!((0.0..=1.0).contains(&conf), "conf: {f}");
            assert!(f["read"].as_u64().is_some(), "{f}");
        }
    }

    #[test]
    fn recover_structure_requires_functions() {
        let b = open_mock();
        let idx = b.build_index().unwrap().0;
        let err = recover_structure(&b, &idx, &[], 64).unwrap_err();
        assert!(err.to_string().contains("requires"));
    }

    #[test]
    fn vtable_scan_reports_slots() {
        let b = open_mock();
        let out = recover_vtable(&b, 0x402000, 8).unwrap();
        let slots = out["slots"].as_array().unwrap();
        assert!(slots.len() >= 2, "out: {out}");
        for s in slots {
            assert!(s["is_code"].as_bool().unwrap(), "{s}");
        }
    }

    #[test]
    fn apply_struct_validates_input() {
        let mut b = open_mock();
        let err = apply_struct(&mut b, "", &["0:4:x:int".into()]).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
        let err = apply_struct(&mut b, "s_t", &[]).unwrap_err();
        assert!(err.to_string().contains("at least one field"));
        // Valid apply mutates and reports a revision.
        let out = apply_struct(&mut b, "s_t", &["0:4:x:int".into()]).unwrap();
        assert_eq!(out["applied"], true);
        assert!(out["revision_after"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn shape_match_finds_known_layout() {
        let b = open_mock();
        let out = b.type_udt_match(&[(0x0, 4), (0x8, 8), (0x10, 4)]).unwrap();
        assert_eq!(out["match"], "mock_shape_t", "out: {out}");
        let miss = b.type_udt_match(&[(0x0, 4)]).unwrap();
        assert!(miss["match"].is_null(), "out: {miss}");
    }
}
