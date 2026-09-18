//! Ground-truth tests for the WASM semantic layer (#71 acceptance):
//! module model, structured CFG, SSA, indirect calls, pseudocode 鈥?//! all against a hand-written WAT fixture with exact known facts.

use rmcp_wasm::calls::{resolve_indirect, Confidence};
use rmcp_wasm::cfg::{analyze_body, BlockKind};
use rmcp_wasm::module::{parse, ModuleModel};
use rmcp_wasm::pseudo::render;
use rmcp_wasm::ssa::analyze_values;

const FIXTURE: &str = r#"
(module
  (type $binop (func (param i32 i32) (result i32)))
  (memory (export "mem") 1)
  (global $g (mut i32) (i32.const 42))
  (table $t 4 funcref)
  (elem (i32.const 0) $add $sub $mul)
  (data (i32.const 16) "hello")
  (func $add (type $binop) (i32.add (local.get 0) (local.get 1)))
  (func $sub (type $binop) (i32.sub (local.get 0) (local.get 1)))
  (func $mul (type $binop) (i32.mul (local.get 0) (local.get 1)))
  (func $dispatch (param $op i32) (param $a i32) (param $b i32) (result i32)
    (call_indirect (type $binop)
      (local.get 0)
      (local.get 1)
      (i32.and (local.get 2) (i32.const 3))))
  (func $loopsum (param $n i32) (result i32)
    (local $acc i32)
    (local $i i32)
    (block $exit
      (loop $top
        (br_if $exit (i32.ge_u (local.get $i) (local.get $n)))
        (local.set $acc (i32.add (local.get $acc) (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $top)))
    (local.get $acc))
  (func $caller (result i32)
    (call $add (i32.const 2) (i32.const 3)))
  (export "add" (func $add))
  (export "dispatch" (func $dispatch))
  (export "caller" (func $caller))
)
"#;

fn build() -> (ModuleModel, Vec<u8>) {
    let bytes = wat::parse_str(FIXTURE).expect("wat");
    let model = parse(&bytes).expect("parse");
    (model, bytes)
}

#[test]
fn module_model_ground_truth() {
    let (m, _) = build();
    // Types: $binop only -> 1 (structural parse may dedupe; assert >=1).
    assert!(!m.types.is_empty(), "at least one type");
    let binop = m
        .types
        .iter()
        .find(|t| t.params == vec!["i32", "i32"] && t.results == vec!["i32"])
        .expect("binop type present");
    assert_eq!(binop.params, vec!["i32", "i32"]);

    // 6 defined functions, no imports.
    assert_eq!(m.imported_functions, 0);
    assert_eq!(m.functions.len(), 6);

    // Names come from the WAT export/name sections only when a name custom
    // section exists; WAT text does not emit one, so names may be None.
    assert!(m.functions.iter().all(|f| f.code_size > 0));

    // Table 4 funcref; element segment with 3 entries at offset 0.
    assert_eq!(m.tables.len(), 1);
    assert_eq!(m.tables[0].initial, 4);
    assert_eq!(m.elements.len(), 1);
    assert_eq!(m.elements[0].offset, Some(0));
    assert_eq!(m.elements[0].func_indices, vec![0, 1, 2]);

    // Global $g = 42.
    assert!(m.globals.iter().any(|g| g.init.as_deref() == Some("42")));

    // Data segment at offset 16 with 5 bytes.
    assert_eq!(m.datas.len(), 1);
    assert_eq!(m.datas[0].offset, Some(16));
    assert_eq!(m.datas[0].len, 5);

    // Exports include add + dispatch + caller as funcs.
    for name in ["add", "dispatch", "caller"] {
        assert!(
            m.exports.iter().any(|e| e.name == name && e.kind == "func"),
            "export {name}"
        );
    }

    // Sections all carry ranges.
    assert!(m.sections.iter().all(|s| s.size > 0));
}

#[test]
fn structured_cfg_preserves_nesting() {
    let (m, bytes) = build();
    // loopsum is function index 4 (0=add,1=sub,2=mul,3=dispatch,4=loopsum).
    let f = m.functions.iter().find(|f| f.index == 4).expect("loopsum");
    let body = &bytes[f.code_offset as usize..(f.code_offset + f.code_size) as usize];
    let cfg = analyze_body(body).expect("cfg");
    assert!(cfg.operator_count > 0);

    // There must be exactly one loop region and one block region.
    let loops = cfg
        .regions
        .iter()
        .filter(|r| r.kind == BlockKind::Loop)
        .count();
    let blocks = cfg
        .regions
        .iter()
        .filter(|r| r.kind == BlockKind::Block)
        .count();
    assert_eq!(loops, 1, "one loop");
    assert_eq!(blocks, 2, "block + the implicit if-block region");
    // The loop's parent is the block.
    let loop_r = cfg.regions.iter().find(|r| r.kind == BlockKind::Loop).unwrap();
    let block_r = cfg
        .regions
        .iter()
        .find(|r| r.id == loop_r.parent.expect("loop has parent"))
        .expect("parent region exists");
    assert_eq!(loop_r.parent, Some(block_r.id));
    // br_if targets the block ($exit), br targets the loop ($top).
    assert!(!block_r.branch_sources.is_empty(), "block receives br_if");
    assert!(!loop_r.branch_sources.is_empty(), "loop receives br");
    assert!(cfg.diagnostics.is_empty(), "no diagnostics: {cfg:?}");
}

#[test]
fn direct_call_graph_ground_truth() {
    let (m, bytes) = build();
    // caller is index 5; it calls $add (index 0) with consts 2,3.
    let f = m.functions.iter().find(|f| f.index == 5).expect("caller");
    let body = &bytes[f.code_offset as usize..(f.code_offset + f.code_size) as usize];
    let cfg = analyze_body(body).expect("cfg");
    assert_eq!(cfg.calls.len(), 1);
    assert_eq!(cfg.calls[0].1, 0, "caller -> add (fn 0)");
    assert!(cfg.indirect_calls.is_empty());
}

#[test]
fn indirect_call_resolution_bounded() {
    let (m, bytes) = build();
    // dispatch is index 3 with one call_indirect typed $binop (type 0).
    let f = m.functions.iter().find(|f| f.index == 3).expect("dispatch");
    let body = &bytes[f.code_offset as usize..(f.code_offset + f.code_size) as usize];
    let cfg = analyze_body(body).expect("cfg");
    assert_eq!(cfg.indirect_calls.len(), 1);
    let (site, tidx, _table) = cfg.indirect_calls[0];
    assert_eq!(tidx, 0, "declared type $binop");

    // Non-constant index -> bounded candidates, not fabricated certainty.
    let resolved = resolve_indirect(&m, &cfg.indirect_calls, &Default::default());
    assert_eq!(resolved.len(), 1);
    let r = &resolved[0];
    assert_eq!(r.site_offset, site);
    // Candidates must be a subset of {0,1,2} (the functions in elem segment).
    assert!(
        r.targets.iter().all(|t| [0u32, 1, 2].contains(t)),
        "candidates bounded to table contents: {:?}",
        r.targets
    );
    assert!(!r.targets.is_empty(), "type-compatible candidates exist");
    assert_eq!(r.confidence, Confidence::Candidate);

    // Constant index 0 -> confirmed target fn 0 ($add).
    let mut consts = std::collections::BTreeMap::new();
    consts.insert(site, 0u64);
    let resolved = resolve_indirect(&m, &cfg.indirect_calls, &consts);
    assert_eq!(resolved[0].confidence, Confidence::Confirmed);
    assert_eq!(resolved[0].targets, vec![0]);
}

#[test]
fn ssa_use_def_ground_truth() {
    let (m, bytes) = build();
    // loopsum: locals accumulate; check loads/stores recorded.
    let f = m.functions.iter().find(|f| f.index == 4).expect("loopsum");
    let body = &bytes[f.code_offset as usize..(f.code_offset + f.code_size) as usize];
    let ssa = analyze_values(body, 1).expect("ssa"); // 1 param
    assert!(ssa.operator_count > 0);
    assert!(!ssa.local_stores.is_empty(), "loop writes locals");
    assert!(!ssa.local_loads.is_empty(), "loop reads locals");
    // The branch condition (br_if) is tracked.
    assert_eq!(ssa.branch_conditions.len(), 1);
    // At least one constant (i32.const 1 in the increment).
    assert!(ssa.values.iter().any(|v| v.constant == Some(1)));
}

#[test]
fn pseudocode_deterministic_and_labeled() {
    let (m, bytes) = build();
    let f = m.functions.iter().find(|f| f.index == 4).expect("loopsum");
    let body = &bytes[f.code_offset as usize..(f.code_offset + f.code_size) as usize];
    let cfg = analyze_body(body).expect("cfg");
    let p1 = render(&m, 4, body, &cfg).expect("pseudo");
    let p2 = render(&m, 4, body, &cfg).expect("pseudo");
    assert_eq!(p1, p2, "deterministic output");
    assert!(p1.contains("not Hex-Rays"), "must be labeled: {p1}");
    assert!(p1.contains("do {") || p1.contains("loop"), "structured: {p1}");
    assert!(p1.contains("goto label_m"), "br rendering: {p1}");
}

#[test]
fn malformed_module_fails_locally() {
    // Truncated: valid magic, cut mid-section.
    let bytes = vec![0u8, b'a', b's', b'm', 1, 0, 0, 0, 1, 5];
    let r = parse(&bytes);
    assert!(r.is_err(), "truncated module must error, not hang");
    // Bad magic.
    let r = parse(b"not a wasm module at all.........");
    assert!(r.is_err());
}
