//! Mock IDA backend: deterministic in-memory dataset mirroring the C fixture
//! sources in `tests/fixtures/`. Lets broker/protocol/tool tests run without
//! an IDA install and forms the CI test bed.

use serde_json::{Value, json};

use rmcp_core::backend::{
    Capabilities, FunctionInfo, GraphParams, IdaBackend, InsnInfo, MutationOutcome, SegmentInfo,
    StringInfo, XrefInfo,
};
use rmcp_core::error::{Error, Result};

/// Deterministic mock DB shaped like the fixture binary.
#[derive(Debug)]
pub struct MockBackend {
    open_path: Option<String>,
    revision: u64,
    names: std::collections::BTreeMap<u64, String>,
    comments: std::collections::BTreeMap<(u64, bool), String>,
    bytes: std::collections::BTreeMap<u64, Vec<u8>>,
    decompile_off: bool,
    /// Extra xrefs injected by tests (from, to, kind).
    extra_xrefs: Vec<(u64, u64, String)>,
    /// Snapshot stack (#16): each entry clones the mutable state at
    /// snapshot time so `snapshot_restore` can roll back.
    snapshots: Vec<SnapshotState>,
}

/// Full copy of the mutable IDB state for logical rollback.
#[derive(Debug, Clone)]
struct SnapshotState {
    revision: u64,
    names: std::collections::BTreeMap<u64, String>,
    comments: std::collections::BTreeMap<(u64, bool), String>,
    bytes: std::collections::BTreeMap<u64, Vec<u8>>,
}

impl MockBackend {
    pub fn new() -> Self {
        let mut names = std::collections::BTreeMap::new();
        // Fixture layout (matches tests/fixtures/simple.c):
        // main at 0x401000, helper at 0x401100, decrypt_packet at 0x401200,
        // dispatch (switch) at 0x401300, call_via_ptr at 0x401400.
        for (ea, name) in [
            (0x401000, "main"),
            (0x401100, "helper"),
            (0x401200, "decrypt_packet"),
            (0x401300, "dispatch"),
            (0x401400, "call_via_ptr"),
        ] {
            names.insert(ea, name.to_string());
        }
        let mut bytes = std::collections::BTreeMap::new();
        bytes.insert(0x401000, vec![0x55, 0x48, 0x89, 0xe5, 0xc3]); // main stub
        bytes.insert(0x401100, vec![0x55, 0xc3]);
        Self {
            open_path: None,
            revision: 0,
            names,
            comments: std::collections::BTreeMap::new(),
            bytes,
            decompile_off: false,
            extra_xrefs: Vec::new(),
            snapshots: Vec::new(),
        }
    }

    /// Test hook: inject an xref so adversarial paths can be driven
    /// deterministically (used by the transform-validate tests).
    pub fn add_xref_for_test(&mut self, from: u64, to: u64, kind: &str) {
        self.extra_xrefs.push((from, to, kind.to_string()));
    }

    /// Disable decompile capability to test `capability_unavailable` paths.
    pub fn without_decompile(mut self) -> Self {
        self.decompile_off = true;
        self
    }

    fn require_open(&self) -> Result<()> {
        if self.open_path.is_some() {
            Ok(())
        } else {
            Err(Error::Worker("no db open".into()))
        }
    }

    fn bump(&mut self) -> u64 {
        self.revision += 1;
        self.revision
    }

    fn functions_vec(&self) -> Vec<FunctionInfo> {
        self.names
            .iter()
            .map(|(&ea, name)| FunctionInfo {
                ea_start: ea,
                ea_end: ea + 0x40,
                name: name.clone(),
                size: 0x40,
            })
            .collect()
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl IdaBackend for MockBackend {
    fn open(&mut self, path: &str) -> Result<Value> {
        if self.open_path.is_some() {
            return Err(Error::Worker("a db is already open".into()));
        }
        self.open_path = Some(path.to_string());
        Ok(json!({"path": path, "arch": "x86_64", "bits": 64}))
    }

    fn close(&mut self) -> Result<()> {
        self.open_path = None;
        Ok(())
    }

    fn save(&mut self) -> Result<()> {
        self.require_open()?;
        Ok(())
    }

    fn db_info(&self) -> Result<Value> {
        self.require_open()?;
        Ok(json!({
            "path": self.open_path,
            "arch": "x86_64",
            "bits": 64,
            "function_count": self.names.len(),
            "revision": self.revision,
        }))
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            decompile: !self.decompile_off,
            types: true,
            imports_exports: true,
            patch_bytes: true,
            rename: true,
            comments: true,
            bookmarks: true,
            plugins: true,
            ctree: !self.decompile_off,
            lvars: !self.decompile_off,
            microcode: !self.decompile_off,
            switches: true,
            fixups: true,
            tails: true,
            sp_delta: true,
            file_map: true,
        }
    }

    fn revision(&self) -> u64 {
        self.revision
    }

    fn functions(&self, offset: usize, limit: usize) -> Result<Vec<FunctionInfo>> {
        self.require_open()?;
        let all = self.functions_vec();
        Ok(all.into_iter().skip(offset).take(limit).collect())
    }

    fn function_at(&self, ea: u64) -> Result<FunctionInfo> {
        self.require_open()?;
        self.functions_vec()
            .into_iter()
            .find(|f| ea >= f.ea_start && ea < f.ea_end)
            .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))
    }

    fn segments(&self) -> Result<Vec<SegmentInfo>> {
        self.require_open()?;
        Ok(vec![
            SegmentInfo {
                name: ".text".into(),
                start: 0x401000,
                end: 0x402000,
                perms: "r-x".into(),
            },
            SegmentInfo {
                name: ".data".into(),
                start: 0x402000,
                end: 0x403000,
                perms: "rw-".into(),
            },
        ])
    }

    fn strings(&self, offset: usize, limit: usize) -> Result<Vec<StringInfo>> {
        self.require_open()?;
        let all = vec![
            StringInfo {
                ea: 0x402010,
                value: "usage: %s <file>".into(),
                length: 16,
            },
            StringInfo {
                ea: 0x402030,
                value: "decrypt: bad key".into(),
                length: 16,
            },
        ];
        Ok(all.into_iter().skip(offset).take(limit).collect())
    }

    fn xrefs_to(&self, ea: u64) -> Result<Vec<XrefInfo>> {
        self.require_open()?;
        // main calls helper and decrypt_packet in the fixture.
        let mut out: Vec<XrefInfo> = self
            .extra_xrefs
            .iter()
            .filter(|(_, to, _)| *to == ea)
            .map(|(from, to, kind)| XrefInfo {
                from: *from,
                to: *to,
                kind: kind.clone(),
            })
            .collect();
        if ea == 0x401100 {
            out.push(XrefInfo {
                from: 0x401020,
                to: ea,
                kind: "call".into(),
            });
        }
        if ea == 0x401200 {
            out.push(XrefInfo {
                from: 0x401030,
                to: ea,
                kind: "call".into(),
            });
        }
        Ok(out)
    }

    fn xrefs_from(&self, ea: u64) -> Result<Vec<XrefInfo>> {
        self.require_open()?;
        let mut out = Vec::new();
        if ea == 0x401000 {
            out.push(XrefInfo {
                from: ea,
                to: 0x401100,
                kind: "call".into(),
            });
            out.push(XrefInfo {
                from: ea,
                to: 0x401200,
                kind: "call".into(),
            });
        }
        Ok(out)
    }

    fn disassemble(
        &self,
        ea_start: u64,
        ea_end: Option<u64>,
        max_insns: usize,
    ) -> Result<Vec<InsnInfo>> {
        self.require_open()?;
        let end = ea_end.unwrap_or(ea_start + 0x10);
        let mut out = Vec::new();
        let mut ea = ea_start;
        while ea < end && out.len() < max_insns {
            out.push(InsnInfo {
                ea,
                mnemonic: "mov".into(),
                operands: "eax, ebx".into(),
                text: format!("mov eax, ebx ; {ea:#x}"),
            });
            ea += 4;
        }
        Ok(out)
    }

    fn decompile(&self, ea: u64) -> Result<Value> {
        if self.decompile_off {
            return Err(Error::CapabilityUnavailable {
                capability: "decompile".into(),
                reason: "hexrays not available in this backend".into(),
            });
        }
        self.require_open()?;
        let f = self.function_at(ea)?;
        Ok(json!({
            "function": f.name,
            "ea": f.ea_start,
            "pseudocode": format!("// {:#x}\nint {}(int a, int b) {{\n    return a + b;\n}}", f.ea_start, f.name),
        }))
    }

    fn graph(&self, ea: u64, params: &GraphParams) -> Result<Value> {
        self.require_open()?;
        let depth = params.depth;
        let f = self.function_at(ea)?;
        let mut nodes = vec![json!({"ea": f.ea_start, "name": f.name})];
        let mut edges = Vec::new();
        if depth >= 1 {
            for x in self.xrefs_from(f.ea_start)? {
                if let Ok(callee) = self.function_at(x.to) {
                    nodes.push(json!({"ea": callee.ea_start, "name": callee.name}));
                    edges.push(json!({"from": f.ea_start, "to": callee.ea_start}));
                }
            }
        }
        Ok(json!({"root": f.ea_start, "nodes": nodes, "edges": edges}))
    }

    fn search_text(&self, needle: &str, limit: usize) -> Result<Vec<Value>> {
        self.require_open()?;
        let mut out = Vec::new();
        for s in self.strings(0, usize::MAX)? {
            if s.value.contains(needle) {
                out.push(json!({"ea": s.ea, "text": s.value}));
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    fn search_immediate(&self, value: u64, limit: usize) -> Result<Vec<Value>> {
        self.require_open()?;
        let mut out = Vec::new();
        for &ea in self.names.keys() {
            if ea == value {
                out.push(json!({"ea": ea, "context": "function start"}));
            }
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    fn get_bytes(&self, ea: u64, size: usize) -> Result<Value> {
        self.require_open()?;
        let empty: Vec<u8> = Vec::new();
        let b = self.bytes.get(&ea).unwrap_or(&empty);
        let b = &b[..size.min(b.len())];
        let hex: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
        Ok(json!({"ea": ea, "size": b.len(), "hex": hex.join("")}))
    }

    fn patch_bytes(&mut self, ea: u64, bytes_hex: &str) -> Result<MutationOutcome> {
        self.require_open()?;
        let decoded = hex::decode(&bytes_hex.trim().replace(' ', ""))
            .map_err(|e| Error::Worker(format!("bad hex: {e}")))?;
        self.bytes.insert(ea, decoded);
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea}),
        })
    }

    fn get_comment(&self, ea: u64, repeatable: bool) -> Result<Value> {
        self.require_open()?;
        Ok(json!({
            "ea": ea,
            "repeatable": repeatable,
            "comment": self.comments.get(&(ea, repeatable)).cloned().unwrap_or_default(),
        }))
    }

    fn set_comment(&mut self, ea: u64, comment: &str, repeatable: bool) -> Result<MutationOutcome> {
        self.require_open()?;
        self.comments.insert((ea, repeatable), comment.to_string());
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea}),
        })
    }

    fn rename(&mut self, ea: u64, new_name: &str) -> Result<MutationOutcome> {
        self.require_open()?;
        if !self.names.contains_key(&ea) {
            return Err(Error::Worker(format!("no function at {ea:#x}")));
        }
        let old = self.names.insert(ea, new_name.to_string()).unwrap();
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea, "old": old, "new": new_name}),
        })
    }

    fn types(&self, name: Option<&str>) -> Result<Value> {
        self.require_open()?;
        let all = vec![
            json!({"name": "packet_header", "decl": "struct packet_header { uint32_t magic; uint16_t len; }"}),
            json!({"name": "status_t", "decl": "enum status_t { OK = 0, ERR = 1 }"}),
        ];
        match name {
            Some(n) => all
                .into_iter()
                .find(|t| t["name"] == *n)
                .ok_or_else(|| Error::Worker(format!("type '{n}' not found"))),
            None => Ok(json!(all)),
        }
    }

    fn set_type(&mut self, ea: u64, type_decl: &str) -> Result<MutationOutcome> {
        self.require_open()?;
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea, "applied": type_decl}),
        })
    }

    // ---- #19: database / binary metadata (deterministic fixture data) ----

    fn db_metadata(&self) -> Result<Value> {
        self.require_open()?;
        Ok(json!({
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "imagebase": 0x400000,
            "entry_count": 1,
            "entries": [{"ordinal": 0, "ea": 0x401000, "name": "main"}],
            "tls_callbacks": Value::Null,
            "tls_callbacks_supported": false,
            "exception_handlers_supported": false,
        }))
    }

    fn imports(&self, module: Option<usize>, offset: usize, limit: usize) -> Result<Value> {
        self.require_open()?;
        let entries = vec![
            json!({"ea": 0x403000u64, "name": "CreateFileA", "ordinal": 0u64}),
            json!({"ea": 0x403004u64, "name": "ReadFile", "ordinal": 1u64}),
        ]
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
        let modules = vec![json!({
            "index": 0,
            "name": "KERNEL32.dll",
            "entries": entries,
        })];
        match module {
            Some(idx) if idx >= modules.len() => Ok(json!({"modules": [], "module_count": 1})),
            _ => Ok(json!({"modules": modules, "module_count": 1})),
        }
    }

    fn fixups(&self, offset: usize, limit: usize) -> Result<Value> {
        self.require_open()?;
        let all = vec![
            json!({"ea": 0x402000, "kind": 1, "flags": 0, "base": 0, "sel": 0, "off": 0x403000, "displacement": 0}),
            json!({"ea": 0x402008, "kind": 1, "flags": 0, "base": 0, "sel": 0, "off": 0x403004, "displacement": 0}),
        ];
        let total = all.len();
        Ok(json!({
            "total": total,
            "fixups": all.into_iter().skip(offset).take(limit).collect::<Vec<_>>(),
        }))
    }

    fn file_map(&self, value: u64, to_ea: bool) -> Result<Value> {
        self.require_open()?;
        // Deterministic fixture mapping: EA 0x401000..0x402000 <-> file
        // offset 0x400..0x1400 (mock of get_fileregion_offset/ea).
        let ea2off = |ea: u64| ea.checked_sub(0x400000).map(|v| v + 0x400);
        let off2ea = |off: u64| off.checked_sub(0x400).map(|v| v + 0x400000);
        if to_ea {
            off2ea(value)
                .map(|ea| json!({"file_offset": value, "ea": ea}))
                .ok_or_else(|| {
                    Error::Worker(format!("file offset {value:#x} does not map to an address"))
                })
        } else {
            ea2off(value)
                .map(|off| json!({"ea": value, "file_offset": off}))
                .ok_or_else(|| {
                    Error::Worker(format!(
                        "address {value:#x} does not map into the input file"
                    ))
                })
        }
    }

    // ---- #19: functions / control flow ----

    fn func_tails(&self, ea: u64) -> Result<Value> {
        let f = self.function_at(ea)?;
        Ok(json!({
            "function": f.ea_start,
            "chunks": [{"start": f.ea_start, "end": f.ea_end, "size": f.size}],
            "is_tail_target": false,
        }))
    }

    fn func_create(&mut self, start: u64, end: Option<u64>) -> Result<MutationOutcome> {
        self.require_open()?;
        self.names
            .entry(start)
            .or_insert_with(|| format!("sub_{start:x}"));
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"start": start, "end": end}),
        })
    }

    fn func_delete(&mut self, ea: u64) -> Result<MutationOutcome> {
        self.require_open()?;
        if self.names.remove(&ea).is_none() {
            return Err(Error::Worker(format!("no function at {ea:#x}")));
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea}),
        })
    }

    fn func_resize(
        &mut self,
        ea: u64,
        new_start: Option<u64>,
        new_end: Option<u64>,
    ) -> Result<MutationOutcome> {
        self.require_open()?;
        if new_start.is_none() && new_end.is_none() {
            return Err(Error::Worker(
                "func_resize requires new_start and/or new_end".into(),
            ));
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea, "start": new_start, "end": new_end}),
        })
    }

    fn func_switch_info(&self, ea: u64) -> Result<Value> {
        self.require_open()?;
        // dispatch at 0x401300 has the fixture's switch.
        if ea == 0x401310 {
            return Ok(json!({
                "ea": ea,
                "jump_table": 0x402100,
                "ncases": 4,
                "elbase": 0x401300,
                "lowcase": 0,
                "regnum": 0,
            }));
        }
        Err(Error::Worker(format!("no switch information at {ea:#x}")))
    }

    fn func_sp_delta(&self, ea: u64) -> Result<Value> {
        let _ = self.function_at(ea)?;
        Ok(json!({"ea": ea, "sp_delta": -8}))
    }

    // ---- #19: Hex-Rays ----

    fn hr_cfunc(
        &self,
        ea: u64,
        include_ctree: bool,
        include_lvars: bool,
        limit: usize,
    ) -> Result<Value> {
        if self.decompile_off {
            return Err(Error::CapabilityUnavailable {
                capability: "decompile".into(),
                reason: "hexrays not available in this backend".into(),
            });
        }
        let f = self.function_at(ea)?;
        let mut out = json!({
            "function": f.name,
            "ea": f.ea_start,
            "return_type": "int",
        });
        if include_ctree {
            // Deterministic ctree summary for decrypt_packet's XOR loop.
            let rows: Vec<Value> = [
                (f.ea_start, 0, "int main(int a, int b)"),
                (f.ea_start + 4, 0, "return a + b"),
            ]
            .into_iter()
            .take(limit)
            .map(|(ea, op, text)| json!({"ea": ea, "op": op, "is_expr": op != 0, "text": text}))
            .collect();
            out["ctree"] = json!(rows);
            out["ctree_truncated"] = json!(false);
        }
        if include_lvars {
            out["lvars"] = json!([
                {"defea": f.ea_start, "name": "a", "type_text": "int", "width": 4, "is_arg": true, "is_result": false},
                {"defea": f.ea_start + 4, "name": "b", "type_text": "int", "width": 4, "is_arg": true, "is_result": false},
            ]);
            out["lvars_truncated"] = json!(false);
        }
        Ok(out)
    }

    fn hr_lvar_rename(
        &mut self,
        ea: u64,
        var_defea: u64,
        new_name: &str,
    ) -> Result<MutationOutcome> {
        if self.decompile_off {
            return Err(Error::CapabilityUnavailable {
                capability: "decompile".into(),
                reason: "hexrays not available in this backend".into(),
            });
        }
        let f = self.function_at(ea)?;
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"function": f.ea_start, "var_defea": var_defea, "new": new_name}),
        })
    }

    // ---- #19: instructions / names ----

    fn insn_features(&self, ea: u64) -> Result<Value> {
        self.require_open()?;
        Ok(json!({
            "ea": ea,
            "features": 0x0500, // CF_CALL|CF_JUMP on call sites in the fixture
            "mnemonic": "mov",
        }))
    }

    fn demangle_name(&self, name: &str) -> Result<Value> {
        self.require_open()?;
        let demangled = if name.starts_with("?") || name.starts_with("_Z") {
            format!("{name}_demangled")
        } else {
            name.to_string()
        };
        Ok(json!({"name": name, "demangled": demangled, "changed": demangled != name}))
    }

    // ---- #43: microcode (deterministic fake mba) ----

    fn hr_microcode(&self, ea: u64, req_maturity: u32, max_insns: usize) -> Result<Value> {
        self.require_open()?;
        if self.decompile_off {
            return Err(Error::CapabilityUnavailable {
                capability: "decompile".into(),
                reason: "hexrays not available in this backend".into(),
            });
        }
        let f = self.function_at(ea)?;
        // Deterministic 3-block mba: entry -> body -> exit, with a jz back
        // edge so successors/predecessors are non-trivial.
        let maturity = if req_maturity == 0 {
            5
        } else {
            req_maturity.min(7)
        };
        let body_ea = f.ea_start + 4;
        let blocks = json!([
            {"serial": 0, "type": 0, "start_ea": f.ea_start, "end_ea": body_ea, "n_pred": 0, "n_succ": 1, "n_insns": 0},
            {"serial": 1, "type": 0, "start_ea": body_ea, "end_ea": f.ea_end, "n_pred": 2, "n_succ": 2, "n_insns": 3},
            {"serial": 2, "type": 0, "start_ea": 0, "end_ea": 0, "n_pred": 2, "n_succ": 0, "n_insns": 0},
        ]);
        // mov #0x5A, eax / add eax, ebx / jz 1  — opcode 4=mov, 12=add, 44=jz
        let mut insns = vec![
            json!({"block": 1, "opcode": 4,  "ea": body_ea,      "l_type": 2, "r_type": 0, "d_type": 1, "d_size": 4, "n_value": 0x5A, "text": "mov #0x5A, eax.4"}),
            json!({"block": 1, "opcode": 12, "ea": body_ea + 2,  "l_type": 1, "r_type": 1, "d_type": 1, "d_size": 4, "n_value": 0,    "text": "add eax.4, ebx.4"}),
            json!({"block": 1, "opcode": 44, "ea": body_ea + 4,  "l_type": 1, "r_type": 0, "d_type": 7, "d_size": 0, "n_value": 0,    "text": "jz 1"}),
        ];
        let truncated = insns.len() > max_insns;
        insns.truncate(max_insns);
        Ok(json!({
            "ea": f.ea_start,
            "function": f.name,
            "maturity": maturity,
            "qty": 3,
            "truncated": truncated,
            "blocks": blocks,
            "insns": insns,
        }))
    }

    fn snapshot_create(&mut self) -> Result<Value> {
        self.require_open()?;
        self.snapshots.push(SnapshotState {
            revision: self.revision,
            names: self.names.clone(),
            comments: self.comments.clone(),
            bytes: self.bytes.clone(),
        });
        Ok(json!({
            "snapshot": self.snapshots.len(),
            "revision": self.revision,
            "rollback": true,
        }))
    }

    fn snapshot_restore(&mut self) -> Result<Value> {
        self.require_open()?;
        match self.snapshots.pop() {
            Some(snap) => {
                let restored_from = snap.revision;
                self.revision = snap.revision;
                self.names = snap.names;
                self.comments = snap.comments;
                self.bytes = snap.bytes;
                // Rollback itself is a state change: bump so concurrent
                // planners cannot act on a stale revision view.
                let revision_after = self.bump();
                Ok(json!({
                    "restored": true,
                    "restored_to_revision": restored_from,
                    "revision_after": revision_after,
                }))
            }
            None => Ok(json!({"restored": false, "reason": "no snapshot taken"})),
        }
    }

    fn analyze_wait(&mut self) -> Result<Value> {
        self.require_open()?;
        Ok(json!({"analyzed": true, "functions": self.names.len()}))
    }

    fn run_plugin(&mut self, plugin: &str, args: Option<&str>) -> Result<Value> {
        self.require_open()?;
        // Reverse-mcp only runs plugins from the exe-relative plugins dir;
        // the mock accepts any name as if listed in that dir.
        Ok(json!({"plugin": plugin, "args": args, "ran": true}))
    }

    fn list_plugins(&self) -> Result<Value> {
        Ok(json!([
            {"name": "sample_audit", "source": "reverse-mcp plugins dir"},
        ]))
    }

    fn build_index(&self) -> Result<(rmcp_core::analysis_index::AnalysisIndex, String)> {
        let mut idx = rmcp_core::analysis_index::AnalysisIndex {
            schema_version: rmcp_core::analysis_index::INDEX_SCHEMA_VERSION,
            binary_md5: "mock-md5".into(),
            revision: self.revision,
            functions: Default::default(),
            strings: Default::default(),
        };
        for f in self.functions_vec() {
            idx.functions.insert(
                f.ea_start,
                rmcp_core::analysis_index::FunctionFacts {
                    ea_start: f.ea_start,
                    ea_end: f.ea_end,
                    name: f.name.clone(),
                    strings: self.strings_of(f.ea_start),
                    ..Default::default()
                },
            );
        }
        // Mirror the fake call graph of deep_function_info so dataflow
        // frontier expansion works over the index.
        let edges: &[(u64, u64)] = &[
            (0x401000, 0x401100),
            (0x401000, 0x401200),
            (0x401000, 0x401300),
            (0x401000, 0x401400),
        ];
        for (from, to) in edges {
            if let Some(f) = idx.functions.get_mut(from) {
                f.callees.push(*to);
            }
            if let Some(f) = idx.functions.get_mut(to) {
                f.callers.push(*from);
            }
        }
        Ok((idx, "mock-md5".into()))
    }

    fn input_md5(&self) -> Result<String> {
        Ok("mock-md5".into())
    }

    fn deep_function_info(&self, ea: u64, max_calls: usize) -> Result<Value> {
        self.require_open()?;
        let f = self
            .functions_vec()
            .into_iter()
            .find(|f| f.ea_start == ea)
            .ok_or_else(|| Error::Worker(format!("no function at {ea:#x}")))?;
        // Deterministic fake call graph: main -> helper/decrypt_packet/
        // dispatch/call_via_ptr; call_via_ptr has one indirect site.
        let known_callees: &[u64] = match ea {
            0x401000 => &[0x401100, 0x401200, 0x401300, 0x401400],
            0x401400 => &[0], // indirect only
            _ => &[],
        };
        let calls: Vec<Value> = known_callees
            .iter()
            .take(max_calls)
            .map(|&c| {
                if c == 0 {
                    json!({
                        "call_ea": format!("{ea:#x}+10"),
                        "direct": false,
                        "target_name": "(*(void (**)(void))(ptr))()",
                        "args": [],
                    })
                } else {
                    json!({
                        "call_ea": format!("{ea:#x}"),
                        "direct": true,
                        "target_ea": format!("{c:#x}"),
                        "target_name": self.names.get(&c).cloned().unwrap_or_default(),
                        "args": [],
                    })
                }
            })
            .collect();
        Ok(json!({
            "ea": format!("{ea:#x}"),
            "name": f.name,
            "prototype": {
                "known": true,
                "ret_type": "int",
                "arg_types": ["int", "int"],
            },
            "calls": calls,
            "calls_truncated": known_callees.len() > max_calls,
        }))
    }

    fn deep_apply_prototype(&mut self, ea: u64, decl: &str) -> Result<MutationOutcome> {
        self.require_open()?;
        if !self.names.contains_key(&ea) {
            return Err(Error::Worker(format!("no function at {ea:#x}")));
        }
        if decl.trim().is_empty() {
            return Err(Error::Worker("empty prototype declaration".into()));
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea, "decl": decl}),
        })
    }

    fn type_member_evidence(&self, ea: u64, limit: usize) -> Result<Value> {
        self.require_open()?;
        if !self.names.contains_key(&ea) {
            return Err(Error::Worker(format!("no function at {ea:#x}")));
        }
        // Deterministic observations shaped like the fixture struct:
        // field at +0 (4 bytes), +8 (8), +0x10 (4); one write at +8.
        let obs = [
            (0x0u64, 4u32, false),
            (0x8, 8, false),
            (0x8, 8, true),
            (0x10, 4, false),
        ];
        let members: Vec<Value> = obs
            .iter()
            .take(limit)
            .map(|(off, size, wr)| {
                json!({
                    "base_text": "obj",
                    "is_global": true,
                    "base_ea": format!("{ea:#x}"),
                    "offset": format!("{off:#x}"),
                    "access_size": size,
                    "is_write": wr,
                    "at_ea": format!("{ea:#x}"),
                })
            })
            .collect();
        Ok(json!({
            "ea": format!("{ea:#x}"),
            "members": members,
            "truncated": obs.len() > limit,
        }))
    }

    fn type_vtable_scan(&self, ea: u64, max_entries: usize) -> Result<Value> {
        self.require_open()?;
        // Deterministic fake vtable: slots point at known functions.
        let targets = [0x401100u64, 0x401200, 0x401300];
        let slots: Vec<Value> = targets
            .iter()
            .take(max_entries)
            .enumerate()
            .map(|(i, &t)| {
                json!({
                    "slot": i,
                    "target_ea": format!("{t:#x}"),
                    "is_code": true,
                    "name": self.names.get(&t).cloned().unwrap_or_default(),
                })
            })
            .collect();
        Ok(
            json!({"ea": format!("{ea:#x}"), "slots": slots, "truncated": targets.len() > max_entries}),
        )
    }

    fn type_udt_create(&mut self, name: &str, fields: &[String]) -> Result<MutationOutcome> {
        self.require_open()?;
        if name.trim().is_empty() || fields.is_empty() {
            return Err(Error::Worker("udt create needs a name and fields".into()));
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"name": name, "fields": fields}),
        })
    }

    fn type_udt_match(&self, shape: &[(u64, u64)]) -> Result<Value> {
        self.require_open()?;
        // The mock "knows" one struct shape: 0x0:4, 0x8:8, 0x10:4.
        let known = [(0x0u64, 4u64), (0x8, 8), (0x10, 4)];
        let hit = shape.len() == known.len()
            && shape
                .iter()
                .zip(known.iter())
                .all(|((o1, s1), (o2, s2))| o1 == o2 && s1 == s2);
        Ok(json!({
            "shape": shape.iter().map(|(o, s)| json!({
                "offset": format!("{o:#x}"), "size": s,
            })).collect::<Vec<_>>(),
            "match": if hit { json!("mock_shape_t") } else { json!(null) },
        }))
    }
}

impl MockBackend {
    fn strings_of(&self, _ea: u64) -> Vec<String> {
        Vec::new()
    }
}

// Minimal hex helper (avoid an external dependency for one function).
pub(crate) mod hex {
    pub fn decode(s: &str) -> std::result::Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd hex length".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_info_functions() {
        let mut b = MockBackend::new();
        assert_eq!(b.db_info().unwrap_err().code(), "worker_failure");
        b.open("fixture.i64").unwrap();
        let info = b.db_info().unwrap();
        assert_eq!(info["function_count"], 5);
        let fns = b.functions(0, 100).unwrap();
        assert_eq!(fns[0].name, "main");
        assert_eq!(fns.len(), 5);
    }

    #[test]
    fn rename_bumps_revision() {
        let mut b = MockBackend::new();
        b.open("x.i64").unwrap();
        assert_eq!(b.revision(), 0);
        let out = b.rename(0x401100, "helper_renamed").unwrap();
        assert_eq!(out.revision_after, 1);
        assert_eq!(b.function_at(0x401100).unwrap().name, "helper_renamed");
    }

    #[test]
    fn decompile_capability_gate() {
        let mut b = MockBackend::new().without_decompile();
        b.open("x.i64").unwrap();
        let err = b.decompile(0x401000).unwrap_err();
        assert_eq!(err.code(), "capability_unavailable");
    }

    #[test]
    fn double_open_rejected() {
        let mut b = MockBackend::new();
        b.open("a.i64").unwrap();
        assert!(b.open("b.i64").is_err());
    }

    #[test]
    fn graph_depth1() {
        let mut b = MockBackend::new();
        b.open("x.i64").unwrap();
        let g = b
            .graph(
                0x401000,
                &GraphParams {
                    kind: "calls".into(),
                    depth: 1,
                    max_nodes: 100,
                    max_edges: 200,
                },
            )
            .unwrap();
        assert_eq!(g["nodes"].as_array().unwrap().len(), 3); // main + helper + decrypt_packet
    }

    #[test]
    fn patch_and_get_bytes() {
        let mut b = MockBackend::new();
        b.open("x.i64").unwrap();
        b.patch_bytes(0x401000, "90 90").unwrap();
        let got = b.get_bytes(0x401000, 2).unwrap();
        assert_eq!(got["hex"], "9090");
    }
}
