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
        }
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
        let mut out = Vec::new();
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
}

// Minimal hex helper (avoid an external dependency for one function).
mod hex {
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
