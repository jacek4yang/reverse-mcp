//! Real IDA backend backed by the vendored `idalib` crate (IDA 9.2 idalib).
//!
//! Compiled only with the `idalib` feature. All calls run on the worker's
//! main thread — idalib requires every database operation to happen on the
//! thread that initialized the library, and worker dispatch is synchronous
//! on `main`, which satisfies that constraint.

use std::path::Path;

use serde_json::{Value, json};

use idalib::idb::{IDB, IDBOpenOptions};
use idalib::xref::XRefQuery;

use rmcp_core::backend::{
    Capabilities, FunctionInfo, IdaBackend, InsnInfo, MutationOutcome, SegmentInfo, StringInfo,
    XrefInfo,
};
use rmcp_core::error::{Error, Result};

// autocxx-generated externs take `c_ulonglong`, not plain u64.
fn into_ea(v: u64) -> autocxx::c_ulonglong {
    autocxx::c_ulonglong(v)
}

pub struct IdaLibBackend {
    idb: Option<IDB>,
    path: Option<String>,
    revision: u64,
}

// SAFETY: idalib requires all database operations to run on the thread that
// initialized the library. The worker dispatches requests synchronously on its
// main thread and `IdaLibBackend` is only ever constructed there, so the
// `Send` bound on `IdaBackend` (satisfied by the broker's box) never results
// in the value actually moving to another thread.
unsafe impl Send for IdaLibBackend {}

impl IdaLibBackend {
    pub fn new() -> Self {
        Self {
            idb: None,
            path: None,
            revision: 0,
        }
    }

    fn idb(&self) -> std::result::Result<&IDB, Error> {
        self.idb
            .as_ref()
            .ok_or_else(|| Error::Worker("no db open".into()))
    }

    fn bump(&mut self) -> u64 {
        self.revision += 1;
        self.revision
    }
}

impl Default for IdaLibBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn err(e: impl std::fmt::Display) -> Error {
    Error::Worker(format!("idalib: {e}"))
}

fn perms_string(perms: idalib::segment::SegmentPermissions) -> String {
    let mut s = String::with_capacity(3);
    s.push(if perms.is_readable() { 'r' } else { '-' });
    s.push(if perms.is_writable() { 'w' } else { '-' });
    s.push(if perms.is_executable() { 'x' } else { '-' });
    s
}

impl IdaBackend for IdaLibBackend {
    fn open(&mut self, path: &str) -> Result<Value> {
        if self.idb.is_some() {
            return Err(Error::Worker("a db is already open".into()));
        }
        // save=true so `close` persists; we also call save() explicitly.
        let mut opts = IDBOpenOptions::new();
        opts.save(true).auto_analyse(true);
        let mut idb = opts.open(Path::new(path)).map_err(err)?;
        idb.auto_wait();
        self.path = Some(path.to_string());
        self.idb = Some(idb);
        let info = self.db_info()?;
        Ok(info)
    }

    fn close(&mut self) -> Result<()> {
        // Dropping IDB closes the database (saving, as opened with save=true).
        self.idb = None;
        self.path = None;
        Ok(())
    }

    fn save(&mut self) -> Result<()> {
        self.idb()?;
        let ok = unsafe { idalib::ffi::backend::idalib_save_database() };
        if ok {
            Ok(())
        } else {
            Err(Error::Worker("idalib: save_database failed".into()))
        }
    }

    fn db_info(&self) -> Result<Value> {
        let idb = self.idb()?;
        let meta = idb.meta();
        Ok(json!({
            "path": self.path,
            "processor": meta.procname(),
            "bits": if meta.is_64bit() { 64 } else if meta.is_32bit_exactly() { 32 } else { 16 },
            "min_ea": meta.min_address(),
            "max_ea": meta.max_address(),
            "function_count": idb.function_count(),
            "segment_count": idb.segment_count(),
            "decompiler": idb.decompiler_available(),
            "revision": self.revision,
        }))
    }

    fn capabilities(&self) -> Capabilities {
        let decompile = self
            .idb
            .as_ref()
            .map(|d| d.decompiler_available())
            .unwrap_or(false);
        Capabilities {
            decompile,
            types: false,
            imports_exports: true,
            patch_bytes: false,
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
        let idb = self.idb()?;
        let out = idb
            .functions()
            .skip(offset)
            .take(limit)
            .map(|(_, f)| {
                let start = f.start_address();
                let end = f.end_address();
                FunctionInfo {
                    ea_start: start,
                    ea_end: end,
                    name: f.name().unwrap_or_default(),
                    size: end.saturating_sub(start),
                }
            })
            .collect();
        Ok(out)
    }

    fn function_at(&self, ea: u64) -> Result<FunctionInfo> {
        let idb = self.idb()?;
        let f = idb
            .function_at(ea)
            .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))?;
        let start = f.start_address();
        let end = f.end_address();
        Ok(FunctionInfo {
            ea_start: start,
            ea_end: end,
            name: f.name().unwrap_or_default(),
            size: end.saturating_sub(start),
        })
    }

    fn segments(&self) -> Result<Vec<SegmentInfo>> {
        let idb = self.idb()?;
        let out = idb
            .segments()
            .map(|(_, s)| SegmentInfo {
                name: s.name().unwrap_or_default(),
                start: s.start_address(),
                end: s.end_address(),
                perms: perms_string(s.permissions()),
            })
            .collect();
        Ok(out)
    }

    fn strings(&self, offset: usize, limit: usize) -> Result<Vec<StringInfo>> {
        let idb = self.idb()?;
        let list = idb.strings();
        let out = list
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(ea, value)| {
                let length = value.len();
                StringInfo { ea, value, length }
            })
            .collect();
        Ok(out)
    }

    fn xrefs_to(&self, ea: u64) -> Result<Vec<XrefInfo>> {
        let idb = self.idb()?;
        let mut out = Vec::new();
        if let Some(first) = idb.first_xref_to(ea, XRefQuery::ALL) {
            let mut cur = Some(first);
            while let Some(x) = cur {
                out.push(XrefInfo {
                    from: x.from(),
                    to: x.to(),
                    kind: xref_kind(&x),
                });
                cur = x.next_to();
            }
        }
        Ok(out)
    }

    fn xrefs_from(&self, ea: u64) -> Result<Vec<XrefInfo>> {
        let idb = self.idb()?;
        let mut out = Vec::new();
        if let Some(first) = idb.first_xref_from(ea, XRefQuery::ALL) {
            let mut cur = Some(first);
            while let Some(x) = cur {
                out.push(XrefInfo {
                    from: x.from(),
                    to: x.to(),
                    kind: xref_kind(&x),
                });
                cur = x.next_from();
            }
        }
        Ok(out)
    }

    fn disassemble(
        &self,
        ea_start: u64,
        ea_end: Option<u64>,
        max_insns: usize,
    ) -> Result<Vec<InsnInfo>> {
        let idb = self.idb()?;
        let max_ea = ea_end.unwrap_or(u64::MAX);
        let mut out = Vec::new();
        let mut ea = ea_start;
        while ea < max_ea && out.len() < max_insns {
            let Some(insn) = idb.insn_at(ea) else { break };
            let text = unsafe { idalib::ffi::backend::idalib_disasm_line(into_ea(ea)) };
            let operands = (0..insn.operand_count())
                .map(|i| operand_text(&insn, i))
                .collect::<Vec<_>>()
                .join(", ");
            out.push(InsnInfo {
                ea,
                mnemonic: mnemonic_of(&text),
                operands,
                text,
            });
            ea += insn.len() as u64;
        }
        Ok(out)
    }

    fn decompile(&self, ea: u64) -> Result<Value> {
        let idb = self.idb()?;
        if !idb.decompiler_available() {
            return Err(Error::CapabilityUnavailable {
                capability: "decompile".into(),
                reason: "hexrays decompiler not available".into(),
            });
        }
        let f = idb
            .function_at(ea)
            .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))?;
        let cf = idb.decompile(&f).map_err(err)?;
        let name = f.name().unwrap_or_default();
        Ok(json!({
            "function": name,
            "ea": f.start_address(),
            "pseudocode": cf.pseudocode(),
        }))
    }

    fn graph(&self, ea: u64, depth: u32) -> Result<Value> {
        let idb = self.idb()?;
        let f = idb
            .function_at(ea)
            .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))?;
        let start = f.start_address();
        let name = f.name().unwrap_or_default();
        let mut nodes = vec![json!({"ea": start, "name": name})];
        let mut edges = Vec::new();
        if depth >= 1 {
            let callees: Vec<u64> = self
                .xrefs_from(start)?
                .into_iter()
                .map(|x| x.to)
                .collect();
            for to in callees {
                if let Ok(callee) = self.function_at(to) {
                    nodes.push(json!({"ea": callee.ea_start, "name": callee.name}));
                    edges.push(json!({"from": start, "to": callee.ea_start}));
                }
            }
        }
        Ok(json!({"root": start, "nodes": nodes, "edges": edges}))
    }

    fn search_text(&self, needle: &str, limit: usize) -> Result<Vec<Value>> {
        let idb = self.idb()?;
        let mut out = Vec::new();
        for (ea, text) in idb.strings().iter() {
            if text.contains(needle) {
                out.push(json!({"ea": ea, "text": text}));
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    fn search_immediate(&self, value: u64, limit: usize) -> Result<Vec<Value>> {
        let idb = self.idb()?;
        let mut out = Vec::new();
        // find_imm operates on 32-bit immediates.
        if value <= u32::MAX as u64 {
            for ea in idb.find_imm_iter(value as u32) {
                out.push(json!({"ea": ea, "context": "immediate"}));
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    fn get_bytes(&self, ea: u64, size: usize) -> Result<Value> {
        let idb = self.idb()?;
        let b = idb.get_bytes(ea, size);
        let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
        Ok(json!({"ea": ea, "size": b.len(), "hex": hex}))
    }

    fn patch_bytes(&mut self, _ea: u64, _bytes_hex: &str) -> Result<MutationOutcome> {
        Err(Error::CapabilityUnavailable {
            capability: "patch_bytes".into(),
            reason: "byte patching not exposed via idalib bridge yet".into(),
        })
    }

    fn get_comment(&self, ea: u64, repeatable: bool) -> Result<Value> {
        let idb = self.idb()?;
        let comment = if repeatable {
            idb.get_cmt_with(ea, true)
        } else {
            idb.get_cmt(ea)
        }
        .unwrap_or_default();
        Ok(json!({"ea": ea, "repeatable": repeatable, "comment": comment}))
    }

    fn set_comment(&mut self, ea: u64, comment: &str, repeatable: bool) -> Result<MutationOutcome> {
        {
            let idb = self.idb()?;
            idb.set_cmt_with(ea, comment, repeatable).map_err(err)?;
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea}),
        })
    }

    fn rename(&mut self, ea: u64, new_name: &str) -> Result<MutationOutcome> {
        {
            let _ = self.idb()?;
            let cname = std::ffi::CString::new(new_name)
                .map_err(|e| Error::Worker(format!("bad name: {e}")))?;
            let ok =
                unsafe { idalib::ffi::backend::idalib_set_name(into_ea(ea), cname.as_ptr()) };
            if !ok {
                return Err(Error::Worker(format!(
                    "rename failed at {ea:#x} (name invalid or in use)"
                )));
            }
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"ea": ea, "new": new_name}),
        })
    }

    fn types(&self, _name: Option<&str>) -> Result<Value> {
        let _ = self.idb()?;
        Err(Error::CapabilityUnavailable {
            capability: "types".into(),
            reason: "local type listing not exposed via idalib bridge yet".into(),
        })
    }

    fn set_type(&mut self, _ea: u64, _type_decl: &str) -> Result<MutationOutcome> {
        let _ = self.idb()?;
        Err(Error::CapabilityUnavailable {
            capability: "types".into(),
            reason: "type application not exposed via idalib bridge yet".into(),
        })
    }

    fn analyze_wait(&mut self) -> Result<Value> {
        if let Some(idb) = self.idb.as_mut() {
            idb.auto_wait();
            return Ok(json!({"analyzed": true, "functions": idb.function_count()}));
        }
        Err(Error::Worker("no db open".into()))
    }

    fn run_plugin(&mut self, plugin: &str, args: Option<&str>) -> Result<Value> {
        let idb = self.idb()?;
        let p = idb.load_plugin(plugin).map_err(err)?;
        let arg: usize = args.and_then(|a| a.parse().ok()).unwrap_or(0);
        let ran = p.run(arg);
        Ok(json!({"plugin": plugin, "args": args, "ran": ran}))
    }

    fn list_plugins(&self) -> Result<Value> {
        // idalib has no plugin enumeration API; report the portable plugins
        // directory configured via IDAUSR instead of guessing contents.
        let dir = std::env::var("IDAUSR").unwrap_or_default();
        Ok(json!({"plugins_dir": dir, "note": "enumerate via filesystem"}))
    }
}

fn xref_kind(x: &idalib::xref::XRef<'_>) -> String {
    use idalib::xref::{CodeRef, XRefType};
    match x.type_() {
        XRefType::Code(cr) => match cr {
            CodeRef::FarCall | CodeRef::NearCall => "call",
            CodeRef::FarJump | CodeRef::NearJump => "jump",
            CodeRef::Flow => "flow",
            _ => "code",
        }
        .to_string(),
        XRefType::Data(_) => "data".to_string(),
    }
}

fn mnemonic_of(text: &str) -> String {
    text.split_whitespace().next().unwrap_or("").to_string()
}

fn operand_text(insn: &idalib::insn::Insn, i: usize) -> String {
    // Operand rendering comes through the full disassembly line; per-operand
    // text is derived from the raw flag/union fields which is not reliable
    // enough, so report the operand type.
    match insn.operand(i) {
        Some(op) => format!("{:?}", op.type_()),
        None => String::new(),
    }
}
