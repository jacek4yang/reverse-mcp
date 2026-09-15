//! Real IDA backend backed by the vendored `idalib` crate (IDA 9.2 idalib).
//!
//! Compiled only with the `idalib` feature. All calls run on the worker's
//! main thread 鈥?idalib requires every database operation to happen on the
//! thread that initialized the library, and worker dispatch is synchronous
//! on `main`, which satisfies that constraint.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use idalib::idb::{IDB, IDBOpenOptions};
use idalib::xref::XRefQuery;

use rmcp_core::backend::{
    Capabilities, FunctionInfo, GraphParams, IdaBackend, InsnInfo, MutationOutcome, SegmentInfo,
    StringInfo, XrefInfo,
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
    /// Current snapshot file (#16); None until snapshot_create runs.
    snapshot_file: Option<PathBuf>,
    /// Monotonic snapshot counter for unique backup filenames.
    snapshot_seq: u64,
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
            snapshot_file: None,
            snapshot_seq: 0,
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

    /// Path of the database file IDA actually persists to (the input path,
    /// or the .i64 IDA created next to a raw binary input).
    fn saved_db_file(&self) -> std::result::Result<PathBuf, Error> {
        let path = self
            .path
            .as_ref()
            .ok_or_else(|| Error::Worker("no db open".into()))?;
        let p = Path::new(path);
        if p.extension().is_some_and(|e| e.eq_ignore_ascii_case("i64")) {
            Ok(p.to_path_buf())
        } else {
            let mut s = p.as_os_str().to_os_string();
            s.push(".i64");
            Ok(PathBuf::from(s))
        }
    }

    fn snapshot_path(db_file: &Path, seq: u64) -> PathBuf {
        let mut s = db_file.as_os_str().to_os_string();
        s.push(format!(".rmbak-{seq}"));
        PathBuf::from(s)
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
            patch_bytes: true,
            rename: true,
            comments: true,
            bookmarks: true,
            plugins: true,
            ctree: decompile,
            lvars: decompile,
            microcode: false, // not implemented in #19; honest
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

    fn graph(&self, ea: u64, params: &GraphParams) -> Result<Value> {
        let idb = self.idb()?;
        let root = idb
            .function_at(ea)
            .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))?;

        let mut nodes: Vec<Value> = Vec::new();
        let mut edges: Vec<Value> = Vec::new();
        let mut seen_nodes = std::collections::HashSet::new();
        let mut seen_edges = std::collections::HashSet::new();
        let mut truncated = false;

        let add_node = |ea: u64,
                        name: String,
                        nodes: &mut Vec<Value>,
                        seen: &mut std::collections::HashSet<u64>|
         -> bool {
            if seen.insert(ea) {
                if nodes.len() >= params.max_nodes {
                    return false;
                }
                nodes.push(json!({"ea": ea, "name": name}));
            }
            true
        };

        // Breadth-first traversal over `calls` edges (function-wide call
        // discovery) or `cfg` edges (basic-block flow inside the function).
        let mut frontier = vec![root.start_address()];
        add_node(
            root.start_address(),
            root.name().unwrap_or_default(),
            &mut nodes,
            &mut seen_nodes,
        );

        let mut depth = 0u32;
        while !frontier.is_empty() && depth < params.depth {
            depth += 1;
            let mut next = Vec::new();
            for f_ea in std::mem::take(&mut frontier) {
                let f = match idb.function_at(f_ea) {
                    Some(f) => f,
                    None => continue,
                };

                match params.kind.as_str() {
                    "cfg" => {
                        // Basic-block flow chart of this function.
                        let cfg = match f.cfg() {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        let mut id_by_start: std::collections::HashMap<u64, ()> =
                            std::collections::HashMap::new();
                        let blocks: Vec<_> = cfg.blocks().collect();
                        for b in &blocks {
                            if nodes.len() >= params.max_nodes {
                                truncated = true;
                                break;
                            }
                            if add_node(
                                b.start_address(),
                                format!("bb_{:x}", b.start_address()),
                                &mut nodes,
                                &mut seen_nodes,
                            ) {
                                id_by_start.insert(b.start_address(), ());
                            }
                        }
                        // CFG edges: fall through / branch to next block in
                        // order; use succs() where the block exposes them.
                        for b in &blocks {
                            if edges.len() >= params.max_edges {
                                truncated = true;
                                break;
                            }
                            let from = b.start_address();
                            let succs: Vec<u64> = b
                                .succs()
                                .filter_map(|id| blocks.get(id).map(|s| s.start_address()))
                                .collect();
                            if succs.is_empty() {
                                // fallthrough to next block if any
                                if let Some(next_b) =
                                    blocks.iter().find(|n| n.start_address() >= b.end_address())
                                {
                                    let to = next_b.start_address();
                                    if seen_edges.insert((from, to)) {
                                        edges.push(json!({"from": from, "to": to}));
                                    }
                                }
                            } else {
                                for to in succs {
                                    if seen_edges.insert((from, to)) {
                                        edges.push(json!({"from": from, "to": to}));
                                    }
                                }
                            }
                        }
                        let _ = &id_by_start;
                    }
                    _ => {
                        // calls: walk every instruction in the function's
                        // range, collecting call/jump targets (function-wide
                        // call discovery, not just xrefs from entry).
                        let mut callees: Vec<u64> = Vec::new();
                        let mut cur = f.start_address();
                        while cur < f.end_address() {
                            let Some(insn) = idb.insn_at(cur) else { break };
                            if insn.is_call() {
                                for i in 0..insn.operand_count() {
                                    if let Some(target) = insn.operand(i).and_then(|op| op.addr()) {
                                        callees.push(target);
                                    }
                                }
                                // also code xrefs from the call site
                                if let Some(x) = idb.first_xref_from(cur, XRefQuery::ALL) {
                                    let mut x = Some(x);
                                    while let Some(xr) = x {
                                        if xr.is_code() {
                                            callees.push(xr.to());
                                        }
                                        x = xr.next_from();
                                    }
                                }
                            }
                            cur += insn.len() as u64;
                        }

                        for to in callees {
                            if edges.len() >= params.max_edges {
                                truncated = true;
                                break;
                            }
                            // resolve callee to containing function
                            let callee = idb.function_at(to);
                            let (callee_ea, callee_name) = match &callee {
                                Some(c) => (c.start_address(), c.name().unwrap_or_default()),
                                None => (to, String::new()),
                            };
                            if !seen_edges.insert((f_ea, callee_ea)) {
                                continue;
                            }
                            if nodes.len() >= params.max_nodes {
                                truncated = true;
                                break;
                            }
                            add_node(callee_ea, callee_name, &mut nodes, &mut seen_nodes);
                            edges.push(json!({"from": f_ea, "to": callee_ea, "callsite": to}));
                            if depth < params.depth {
                                next.push(callee_ea);
                            }
                        }
                    }
                }
                if edges.len() >= params.max_edges || nodes.len() >= params.max_nodes {
                    truncated = true;
                    break;
                }
            }
            if truncated {
                break;
            }
            frontier = next;
        }

        let mut out = json!({
            "kind": params.kind,
            "root": root.start_address(),
            "nodes": nodes,
            "edges": edges,
        });
        if truncated {
            out["truncated"] = json!(true);
        }
        Ok(out)
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

    fn patch_bytes(&mut self, ea: u64, bytes_hex: &str) -> Result<MutationOutcome> {
        let idb = self.idb()?;
        let _ = idb;
        let decoded = crate::mock::hex::decode(bytes_hex.trim().replace(' ', "").as_str())
            .map_err(|e| Error::Worker(format!("bad hex: {e}")))?;
        if decoded.is_empty() {
            return Err(Error::Worker("empty patch".into()));
        }
        let bytes: Vec<u8> = decoded;
        // Record original bytes for the audit trail (before/after diff).
        let original: Vec<u8> = bytes
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let v =
                    unsafe { idalib::ffi::bytes::idalib_get_original_byte(into_ea(ea + i as u64)) };
                (v.0 & 0xFF) as u8
            })
            .collect();
        let ok = unsafe { idalib::ffi::bytes::idalib_patch_bytes(into_ea(ea), &bytes) };
        if !ok {
            return Err(Error::Worker(format!("patch failed at {ea:#x}")));
        }
        let revision_after = self.bump();
        let old_hex: String = original.iter().map(|x| format!("{x:02x}")).collect();
        let new_hex: String = bytes.iter().map(|x| format!("{x:02x}")).collect();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({
                "ea": format!("{ea:#x}"),
                "size": bytes.len(),
                "original": old_hex,
                "patched": new_hex,
            }),
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
            let ok = unsafe { idalib::ffi::backend::idalib_set_name(into_ea(ea), cname.as_ptr()) };
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

    // ---- #19: database / binary metadata ----

    fn db_metadata(&self) -> Result<Value> {
        let idb = self.idb()?;
        let meta = idb.meta();
        // retrieve_input_file_md5/sha256 write into caller buffers and
        // return false when the hash is unavailable.
        let hash_hex = |ok: bool, buf: &mut [u8]| -> Option<String> {
            if ok {
                Some(buf.iter().map(|b| format!("{b:02x}")).collect())
            } else {
                None
            }
        };
        let mut md5buf = [0u8; 16];
        let md5 = unsafe {
            let ok = idalib::ffi::nalt::retrieve_input_file_md5(md5buf.as_mut_ptr());
            hash_hex(ok, &mut md5buf)
        };
        let mut shabuf = [0u8; 32];
        let sha256 = unsafe {
            let ok = idalib::ffi::nalt::retrieve_input_file_sha256(shabuf.as_mut_ptr());
            hash_hex(ok, &mut shabuf)
        };
        let entries: Vec<Value> = idb
            .entries()
            .map(|(ordinal, ea, name)| json!({"ordinal": ordinal, "ea": ea, "name": name}))
            .collect();
        Ok(json!({
            "md5": md5,
            "sha256": sha256,
            "imagebase": idalib::caps::imagebase(),
            "entry_count": entries.len(),
            "entries": entries,
            "tls_callbacks": Value::Null,
            "tls_callbacks_supported": false,
            "exception_handlers_supported": false,
            "processor": meta.procname(),
            "bits": if meta.is_64bit() { 64 } else if meta.is_32bit_exactly() { 32 } else { 16 },
        }))
    }

    fn imports(&self, module: Option<usize>, offset: usize, limit: usize) -> Result<Value> {
        let _ = self.idb()?;
        let qty = idalib::caps::import_module_qty();
        let mut modules = Vec::new();
        for idx in 0..qty {
            if module.is_some_and(|want| idx != want) {
                continue;
            }
            let name = idalib::caps::import_module_name(idx).unwrap_or_default();
            let entries = idalib::caps::enum_imports(idx)
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|e| json!({"ea": e.ea, "name": e.name, "ordinal": e.ord}))
                .collect::<Vec<_>>();
            modules.push(json!({"index": idx, "name": name, "entries": entries}));
        }
        Ok(json!({"modules": modules, "module_count": qty}))
    }

    fn fixups(&self, offset: usize, limit: usize) -> Result<Value> {
        let _ = self.idb()?;
        let all = idalib::caps::fixups(offset.saturating_add(limit));
        let total = all.len();
        let page: Vec<Value> = all
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|f| {
                json!({
                    "ea": f.ea,
                    "kind": f.kind,
                    "flags": f.flags,
                    "base": f.base,
                    "sel": f.sel,
                    "off": f.off,
                    "displacement": f.displacement,
                })
            })
            .collect();
        Ok(json!({"total": total, "fixups": page}))
    }

    fn file_map(&self, value: u64, to_ea: bool) -> Result<Value> {
        let _ = self.idb()?;
        if to_ea {
            match idalib::caps::ea_of_file_offset(value as i64) {
                Some(ea) => Ok(json!({"file_offset": value, "ea": ea})),
                None => Err(Error::Worker(format!(
                    "file offset {value:#x} does not map to an address"
                ))),
            }
        } else {
            match idalib::caps::file_offset_of(value) {
                Some(off) => Ok(json!({"ea": value, "file_offset": off})),
                None => Err(Error::Worker(format!(
                    "address {value:#x} does not map into the input file"
                ))),
            }
        }
    }

    // ---- #19: functions / control flow ----

    fn func_tails(&self, ea: u64) -> Result<Value> {
        let idb = self.idb()?;
        let f = idb
            .function_at(ea)
            .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))?;
        let fptr = function_ptr(idb, f.start_address())?;
        let chunks = idalib::caps::func_chunks(fptr);
        let rows: Vec<Value> = chunks
            .iter()
            .map(|c| json!({"start": c.start, "end": c.end, "size": c.end - c.start}))
            .collect();
        Ok(json!({
            "function": f.start_address(),
            "chunks": rows,
            "is_tail_target": idalib::caps::is_tail_chunk(ea),
        }))
    }

    fn func_create(&mut self, start: u64, end: Option<u64>) -> Result<MutationOutcome> {
        let _ = self.idb()?;
        let ok = match end {
            Some(e) => idalib::caps::add_func_range(start, e),
            None => idalib::caps::add_func(start),
        };
        if !ok {
            return Err(Error::Worker(format!(
                "function creation failed at {start:#x}"
            )));
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"start": start, "end": end}),
        })
    }

    fn func_delete(&mut self, ea: u64) -> Result<MutationOutcome> {
        let _ = self.idb()?;
        let ok = idalib::caps::del_func(ea);
        if !ok {
            return Err(Error::Worker(format!(
                "function deletion failed at {ea:#x}"
            )));
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
        let _ = self.idb()?;
        let mut detail = json!({"ea": ea});
        let mut changed = false;
        if let Some(ns) = new_start {
            let code = idalib::caps::set_func_start(ea, ns);
            detail["start_move_code"] = json!(code);
            changed = true;
        }
        if let Some(ne) = new_end {
            if !idalib::caps::set_func_end(ea, ne) {
                return Err(Error::Worker(format!(
                    "set_func_end failed at {ea:#x} -> {ne:#x}"
                )));
            }
            detail["end"] = json!(ne);
            changed = true;
        }
        if !changed {
            return Err(Error::Worker(
                "func_resize requires new_start and/or new_end".into(),
            ));
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail,
        })
    }

    fn func_switch_info(&self, ea: u64) -> Result<Value> {
        let _ = self.idb()?;
        match idalib::caps::switch_info(ea) {
            Some(s) => Ok(json!({
                "ea": s.jump_ea,
                "flags": s.flags,
                "jump_table": s.jumps,
                "value_table": s.values,
                "default_jump": s.defjump,
                "elbase": s.elbase,
                "ncases": s.ncases,
                "jcases": s.jcases,
                "lowcase": s.lowcase,
                "regnum": s.regnum,
                "jtable_element_size": s.jtable_element_size,
                "vtable_element_size": s.vtable_element_size,
                "start_ea": s.startea,
            })),
            None => Err(Error::Worker(format!("no switch information at {ea:#x}"))),
        }
    }

    fn func_sp_delta(&self, ea: u64) -> Result<Value> {
        let idb = self.idb()?;
        let f = idb
            .function_at(ea)
            .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))?;
        let fptr = function_ptr(idb, f.start_address())?;
        Ok(json!({
            "ea": ea,
            "sp_delta": idalib::caps::sp_delta(fptr, ea),
        }))
    }

    // ---- #19: Hex-Rays ----

    fn hr_cfunc(
        &self,
        ea: u64,
        include_ctree: bool,
        include_lvars: bool,
        limit: usize,
    ) -> Result<Value> {
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
        let cfptr = cf.inner_ptr();

        let out = json!({
            "function": f.name().unwrap_or_default(),
            "ea": f.start_address(),
            "return_type": idalib::caps::func_return_type(cfptr),
        });
        let mut out = out;
        if include_ctree {
            let (rows, truncated) = idalib::caps::ctree_rows(cfptr, limit);
            out["ctree"] = json!(rows);
            out["ctree_truncated"] = json!(truncated);
        }
        if include_lvars {
            let (rows, truncated) = idalib::caps::lvar_rows(cfptr, limit);
            out["lvars"] = json!(rows);
            out["lvars_truncated"] = json!(truncated);
        }
        Ok(out)
    }

    fn hr_lvar_rename(
        &mut self,
        ea: u64,
        var_defea: u64,
        new_name: &str,
    ) -> Result<MutationOutcome> {
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
        let func_ea = f.start_address();
        let func_name = f.name().unwrap_or_default();
        let cf = idb.decompile(&f).map_err(err)?;
        let ok = idalib::caps::lvar_rename(cf.inner_ptr(), var_defea, new_name);
        if !ok {
            return Err(Error::Worker(format!(
                "lvar rename failed: no lvar defined at {var_defea:#x}"
            )));
        }
        let revision_after = self.bump();
        Ok(MutationOutcome {
            changed: true,
            revision_after,
            detail: json!({"function": func_ea, "name": func_name, "var_defea": var_defea, "new": new_name}),
        })
    }

    // ---- #19: instructions / names ----

    fn insn_features(&self, ea: u64) -> Result<Value> {
        let _ = self.idb()?;
        Ok(json!({
            "ea": ea,
            "features": idalib::caps::insn_feature(ea),
            "mnemonic": idalib::caps::insn_mnemonic(ea),
        }))
    }

    fn demangle_name(&self, name: &str) -> Result<Value> {
        let _ = self.idb()?;
        match idalib::caps::demangle_name(name) {
            Some(demangled) => Ok(json!({
                "name": name,
                "demangled": demangled,
                "changed": true,
            })),
            None => Ok(json!({
                "name": name,
                "demangled": name,
                "changed": false,
            })),
        }
    }

    fn analyze_wait(&mut self) -> Result<Value> {
        if let Some(idb) = self.idb.as_mut() {
            idb.auto_wait();
            return Ok(json!({"analyzed": true, "functions": idb.function_count()}));
        }
        Err(Error::Worker("no db open".into()))
    }

    fn snapshot_create(&mut self) -> Result<Value> {
        // IDA's create_undo_point/perform_undo proved unreliable for our
        // use in idalib sessions (perform_undo can silently no-op). A
        // file-level snapshot is deterministic: save the IDB, copy the
        // database file aside, and roll back by restoring the copy.
        self.save()?;
        let db_file = self.saved_db_file()?;
        let backup = Self::snapshot_path(&db_file, self.snapshot_seq + 1);
        std::fs::copy(&db_file, &backup)
            .map_err(|e| Error::Worker(format!("snapshot copy failed: {e}")))?;
        self.snapshot_seq += 1;
        self.snapshot_file = Some(backup);
        let revision_after = self.bump();
        Ok(json!({
            "snapshot": true,
            "revision_after": revision_after,
            "rollback": true,
        }))
    }

    fn snapshot_restore(&mut self) -> Result<Value> {
        let backup = match &self.snapshot_file {
            Some(p) => p.clone(),
            None => {
                return Ok(json!({
                    "restored": false,
                    "reason": "no snapshot taken",
                    "rollback": false,
                }));
            }
        };
        let db_file = self.saved_db_file()?;
        // Drop the IDB WITHOUT saving: pending changes are discarded.
        if let Some(idb) = self.idb.as_mut() {
            idb.save_on_close(false);
        }
        self.idb = None;
        std::fs::copy(&backup, &db_file)
            .map_err(|e| Error::Worker(format!("snapshot restore failed: {e}")))?;
        // Reopen the rolled-back database.
        let path = self
            .path
            .clone()
            .ok_or_else(|| Error::Worker("no db open".into()))?;
        let mut opts = IDBOpenOptions::new();
        opts.save(true).auto_analyse(false);
        let mut idb = opts.open(Path::new(&path)).map_err(err)?;
        idb.auto_wait();
        self.idb = Some(idb);
        let revision_after = self.bump();
        Ok(json!({
            "restored": true,
            "file": backup.display().to_string(),
            "revision_after": revision_after,
            "rollback": true,
        }))
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

/// Raw `func_t*` for the function starting at `ea` (for cap shims that the
/// safe `Function` wrapper does not cover).
fn function_ptr(idb: &IDB, ea: u64) -> Result<*mut idalib::ffi::func::func_t> {
    let f = idb
        .function_at(ea)
        .ok_or_else(|| Error::Worker(format!("no function containing {ea:#x}")))?;
    Ok(f.raw_ptr())
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
