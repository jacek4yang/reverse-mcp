//! Thin typed accessors over the SDK shims in `idasdk_extras.h`
//! (issue #19 capability layer). Everything here is bounded and
//! side-effect-free unless stated otherwise.

use crate::ffi;
use crate::ffi::{func, hexrays, into_ea, segment};

/// Image base of the loaded binary (`get_imagebase()`).
pub fn imagebase() -> u64 {
    unsafe { ffi::backend::idalib_get_imagebase().0 }
}

/// Map an EA to the offset in the original input file
/// (`get_fileregion_offset`). Returns `None` when the EA cannot be mapped.
pub fn file_offset_of(ea: u64) -> Option<i64> {
    let off = unsafe { ffi::backend::idalib_get_fileregion_offset(into_ea(ea)) };
    if off < 0 { None } else { Some(off) }
}

/// Map an input-file offset back to an EA (`get_fileregion_ea`).
/// Returns `None` when the offset cannot be mapped.
pub fn ea_of_file_offset(off: i64) -> Option<u64> {
    let ea = unsafe { ffi::backend::idalib_get_fileregion_ea(off) };
    if ea.0 == u64::MAX || ea.0 == 0 {
        // BADADDR or "not mapped"
        None
    } else {
        Some(ea.0)
    }
}

/// One import entry collected from `enum_import_names`.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub ea: u64,
    pub name: String,
    pub ord: u64,
}

/// Number of imported modules (`get_import_module_qty`).
pub fn import_module_qty() -> usize {
    unsafe { ffi::backend::idalib_get_import_module_qty() }
}

/// Name of imported module `idx` (`get_import_module_name`), if any.
pub fn import_module_name(idx: usize) -> Option<String> {
    let name = unsafe { ffi::backend::idalib_get_import_module_name(autocxx::c_int(idx as i32)) };
    if name.is_empty() { None } else { Some(name) }
}

/// Enumerate all imports of module `idx` (bounded by the caller).
/// Returns `(ea, name, ordinal)` triples; `ea` is the import thunk address
/// when the module has been loaded, otherwise `BADADDR`.
pub fn enum_imports(idx: usize) -> Vec<ImportEntry> {
    let mut eas = Vec::new();
    let mut names = Vec::new();
    let mut ords = Vec::new();
    unsafe {
        ffi::backend::idalib_enum_import_names(
            autocxx::c_int(idx as i32),
            &mut eas,
            &mut names,
            &mut ords,
        );
    }
    eas.into_iter()
        .zip(names)
        .zip(ords)
        .map(|((ea, name), ord)| ImportEntry { ea, name, ord })
        .collect()
}

/// One fixup/relocation record (bounded subset of `fixup_data_t`).
#[derive(Debug, Clone)]
pub struct FixupInfo {
    pub ea: u64,
    pub kind: u64,
    pub flags: u64,
    pub base: u64,
    pub sel: u64,
    pub off: u64,
    pub displacement: i64,
}

/// Enumerate all fixups in the database (bounded by `max`).
pub fn fixups(max: usize) -> Vec<FixupInfo> {
    let mut out = Vec::new();
    unsafe {
        let mut ea = ffi::backend::idalib_get_first_fixup_ea();
        while ea.0 != 0 && ea.0 != u64::MAX && out.len() < max {
            let mut fields = Vec::new();
            if ffi::backend::idalib_get_fixup(ea, &mut fields) && fields.len() >= 6 {
                out.push(FixupInfo {
                    ea: ea.0,
                    kind: fields[0],
                    flags: fields[1],
                    base: fields[2],
                    sel: fields[3],
                    off: fields[4],
                    displacement: fields[5] as u32 as i64,
                });
            }
            ea = ffi::backend::idalib_get_next_fixup_ea(ea);
        }
    }
    out
}

/// Bounded switch/jump-table information (`get_switch_info`).
#[derive(Debug, Clone)]
pub struct SwitchInfo {
    pub jump_ea: u64,
    pub flags: u64,
    pub jumps: u64,
    pub values: u64,
    pub defjump: u64,
    pub elbase: u64,
    pub ncases: u64,
    pub jcases: u64,
    pub lowcase: i64,
    pub regnum: i64,
    pub jtable_element_size: u64,
    pub vtable_element_size: u64,
    pub startea: u64,
}

/// Switch info for the indirect jump at `ea`, if any.
pub fn switch_info(ea: u64) -> Option<SwitchInfo> {
    let mut v = Vec::new();
    let found = unsafe { ffi::backend::idalib_get_switch_info(into_ea(ea), &mut v) };
    if !found || v.len() < 12 {
        return None;
    }
    Some(SwitchInfo {
        jump_ea: ea,
        flags: v[0],
        jumps: v[1],
        values: v[2],
        defjump: v[3],
        elbase: v[4],
        ncases: v[5],
        jcases: v[6],
        lowcase: v[7] as i64,
        regnum: v[8] as i64,
        jtable_element_size: v[9],
        vtable_element_size: v[10],
        startea: v[11],
    })
}

/// One function chunk (entry or tail) range.
#[derive(Debug, Clone)]
pub struct ChunkRange {
    pub start: u64,
    pub end: u64,
}

/// Number of function chunks (entry + tails) in the database.
pub fn fchunk_qty() -> usize {
    unsafe { ffi::backend::idalib_get_fchunk_qty() }
}

/// All chunks of the function containing `f` (entry chunk first).
pub fn func_chunks(f: *mut func::func_t) -> Vec<ChunkRange> {
    let mut raw = Vec::new();
    unsafe {
        ffi::backend::idalib_func_chunks(f, &mut raw);
    }
    raw.chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| ChunkRange {
            start: c[0],
            end: c[1],
        })
        .collect()
}

/// Is the function chunk at `ea` a tail chunk?
pub fn is_tail_chunk(ea: u64) -> bool {
    unsafe { ffi::backend::idalib_func_is_tail(func::get_func(into_ea(ea))) }
}

/// Create a function at `start` (end = BADADDR lets IDA determine bounds).
/// Mutation: caller must bump the revision.
pub fn add_func(start: u64) -> bool {
    unsafe { ffi::backend::idalib_add_func(into_ea(start), into_ea(u64::MAX)) }
}

/// Create a function spanning `[start, end)`. Mutation: caller must bump.
pub fn add_func_range(start: u64, end: u64) -> bool {
    unsafe { ffi::backend::idalib_add_func(into_ea(start), into_ea(end)) }
}

/// Delete the function containing `ea`. Mutation: caller must bump.
pub fn del_func(ea: u64) -> bool {
    unsafe { ffi::backend::idalib_del_func(into_ea(ea)) }
}

/// Move the start of the function containing `ea`.
/// Mutation: caller must bump. Returns the SDK MOVE_FUNC_ code.
pub fn set_func_start(ea: u64, new_start: u64) -> i32 {
    unsafe { ffi::backend::idalib_set_func_start(into_ea(ea), into_ea(new_start)).0 }
}

/// Move the end of the function containing `ea`. Mutation: caller must bump.
pub fn set_func_end(ea: u64, new_end: u64) -> bool {
    unsafe { ffi::backend::idalib_set_func_end(into_ea(ea), into_ea(new_end)) }
}

/// Cumulative SP delta at `ea` inside the function `f` (`get_sp_delta`).
pub fn sp_delta(f: *mut func::func_t, ea: u64) -> i64 {
    unsafe { ffi::backend::idalib_get_sp_delta(f, into_ea(ea)) }
}

/// Demangle a (possibly mangled) name. Returns `None` when the name is not
/// demangleable (plain C names, unknown compilers).
pub fn demangle_name(name: &str) -> Option<String> {
    let cname = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let out = unsafe { ffi::backend::idalib_demangle_name(cname.as_ptr()) };
    if out.is_empty() { None } else { Some(out) }
}

/// Canon feature bits of the instruction at `ea` (`CF_*` flags), 0 when the
/// address cannot be decoded.
pub fn insn_feature(ea: u64) -> u32 {
    unsafe { ffi::backend::idalib_get_insn_feature(into_ea(ea)) }
}

/// Mnemonic of the instruction at `ea`, empty when undecodable.
pub fn insn_mnemonic(ea: u64) -> String {
    unsafe { ffi::backend::idalib_print_insn_mnem(into_ea(ea)) }
}

/// Base (SEL) of the segment containing the address.
pub fn segment_base(ea: u64) -> Option<u64> {
    let seg = unsafe { segment::getseg(into_ea(ea)) };
    if seg.is_null() {
        return None;
    }
    Some(unsafe { ffi::backend::idalib_get_segm_base(seg) }.0)
}

// ---- hexrays caps (bounded ctree / lvar summaries) ----

/// One bounded ctree node summary. `op` is a `cot_*` code for expressions
/// and a `cit_*` code for statements; `a`/`b` are reserved (always 0) and
/// `c` carries the item-specific payload (number value, object EA, var
/// index, member offset or pointer size, depending on `op`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CtreeRow {
    pub ea: u64,
    pub op: u32,
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub is_expr: bool,
    pub text: String,
}

/// One bounded lvar summary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LvarRow {
    pub defea: u64,
    pub name: String,
    pub type_text: String,
    pub width: i64,
    pub is_arg: bool,
    pub is_result: bool,
}

/// Bounded ctree node summaries of a decompiled function
/// (`ctree_parentee_t` CV_FAST walk over `f->body`).
pub fn ctree_rows(cfunc: *mut hexrays::cfunc_t, limit: usize) -> (Vec<CtreeRow>, bool) {
    unsafe {
        let raw = ffi::ffix::idalib_ctree_walk(cfunc, limit);
        if raw.is_null() {
            return (Vec::new(), false);
        }
        let n = ffi::ffix::idalib_ctree_rows_size(raw);
        let truncated = ffi::ffix::idalib_ctree_rows_truncated(raw);
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            rows.push(CtreeRow {
                ea: ffi::ffix::idalib_ctree_row_ea(raw, i),
                op: ffi::ffix::idalib_ctree_row_op(raw, i),
                a: ffi::ffix::idalib_ctree_row_a(raw, i),
                b: ffi::ffix::idalib_ctree_row_b(raw, i),
                c: ffi::ffix::idalib_ctree_row_c(raw, i),
                is_expr: ffi::ffix::idalib_ctree_row_is_expr(raw, i),
                text: ffi::ffix::idalib_ctree_row_text(raw, i).to_string(),
            });
        }
        ffi::ffix::idalib_ctree_rows_free(raw);
        (rows, truncated)
    }
}

/// Bounded lvar summaries of a decompiled function.
pub fn lvar_rows(cfunc: *mut hexrays::cfunc_t, limit: usize) -> (Vec<LvarRow>, bool) {
    unsafe {
        let raw = ffi::ffix::idalib_lvars_walk(cfunc, limit);
        if raw.is_null() {
            return (Vec::new(), false);
        }
        let n = ffi::ffix::idalib_lvar_rows_size(raw);
        let truncated = ffi::ffix::idalib_lvar_rows_truncated(raw);
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            rows.push(LvarRow {
                defea: ffi::ffix::idalib_lvar_row_defea(raw, i),
                name: ffi::ffix::idalib_lvar_row_name(raw, i).to_string(),
                type_text: ffi::ffix::idalib_lvar_row_type_text(raw, i).to_string(),
                width: ffi::ffix::idalib_lvar_row_width(raw, i),
                is_arg: ffi::ffix::idalib_lvar_row_is_arg(raw, i),
                is_result: ffi::ffix::idalib_lvar_row_is_result(raw, i),
            });
        }
        ffi::ffix::idalib_lvar_rows_free(raw);
        (rows, truncated)
    }
}

/// Function return type as one-line text (empty when unknown).
pub fn func_return_type(cfunc: *mut hexrays::cfunc_t) -> String {
    unsafe { ffi::ffix::idalib_func_return_type(cfunc) }.to_string()
}

/// Rename one lvar identified by its definition EA (user lvar settings).
/// Mutation: caller must bump the revision.
pub fn lvar_rename(cfunc: *mut hexrays::cfunc_t, var_defea: u64, new_name: &str) -> bool {
    let cname = match std::ffi::CString::new(new_name) {
        Ok(c) => c,
        Err(_) => return false,
    };
    unsafe { ffi::ffix::idalib_lvar_rename(cfunc, var_defea, cname.as_ptr()) }
}

// ---- deep analysis (#10): call sites, prototypes, prototype apply ----

/// One call site of a decompiled function (concrete ctree evidence).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CallRow {
    pub call_ea: u64,
    pub target_ea: u64,
    pub direct: bool,
    pub target_name: String,
    pub args: Vec<String>,
}

/// Full prototype of a decompiled function: return + per-arg type texts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Prototype {
    pub ret_type: String,
    pub arg_types: Vec<String>,
    pub truncated: bool,
    pub known: bool,
}

/// Full prototype of a decompiled function (`get_func_details` walk).
pub fn func_prototype(cfunc: *mut hexrays::cfunc_t, max_args: usize) -> Prototype {
    unsafe {
        let p = ffi::ffix::idalib_func_prototype(cfunc, max_args);
        let Some(p) = p.as_ref() else {
            return Prototype {
                ret_type: String::new(),
                arg_types: Vec::new(),
                truncated: false,
                known: false,
            };
        };
        use ffi::ffix;
        let arg_types = (0..ffix::idalib_proto_arg_count(p))
            .map(|i| ffix::idalib_proto_arg_type(p, i).to_string())
            .collect();
        Prototype {
            ret_type: ffix::idalib_proto_ret_type(p).to_string(),
            arg_types,
            truncated: ffix::idalib_proto_truncated(p),
            known: ffix::idalib_proto_known(p),
        }
    }
}

/// Bounded call-site rows of a decompiled function.
pub fn call_rows(cfunc: *mut hexrays::cfunc_t, limit: usize) -> (Vec<CallRow>, bool) {
    unsafe {
        let raw = ffi::ffix::idalib_calls_walk(cfunc, limit);
        if raw.is_null() {
            return (Vec::new(), false);
        }
        let n = ffi::ffix::idalib_call_rows_size(raw);
        let truncated = ffi::ffix::idalib_call_rows_truncated(raw);
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            let argc = ffi::ffix::idalib_call_row_arg_count(raw, i);
            let args = (0..argc)
                .map(|j| ffi::ffix::idalib_call_row_arg(raw, i, j).to_string())
                .collect();
            rows.push(CallRow {
                call_ea: ffi::ffix::idalib_call_row_call_ea(raw, i),
                target_ea: ffi::ffix::idalib_call_row_target_ea(raw, i),
                direct: ffi::ffix::idalib_call_row_direct(raw, i),
                target_name: ffi::ffix::idalib_call_row_target_name(raw, i).to_string(),
                args,
            });
        }
        ffi::ffix::idalib_call_rows_free(raw);
        (rows, truncated)
    }
}

/// Apply a parsed C prototype declaration to the function at `cfunc`'s entry.
/// Mutation: caller must bump the revision.
pub fn apply_prototype(cfunc: *mut hexrays::cfunc_t, decl: &str) -> bool {
    let cdecl = match std::ffi::CString::new(decl) {
        Ok(c) => c,
        Err(_) => return false,
    };
    unsafe { ffi::ffix::idalib_apply_prototype(cfunc, cdecl.as_ptr()) }
}

/// Current prototype as one-line text (empty when the type is unknown).
pub fn prototype_text(cfunc: *mut hexrays::cfunc_t) -> String {
    unsafe { ffi::ffix::idalib_prototype_text(cfunc) }.to_string()
}

// ---- type recovery (#11): member evidence, vtables, UDT create/match ----

/// One member-access observation from a decompiled function.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberRow {
    pub base_text: String,
    pub is_global: bool,
    pub base_ea: u64,
    pub offset: u64,
    pub access_size: u32,
    pub is_write: bool,
    pub at_ea: u64,
}

/// Bounded member-access rows of a decompiled function.
pub fn member_rows(cfunc: *mut hexrays::cfunc_t, limit: usize) -> (Vec<MemberRow>, bool) {
    unsafe {
        let raw = ffi::ffix::idalib_members_walk(cfunc, limit);
        if raw.is_null() {
            return (Vec::new(), false);
        }
        let n = ffi::ffix::idalib_member_rows_size(raw);
        let truncated = ffi::ffix::idalib_member_rows_truncated(raw);
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            rows.push(MemberRow {
                base_text: ffi::ffix::idalib_member_row_base(raw, i).to_string(),
                is_global: ffi::ffix::idalib_member_row_global(raw, i),
                base_ea: ffi::ffix::idalib_member_row_base_ea(raw, i),
                offset: ffi::ffix::idalib_member_row_offset(raw, i),
                access_size: ffi::ffix::idalib_member_row_size(raw, i),
                is_write: ffi::ffix::idalib_member_row_write(raw, i),
                at_ea: ffi::ffix::idalib_member_row_at(raw, i),
            });
        }
        ffi::ffix::idalib_member_rows_free(raw);
        (rows, truncated)
    }
}

/// One vtable slot.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VtableSlot {
    pub slot: u64,
    pub target_ea: u64,
    pub is_code: bool,
    pub name: String,
}

/// Scan `max_entries` vtable slots starting at `ea` (read-only).
pub fn vtable_slots(ea: u64, max_entries: usize) -> Vec<VtableSlot> {
    unsafe {
        (0..max_entries as u64)
            .filter_map(|slot| {
                let r = ffi::ffix::idalib_vtable_scan_row(ea, slot);
                let r = r.as_ref()?;
                Some(VtableSlot {
                    slot: ffi::ffix::idalib_vtable_row_slot(r),
                    target_ea: ffi::ffix::idalib_vtable_row_target(r),
                    is_code: ffi::ffix::idalib_vtable_row_is_code(r),
                    name: ffi::ffix::idalib_vtable_row_name(r).to_string(),
                })
            })
            .collect()
    }
}

/// Create (or replace) a named struct in the local TIL. `fields` items are
/// "offset:size:name:type_decl" quadruples. Returns the new ordinal or None.
/// Mutation: caller bumps the revision.
pub fn udt_create(name: &str, fields: &[String]) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let items = std::ffi::CString::new(fields.join(", ")).ok()?;
    let ord = unsafe { ffi::ffix::idalib_udt_create(cname.as_ptr(), items.as_ptr()) };
    if ord == 0 { None } else { Some(ord) }
}

/// Find a local type whose (offset, size) field shape matches. Returns the
/// type name or None.
pub fn udt_match_shape(shape: &[(u64, u64)]) -> Option<String> {
    let spec = shape
        .iter()
        .map(|(o, s)| format!("{o}:{s}"))
        .collect::<Vec<_>>()
        .join(", ");
    let cspec = std::ffi::CString::new(spec).ok()?;
    let name = unsafe { ffi::ffix::idalib_udt_match_shape(cspec.as_ptr()) }.to_string();
    if name.is_empty() { None } else { Some(name) }
}
