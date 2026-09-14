//! Hand-written `#[repr(C)]` definitions for the IDA 9.2 SDK types that
//! bindgen/autocxx render opaque (forward declaration encountered before the
//! definition breaks codegen). Layouts were extracted from the real
//! `idalib-sys 0.7.2+9.2.250908` SDK headers with clang
//! `-fdump-record-layouts` and verified with static asserts below.
//!
//! Types used only through pointers are modelled as opaque byte blobs with
//! the correct size/alignment; types the safe layer accesses by field are
//! fully declared.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]
#![allow(dead_code)]

/// effective address (`ea_t`, `__EA64__` build)
pub type ea_t = u64;
/// `sval_t`
pub type sval_t = i64;
/// `uval_t`
pub type uval_t = u64;
/// `flags64_t`
pub type flags64_t = u64;
/// `asize_t`
pub type asize_t = u64;
/// `typid_t`
pub type typid_t = u64;

/// `qvector<T>` shape (array, n, alloc) - the only members ever accessed.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct qvector<T> {
    pub array: *mut T,
    pub n: usize,
    pub alloc: usize,
}

// Statement/detail types referenced through pointers only.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cif_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cfor_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cwhile_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cdo_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct creturn_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cgoto_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct casm_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cnumber_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fnumber_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mba_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct carglist_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct var_ref_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct user_labels_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct user_cmts_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct user_numforms_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct user_iflags_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct user_unions_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct eamap_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct boundaries_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct simpleline_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cthrow_t {
    pub expr: cexpr_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ccase_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ccatch_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct rrel_t {
    _opaque: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct scattered_aloc_t {
    _opaque: [u8; 0],
}

pub type biggest_t = u64;

/// `range_t` - fully mirrored (size 16, align 8).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct range_t {
    pub start_ea: ea_t,
    pub end_ea: ea_t,
}

impl range_t {
    pub fn contains(&self, ea: u64) -> bool {
        self.start_ea <= ea && self.end_ea > ea
    }
    pub fn size(&self) -> u64 {
        self.end_ea - self.start_ea
    }
}
/// op_t - fully mirrored (size 40, align 8), matching IDA 9.2 SDK `ua.hpp`.
/// The SDK has four anonymous unions; we flatten them (the Rust accessor layer
/// in vendor/idalib/src/insn.rs interprets the fields per operand type).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct op_t {
    pub n: u8,
    pub type_: u8,
    pub offb: i8,
    pub offo: i8,
    pub flags: u8,
    pub dtype: u8,
    /// union { uint16 reg; uint16 phrase; } (aliased, same size)
    pub reg: u16,
    /// union { uval_t value; struct { uint16 low; uint16 high; } value_shorts; }
    pub value: ea_t,
    /// union { ea_t addr; struct { uint16 low; uint16 high; } addr_shorts; }
    pub addr: ea_t,
    /// union { ea_t specval; struct { uint16 low; uint16 high; } specval_shorts; }
    pub specval: ea_t,
    pub specflag1: i8,
    pub specflag2: i8,
    pub specflag3: i8,
    pub specflag4: i8,
}
/// `insn_t` - fully mirrored (size 360, align 8).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct insn_t {
    pub cs: ea_t,
    pub ip: ea_t,
    pub ea: ea_t,
    pub itype: u16,
    pub size: u16,
    pub auxpref: u32,
    pub segpref: i8,
    pub insnpref: i8,
    pub flags: i16,
    pub ops: [op_t; 8],
}

/// `argloc_t` - full layout (size 16): discriminant + union.
#[repr(C)]
#[derive(Copy, Clone)]
pub union argloc_union {
    pub sval: sval_t,
    pub reginfo: u32,
    pub rrel: *mut rrel_t,
    pub dist: *mut scattered_aloc_t,
    pub custom: *mut core::ffi::c_void,
    pub biggest: biggest_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct argloc_t {
    pub atype: u32,
    pub _pad: u32,
    pub u: argloc_union,
}

/// `tinfo_t` - single typid (size 8).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tinfo_t {
    pub typid: typid_t,
}

/// `vdloc_t` = argloc_t (same layout, size 16).
pub type vdloc_t = argloc_t;

/// `lvar_locator_t` - size 24.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lvar_locator_t {
    pub location: vdloc_t,
    pub defea: ea_t,
}

/// `_qstring<char>` = `qvector<char>` - size 24.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct qstring {
    pub array: *mut u8,
    pub n: usize,
    pub alloc: usize,
}

/// `lvar_t` - full layout (size 104).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct lvar_t {
    pub location: vdloc_t,
    pub defea: ea_t,
    pub flags: i32,
    pub _pad0: u32,
    pub name: qstring,
    pub cmt: qstring,
    pub tif: tinfo_t,
    pub width: i32,
    pub defblk: i32,
    pub divisor: u64,
}

/// `citem_t` - base of the ctree nodes (size 24).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct citem_t {
    pub ea: ea_t,
    pub op: u8,
    pub label_num: i32,
    pub index: i32,
    pub _pad1: i32,
}

/// `cinsn_t` - citem_t + union of statement pointers (size 32).
#[repr(C)]
#[derive(Copy, Clone)]
pub union cinsn_u {
    pub cblock: *mut cblock_t,
    pub cexpr: *mut cexpr_t,
    pub cif: *mut cif_t,
    pub cfor: *mut cfor_t,
    pub cwhile: *mut cwhile_t,
    pub cdo: *mut cdo_t,
    pub cswitch: *mut cswitch_t,
    pub creturn: *mut creturn_t,
    pub cgoto: *mut cgoto_t,
    pub casm: *mut casm_t,
    pub ctry: *mut ctry_t,
    pub cthrow: *mut cthrow_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cinsn_t {
    pub base: citem_t,
    pub u: cinsn_u,
}

/// `cblock_t` = qlist<cinsn_t> {next, prev, length} (size 24).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cblock_t {
    pub next: *mut cblock_t,
    pub prev: *mut cblock_t,
    pub length: usize,
}

/// `cexpr_t` - citem_t + union (size 64).
#[repr(C)]
#[derive(Copy, Clone)]
pub union cexpr_u {
    pub n: *mut cnumber_t,
    pub fpc: *mut fnumber_t,
    pub v: *mut var_ref_t,
    pub obj_ea: ea_t,
    pub x: *mut cexpr_t,
    pub y: *mut cexpr_t,
    pub a: *mut carglist_t,
    pub m: u32,
    pub z: *mut cexpr_t,
    pub ptrsize: i32,
    pub insn: *mut cinsn_t,
    pub helper: *mut u8,
    pub string: *mut u8,
    pub refwidth: i32,
    pub _upad0: u32,
    pub _upad1: u64,
    pub _usize: [u8; 24],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cexpr_t {
    pub base: citem_t,
    pub u: cexpr_u,
    pub typ: tinfo_t,
    pub exflags: u32,
    pub _pad2: u32,
}

/// `ctree_maturity_t` - 4-byte enum.
pub type ctree_maturity_t = u32;

/// `intvec_t` = qvector<int>.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct intvec_t {
    pub array: *mut i32,
    pub n: usize,
    pub alloc: usize,
}

/// `cswitch_t` - size 136. Full prefix mirrored, tail carried implicitly.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cswitch_t {
    pub base: citem_t,
    pub u: cexpr_u,
    pub typ: tinfo_t,
    pub exflags: u32,
    pub _pad2: u32,
    pub mvnf_value: u64,
    pub nf_flags32: u32,
    pub nf_opnum: i8,
    pub nf_props: i8,
    pub nf_serial: u8,
    pub nf_org_nbytes: i8,
    pub nf_type_name: qstring,
    pub nf_flags: flags64_t,
    pub cases_array: *mut ccase_t,
    pub cases_n: usize,
    pub cases_alloc: usize,
}

/// `ctry_t` - size 72.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ctry_t {
    pub next: *mut cblock_t,
    pub prev: *mut cblock_t,
    pub length: usize,
    pub catchs_array: *mut ccatch_t,
    pub catchs_n: usize,
    pub catchs_alloc: usize,
    pub old_state: usize,
    pub new_state: usize,
    pub is_wind: bool,
}

/// `cfunc_t` - full layout (size 184).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cfunc_t {
    pub entry_ea: ea_t,
    pub mba: *mut mba_t,
    pub body: cinsn_t,
    pub argidx: *mut intvec_t,
    pub maturity: ctree_maturity_t,
    pub user_labels: *mut user_labels_t,
    pub user_cmts: *mut user_cmts_t,
    pub numforms: *mut user_numforms_t,
    pub user_iflags: *mut user_iflags_t,
    pub user_unions: *mut user_unions_t,
    pub refcnt: i32,
    pub statebits: i32,
    pub eamap: *mut eamap_t,
    pub boundaries: *mut boundaries_t,
    pub sv: qvector<simpleline_t>,
    pub hdrlines: i32,
    pub _pad3: u32,
    pub treeitems: qvector<*mut citem_t>,
}

// ---------------------------------------------------------------------------
impl core::fmt::Debug for argloc_union {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("argloc_union")
    }
}
impl core::fmt::Debug for cinsn_u {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("cinsn_u")
    }
}
impl core::fmt::Debug for cexpr_u {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("cexpr_u")
    }
}
/// `gdl_graph_t` - abstract graph interface; never constructed in Rust.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct gdl_graph_t {
    _opaque: [u8; 0],
}
unsafe impl cxx::ExternType for gdl_graph_t {
    type Id = cxx::type_id!("gdl_graph_t");
    type Kind = cxx::kind::Opaque;
}
/// xrefblk_t - xref enumerator (size 24, align 8).
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct xrefblk_t {
    pub from: ea_t,
    pub to: ea_t,
    pub iscode: bool,
    pub type_: u8,
    pub user: bool,
    pub _flags: u8,
    pub _pad: [u8; 2],
}
unsafe impl cxx::ExternType for xrefblk_t {
    type Id = cxx::type_id!("xrefblk_t");
    type Kind = cxx::kind::Trivial;
}
/// `qbasic_block_t` - opaque; accessed through idalib helpers.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct qbasic_block_t {
    _opaque: [u8; 0],
}

/// `qflow_chart_t` - opaque; accessed through idalib helpers.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct qflow_chart_t {
    _opaque: [u8; 0],
}

unsafe impl cxx::ExternType for qbasic_block_t {
    type Id = cxx::type_id!("qbasic_block_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for qflow_chart_t {
    type Id = cxx::type_id!("qflow_chart_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for range_t {
    type Id = cxx::type_id!("range_t");
    type Kind = cxx::kind::Trivial;
}
unsafe impl cxx::ExternType for insn_t {
    type Id = cxx::type_id!("insn_t");
    type Kind = cxx::kind::Trivial;
}
unsafe impl cxx::ExternType for op_t {
    type Id = cxx::type_id!("op_t");
    type Kind = cxx::kind::Trivial;
}
unsafe impl cxx::ExternType for cfunc_t {
    type Id = cxx::type_id!("cfunc_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for citem_t {
    type Id = cxx::type_id!("citem_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for cinsn_t {
    type Id = cxx::type_id!("cinsn_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for cexpr_t {
    type Id = cxx::type_id!("cexpr_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for cblock_t {
    type Id = cxx::type_id!("cblock_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for cswitch_t {
    type Id = cxx::type_id!("cswitch_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for ctry_t {
    type Id = cxx::type_id!("ctry_t");
    type Kind = cxx::kind::Opaque;
}
unsafe impl cxx::ExternType for cthrow_t {
    type Id = cxx::type_id!("cthrow_t");
    type Kind = cxx::kind::Opaque;
}
// Layout verification - matches values measured from the real SDK headers.
// ---------------------------------------------------------------------------
const _: () = {
    assert!(core::mem::size_of::<range_t>() == 16);
    assert!(core::mem::align_of::<range_t>() == 8);
    // op_t offsets must match the IDA 9.2 SDK ua.hpp layout exactly
    // (n=0, reg/phrase union=6, value=8, addr=16, specval=24, specflag1=32).
    assert!(core::mem::offset_of!(op_t, n) == 0);
    assert!(core::mem::offset_of!(op_t, type_) == 1);
    assert!(core::mem::offset_of!(op_t, reg) == 6);
    assert!(core::mem::offset_of!(op_t, value) == 8);
    assert!(core::mem::offset_of!(op_t, addr) == 16);
    assert!(core::mem::offset_of!(op_t, specval) == 24);
    assert!(core::mem::offset_of!(op_t, specflag1) == 32);
    assert!(core::mem::offset_of!(op_t, specflag4) == 35);
    assert!(core::mem::size_of::<op_t>() == 40);
    assert!(core::mem::size_of::<insn_t>() == 360);
    assert!(core::mem::size_of::<argloc_t>() == 16);
    assert!(core::mem::size_of::<tinfo_t>() == 8);
    assert!(core::mem::size_of::<vdloc_t>() == 16);
    assert!(core::mem::size_of::<lvar_locator_t>() == 24);
    assert!(core::mem::size_of::<lvar_t>() == 104);
    assert!(core::mem::size_of::<citem_t>() == 24);
    assert!(core::mem::size_of::<cinsn_t>() == 32);
    assert!(core::mem::size_of::<cblock_t>() == 24);
    assert!(core::mem::size_of::<cexpr_t>() == 64);
    assert!(core::mem::size_of::<cswitch_t>() == 136);
    assert!(core::mem::size_of::<ctry_t>() == 72);
    assert!(core::mem::size_of::<cthrow_t>() == 64);
    assert!(core::mem::size_of::<cfunc_t>() == 184);
    assert!(core::mem::size_of::<qstring>() == 24);
};
#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn sizes() {
        println!("cexpr={} cinsn={} citem={} cfunc={} cswitch={} ctry={} cthrow={} lvar={} lvar_loc={} vdloc={} argloc={} tinfo={} range={} op={} insn={} qstring={}",
            std::mem::size_of::<cexpr_t>(), std::mem::size_of::<cinsn_t>(), std::mem::size_of::<citem_t>(),
            std::mem::size_of::<cfunc_t>(), std::mem::size_of::<cswitch_t>(), std::mem::size_of::<ctry_t>(),
            std::mem::size_of::<cthrow_t>(), std::mem::size_of::<lvar_t>(), std::mem::size_of::<lvar_locator_t>(),
            std::mem::size_of::<vdloc_t>(), std::mem::size_of::<argloc_t>(), std::mem::size_of::<tinfo_t>(),
            std::mem::size_of::<range_t>(), std::mem::size_of::<op_t>(), std::mem::size_of::<insn_t>(),
            std::mem::size_of::<qstring>());
    }
}