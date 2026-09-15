//! `IdaBackend` — the abstraction that lets the whole broker/protocol/tool
//! stack run against a mock (no IDA needed) or the real idalib-backed
//! implementation. One backend instance = one loaded IDB = one worker thread.

use serde_json::Value;

use crate::error::Result;

/// A function entry as reported by `ida_functions` / `ida_inspect`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionInfo {
    pub ea_start: u64,
    pub ea_end: u64,
    pub name: String,
    pub size: u64,
}

/// A cross-reference.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XrefInfo {
    pub from: u64,
    pub to: u64,
    pub kind: String, // call / data / flow / far / jump
}

/// Parameters for `ida_graph` requests.
#[derive(Debug, Clone)]
pub struct GraphParams {
    /// `calls` (default) or `cfg`.
    pub kind: String,
    /// How many levels to follow from the root function.
    pub depth: u32,
    /// Hard caps so hostile inputs cannot flood the output.
    pub max_nodes: usize,
    pub max_edges: usize,
}

/// A string found in the DB.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StringInfo {
    pub ea: u64,
    pub value: String,
    pub length: usize,
}

/// A segment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SegmentInfo {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub perms: String,
}

/// One disassembled instruction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InsnInfo {
    pub ea: u64,
    pub mnemonic: String,
    pub operands: String,
    pub text: String,
}

/// What a backend can do — drives `ida_capabilities` and honest errors.
/// Fields added for #19 are declared honestly: a backend that does not
/// implement a capability reports `false` rather than guessing.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Capabilities {
    pub decompile: bool,
    pub types: bool,
    pub imports_exports: bool,
    pub patch_bytes: bool,
    pub rename: bool,
    pub comments: bool,
    pub bookmarks: bool,
    pub plugins: bool,
    /// Typed ctree node summaries (`hr.cfunc`).
    pub ctree: bool,
    /// Local variable summaries + rename (`hr.cfunc` / `hr.lvar_rename`).
    pub lvars: bool,
    /// Microcode generation/inspection (`hr.microcode`).
    pub microcode: bool,
    /// Switch/jump-table metadata (`func.switch_info`).
    pub switches: bool,
    /// Fixup/relocation enumeration (`fixups.list`).
    pub fixups: bool,
    /// Function chunk/tail enumeration (`func.tails`).
    pub tails: bool,
    /// Per-instruction SP delta (`func.sp_delta`).
    pub sp_delta: bool,
    /// File-offset <-> EA mapping (`file.map`).
    pub file_map: bool,
}

/// Mutation results.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MutationOutcome {
    pub changed: bool,
    pub revision_after: u64,
    pub detail: Value,
}

/// Backend trait. All addresses are effective addresses (u64).
/// Synchronous by design: the broker guarantees one request at a time per DB.
pub trait IdaBackend: Send {
    /// Open a database file (.i64/.idb/binary). Returns the short handle info.
    fn open(&mut self, path: &str) -> Result<Value>;

    /// Close the currently open DB.
    fn close(&mut self) -> Result<()>;

    /// Save the DB.
    fn save(&mut self) -> Result<()>;

    /// DB metadata for `ida_db` / `ida_inspect`.
    fn db_info(&self) -> Result<Value>;

    fn capabilities(&self) -> Capabilities;

    /// Monotonic revision counter bumped by every mutation.
    fn revision(&self) -> u64;

    fn functions(&self, offset: usize, limit: usize) -> Result<Vec<FunctionInfo>>;
    fn function_at(&self, ea: u64) -> Result<FunctionInfo>;
    fn segments(&self) -> Result<Vec<SegmentInfo>>;
    fn strings(&self, offset: usize, limit: usize) -> Result<Vec<StringInfo>>;
    fn xrefs_to(&self, ea: u64) -> Result<Vec<XrefInfo>>;
    fn xrefs_from(&self, ea: u64) -> Result<Vec<XrefInfo>>;
    fn disassemble(
        &self,
        ea_start: u64,
        ea_end: Option<u64>,
        max_insns: usize,
    ) -> Result<Vec<InsnInfo>>;
    fn decompile(&self, ea: u64) -> Result<Value>;
    fn graph(&self, ea: u64, params: &GraphParams) -> Result<Value>;

    fn search_text(&self, needle: &str, limit: usize) -> Result<Vec<Value>>;
    fn search_immediate(&self, value: u64, limit: usize) -> Result<Vec<Value>>;

    fn get_bytes(&self, ea: u64, size: usize) -> Result<Value>;
    fn patch_bytes(&mut self, ea: u64, bytes_hex: &str) -> Result<MutationOutcome>;

    fn get_comment(&self, ea: u64, repeatable: bool) -> Result<Value>;
    fn set_comment(&mut self, ea: u64, comment: &str, repeatable: bool) -> Result<MutationOutcome>;

    fn rename(&mut self, ea: u64, new_name: &str) -> Result<MutationOutcome>;

    fn types(&self, name: Option<&str>) -> Result<Value>;

    fn set_type(&mut self, ea: u64, type_decl: &str) -> Result<MutationOutcome>;

    // ---- #19: database / binary metadata ----

    /// Extended DB metadata: input hashes, image base, entry points.
    fn db_metadata(&self) -> Result<Value>;

    /// Imports per module (bounded). `module` None lists all modules.
    fn imports(&self, module: Option<usize>, offset: usize, limit: usize) -> Result<Value>;

    /// Fixup/relocation records (bounded).
    fn fixups(&self, offset: usize, limit: usize) -> Result<Value>;

    /// File-offset <-> EA mapping. `to_ea == false` maps EA -> file offset.
    fn file_map(&self, value: u64, to_ea: bool) -> Result<Value>;

    // ---- #19: functions / control flow ----

    /// Function chunks (entry + tail chunks) of the function containing `ea`.
    fn func_tails(&self, ea: u64) -> Result<Value>;

    /// Create a function at `start`.
    fn func_create(&mut self, start: u64, end: Option<u64>) -> Result<MutationOutcome>;

    /// Delete the function containing `ea`.
    fn func_delete(&mut self, ea: u64) -> Result<MutationOutcome>;

    /// Resize (move start/end of) the function containing `ea`.
    fn func_resize(
        &mut self,
        ea: u64,
        new_start: Option<u64>,
        new_end: Option<u64>,
    ) -> Result<MutationOutcome>;

    /// Switch/jump-table metadata for the indirect jump at `ea`.
    fn func_switch_info(&self, ea: u64) -> Result<Value>;

    /// SP delta at `ea` inside the function containing it.
    fn func_sp_delta(&self, ea: u64) -> Result<Value>;

    // ---- #19: Hex-Rays ----

    /// Bounded ctree summaries + lvars + return type of a decompiled function.
    /// `include_ctree`/`include_lvars` gate the (potentially large) lists.
    fn hr_cfunc(
        &self,
        ea: u64,
        include_ctree: bool,
        include_lvars: bool,
        limit: usize,
    ) -> Result<Value>;

    /// Rename a local variable of the decompiled function at `ea`.
    fn hr_lvar_rename(
        &mut self,
        ea: u64,
        var_defea: u64,
        new_name: &str,
    ) -> Result<MutationOutcome>;

    // ---- #16: snapshots / rollback ----

    /// Take an IDB snapshot/restore point. Real backend wraps IDA's undo
    /// history (`create_undo_point`); mock records a logical checkpoint.
    fn snapshot_create(&mut self) -> Result<Value>;

    /// Restore to the last snapshot taken by this session. Reports honestly
    /// when the backend cannot roll back generically.
    fn snapshot_restore(&mut self) -> Result<Value>;

    // ---- #19: instructions / names ----

    /// Canon feature bits (CF_*) and mnemonic of the instruction at `ea`.
    fn insn_features(&self, ea: u64) -> Result<Value>;

    /// Demangle a name (returns the input when demangling does not apply).
    fn demangle_name(&self, name: &str) -> Result<Value>;

    fn analyze_wait(&mut self) -> Result<Value>;
    fn run_plugin(&mut self, plugin: &str, args: Option<&str>) -> Result<Value>;
    fn list_plugins(&self) -> Result<Value>;
}

/// Boxed alias used across the workspace.
pub type BoxedBackend = Box<dyn IdaBackend>;
