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
    fn graph(&self, ea: u64, depth: u32) -> Result<Value>;

    fn search_text(&self, needle: &str, limit: usize) -> Result<Vec<Value>>;
    fn search_immediate(&self, value: u64, limit: usize) -> Result<Vec<Value>>;

    fn get_bytes(&self, ea: u64, size: usize) -> Result<Value>;
    fn patch_bytes(&mut self, ea: u64, bytes_hex: &str) -> Result<MutationOutcome>;

    fn get_comment(&self, ea: u64, repeatable: bool) -> Result<Value>;
    fn set_comment(&mut self, ea: u64, comment: &str, repeatable: bool) -> Result<MutationOutcome>;

    fn rename(&mut self, ea: u64, new_name: &str) -> Result<MutationOutcome>;

    fn types(&self, name: Option<&str>) -> Result<Value>;

    fn set_type(&mut self, ea: u64, type_decl: &str) -> Result<MutationOutcome>;

    fn analyze_wait(&mut self) -> Result<Value>;
    fn run_plugin(&mut self, plugin: &str, args: Option<&str>) -> Result<Value>;
    fn list_plugins(&self) -> Result<Value>;
}

/// Boxed alias used across the workspace.
pub type BoxedBackend = Box<dyn IdaBackend>;
