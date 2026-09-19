//! #71 WASM semantic analysis layer.
//!
//! Bounded, cache-aware, static-only parsing and analysis of WebAssembly
//! modules. IDA stays the primary reverse-engineering database; this crate
//! supplies WASM-specific facts IDA does not expose and cross-checks the
//! facts it does.
//!
//! Subsystems (landed incrementally, each behind tests):
//! - [`module`]: bounded parse into a normalized module model
//!   (sections, types, imports/exports, functions/locals, globals, tables,
//!   memories, element/data segments, custom/name/producers, feature map).
//! - [`cfg`]: structured control-flow recovery preserving block/loop/if
//!   signatures and stack effects (never flattened into native-style CFG).
//! - [`ssa`]: operand-stack-to-SSA/use-def value analysis with bounded
//!   constant propagation.
//! - [`calls`]: direct call graph + `call_indirect`/`call_ref` resolution
//!   into confirmed/candidate/unresolved with evidence.
//! - [`pseudo`]: deterministic WASM-native C-like pseudocode (explicitly
//!   NOT Hex-Rays output).
//!
//! Everything is keyed by binary hash + analysis revision + parser version
//! and cached through the worker's existing workflow cache.

pub mod calls;
pub mod cfg;
pub mod module;
pub mod pseudo;
pub mod ssa;

/// Parser/engine version, part of every cache key: a parser upgrade must
/// never serve stale IR.
pub const ENGINE_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "/wasmparser-0.239");

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wasm parse failed at offset {offset}: {message}")]
    Parse { offset: u64, message: String },
    #[error("feature '{feature}' not enabled in this module: {message}")]
    FeatureDisabled {
        feature: &'static str,
        message: String,
    },
    #[error("budget exhausted: {0}")]
    Budget(&'static str),
    #[error("analysis ambiguous: {0}")]
    Ambiguous(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
