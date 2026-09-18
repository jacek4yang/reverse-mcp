//! Domain model shared by all reverse-mcp crates: config, discovery, errors,
//! backend trait, handles, result store.

pub mod analysis_index;
pub mod backend;
pub mod backend_registry;
pub mod config;
pub mod discovery;
pub mod error;
pub mod handle;
pub mod layout;
pub mod platform;
pub mod protocol;
pub mod result_store;
