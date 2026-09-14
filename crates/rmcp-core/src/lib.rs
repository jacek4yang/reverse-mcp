//! Domain model shared by all reverse-mcp crates: config, discovery, errors,
//! backend trait, handles, result store.

pub mod backend;
pub mod config;
pub mod discovery;
pub mod error;
pub mod handle;
pub mod layout;
pub mod result_store;
