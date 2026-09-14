//! IDA backend: mock implementation (default) and real idalib-backed
//! implementation (commit 6) behind `rmcp_core::backend::IdaBackend`.

pub mod mock;

pub use mock::MockBackend;
