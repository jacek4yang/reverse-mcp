//! IDA backend: mock implementation (default) and real idalib-backed
//! implementation behind `rmcp_core::backend::IdaBackend`.

pub mod mock;

pub use mock::MockBackend;

#[cfg(feature = "idalib")]
pub mod idalib_backend;
#[cfg(feature = "idalib")]
pub use idalib_backend::IdaLibBackend;
