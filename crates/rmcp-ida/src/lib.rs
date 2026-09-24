//! IDA backend: mock implementation (default) and real idalib-backed
//! implementation behind `rmcp_core::backend::IdaBackend`.
//!
//! Two mutually exclusive native backends exist: `idalib92` (vendored
//! idalib 0.7.2+9.2.250908) and `idalib94` (vendored idalib 0.10.1+9.4.260714).
//! They mirror different IDA SDK ABIs and must never be linked into one build;
//! the guard below fails the compile when both are requested.

#[cfg(all(feature = "idalib92", feature = "idalib94"))]
compile_error!(
    "features `idalib92` and `idalib94` are mutually exclusive: pick exactly one IDA ABI per build"
);

pub mod mock;

pub use mock::MockBackend;

#[cfg(any(feature = "idalib92", feature = "idalib94"))]
pub mod idalib_backend;
#[cfg(any(feature = "idalib92", feature = "idalib94"))]
pub use idalib_backend::IdaLibBackend;
