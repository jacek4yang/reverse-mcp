//! Unified error type. MCP-facing errors map onto stable machine-readable
//! codes (`capability_unavailable`, `db_ambiguous`, …) so agents can react.

use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ida not found: {0}")]
    IdaNotFound(String),

    #[error("ida version mismatch: found {found}, require 9.2.x: {detail}")]
    IdaVersionMismatch { found: String, detail: String },

    #[error("config error: {0}")]
    Config(String),

    #[error("capability unavailable: {capability}: {reason}")]
    CapabilityUnavailable { capability: String, reason: String },

    #[error("db handle '{0}' is unknown or closed")]
    UnknownDb(String),

    #[error("db handle omitted and {count} DBs are open; specify one of: {candidates}")]
    DbAmbiguous { count: usize, candidates: String },

    #[error("result handle '{0}' is unknown or expired")]
    UnknownResult(String),

    #[error("revision conflict: expected {expected}, current {current}")]
    RevisionConflict { expected: u64, current: u64 },

    #[error("worker failure: {0}")]
    Worker(String),

    #[error("ipc failure: {0}")]
    Ipc(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Stable error code used in MCP error payloads.
    pub fn code(&self) -> &'static str {
        match self {
            Error::IdaNotFound(_) => "ida_not_found",
            Error::IdaVersionMismatch { .. } => "ida_version_mismatch",
            Error::Config(_) => "config",
            Error::CapabilityUnavailable { .. } => "capability_unavailable",
            Error::UnknownDb(_) => "unknown_db",
            Error::DbAmbiguous { .. } => "db_ambiguous",
            Error::UnknownResult(_) => "unknown_result",
            Error::RevisionConflict { .. } => "revision_conflict",
            Error::Worker(_) => "worker_failure",
            Error::Ipc(_) => "ipc_failure",
            Error::Io(_) => "io",
        }
    }
}

/// Convenience alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A JSON-shaped error payload safe to hand to MCP clients.
#[derive(Debug, serde::Serialize)]
pub struct ErrorPayload<'a> {
    pub code: &'a str,
    pub message: String,
}

impl Error {
    pub fn payload(&self) -> ErrorPayload<'_> {
        ErrorPayload {
            code: self.code(),
            message: self.to_string(),
        }
    }
}

impl fmt::Display for ErrorPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable() {
        assert_eq!(
            Error::CapabilityUnavailable {
                capability: "decompile".into(),
                reason: "hexrays missing".into()
            }
            .code(),
            "capability_unavailable"
        );
        assert_eq!(
            Error::DbAmbiguous {
                count: 2,
                candidates: "db1, db2".into()
            }
            .code(),
            "db_ambiguous"
        );
    }
}
