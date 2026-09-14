//! Worker lifecycle state machine and crash recovery.
//!
//! States: Healthy -> Crashed -> Recovering -> Healthy (or Dead after
//! `max_restarts` consecutive failures with backoff).
//!
//! The broker keeps enough session metadata (db path, backend kind, IDA
//! version requirement) to respawn the same backend and reopen the same
//! database while preserving the public db handle.
//!
//! Mutation requests whose success is unknown (in flight when the worker
//! died) are never replayed: the caller gets `WorkerDied { code }` and must
//! retry explicitly.

use std::time::Duration;

/// Lifecycle state of one worker session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerHealth {
    /// Serving requests.
    Healthy,
    /// The worker process died; no requests can be served.
    Crashed,
    /// A replacement worker is starting and the DB is being reopened.
    Recovering,
    /// Consecutive restart attempts exhausted; the session stays dead until
    /// explicitly closed and reopened by the caller.
    Dead,
}

/// Bounded restart policy.
#[derive(Debug, Clone)]
pub struct RestartPolicy {
    pub max_restarts: u32,
    pub backoff: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            backoff: Duration::from_millis(200),
        }
    }
}

/// Session metadata the broker persists so it can respawn the exact same
/// backend/IDA version and reopen the same database.
#[derive(Debug, Clone)]
pub struct SessionMeta {
    pub db_path: String,
    pub backend_kind: String,
    pub ida_version: String,
}

impl SessionMeta {
    pub fn new(db_path: &str, backend_kind: &str, ida_version: &str) -> Self {
        Self {
            db_path: db_path.to_string(),
            backend_kind: backend_kind.to_string(),
            ida_version: ida_version.to_string(),
        }
    }
}

/// Distinguishes failures so callers know what is safe to retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallFailure {
    /// Request was fully processed and answered; the error came from the
    /// operation itself. Safe to inspect and retry.
    Operation(ErrorLike),
    /// The request was written to the worker but no answer arrived (worker
    /// died mid-call). Unknown outcome: never replayed automatically. The
    /// caller may retry explicitly after recovery, understanding the
    /// mutation may or may not have applied.
    UnknownOutcome { hint: &'static str },
    /// The request never reached the worker. Always safe to retry.
    NotSent { hint: &'static str },
    /// Timed out waiting for an answer. Unknown outcome.
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLike {
    pub code: &'static str,
    pub message: String,
}

impl From<rmcp_core::error::Error> for CallFailure {
    fn from(e: rmcp_core::error::Error) -> Self {
        CallFailure::Operation(ErrorLike {
            code: e.code(),
            message: e.to_string(),
        })
    }
}

/// Classification helper used by the pump: did the failure happen before the
/// request reached the worker (safe) or after (unknown outcome)?
pub fn classify_send_failure(sent: bool, why: &'static str) -> CallFailure {
    if sent {
        CallFailure::UnknownOutcome { hint: why }
    } else {
        CallFailure::NotSent { hint: why }
    }
}

/// Whether a method mutates the DB (conservative list used to decide whether
/// an unknown-outcome failure must block automatic retries).
pub fn is_mutation(method: &str) -> bool {
    matches!(
        method,
        "rename" | "set_comment" | "set_type" | "patch_bytes" | "run_plugin"
    )
}
