//! Worker-side state: the active backend, open/closed bookkeeping, and the
//! per-session mutation audit trail (#16).

use rmcp_core::backend::IdaBackend;

#[derive(Default)]
pub struct WorkerState {
    pub backend: Option<Box<dyn IdaBackend>>,
    pub closed: bool,
    /// Audit trail of applied mutations (bounded tail, see plan::audit_tail).
    pub audit: Vec<serde_json::Value>,
}

impl WorkerState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: None,
            closed: false,
            audit: Vec::new(),
        }
    }
}
