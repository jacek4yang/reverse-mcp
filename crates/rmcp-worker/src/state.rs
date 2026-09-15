//! Worker-side state: the active backend, open/closed bookkeeping, the
//! per-session mutation audit trail (#16), the analysis index (#14), and the
//! workflow result cache (#8).

use rmcp_core::analysis_index::AnalysisIndex;
use rmcp_core::backend::IdaBackend;

#[derive(Default)]
pub struct WorkerState {
    pub backend: Option<Box<dyn IdaBackend>>,
    pub closed: bool,
    /// Audit trail of applied mutations (bounded tail, see plan::audit_tail).
    pub audit: Vec<serde_json::Value>,
    /// Built analysis index + the md5 it was keyed by. None until built.
    pub index: Option<(AnalysisIndex, String)>,
    /// Workflow result cache (#8): revision-keyed; invalidated on mutation.
    pub workflow_cache: crate::workflow::WorkflowCache,
}

impl WorkerState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: None,
            closed: false,
            audit: Vec::new(),
            index: None,
            workflow_cache: crate::workflow::WorkflowCache::default(),
        }
    }
}
