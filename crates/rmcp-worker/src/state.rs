//! Worker-side state: the active backend and open/closed bookkeeping.

use rmcp_core::backend::IdaBackend;

#[derive(Default)]
pub struct WorkerState {
    pub backend: Option<Box<dyn IdaBackend>>,
    pub closed: bool,
}

impl WorkerState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            backend: None,
            closed: false,
        }
    }
}
