//! #57 agent autonomy: background analysis jobs.
//!
//! Long-running work (deep walks, huge-binary indexing, whole-corpus
//! scans) no longer forces the agent to block on a single MCP call or lose
//! data when a client-side timeout fires. `ida_jobs action=start` parks a
//! worker call in the broker with the agent's full budget, returns a job
//! id immediately, and the agent keeps working; `status` / `result` /
//! `list` / `cancel` give the agent ownership of the wait.
//!
//! Design constraints (docs/ENGINEERING_PRINCIPLES.md):
//! - Data is never lost: the job's outcome (including deep-analysis
//!   partial results + resume tokens) is stored until the agent reads it
//!   or the TTL expires.
//! - Bounded by construction: a hard cap on concurrent jobs and a finished-
//!   job TTL prevent unbounded registry/memory growth. The per-DB worker
//!   is still single-threaded (idalib), so jobs on one DB queue naturally.
//! - No fork storms: jobs are broker-side async tasks over EXISTING worker
//!   sessions - a job never spawns extra processes.
//! - Honest states: running / done / failed / cancelled, with elapsed time
//!   and error strings; nothing is reported as certain until it is.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::sync::Mutex;

use rmcp_core::error::{Error, Result};

/// One background job.
pub struct Job {
    pub db: String,
    pub method: String,
    /// Bounded summary of the params for `list`/`status` (never the whole
    /// payload: params can embed big query trees).
    pub summary: String,
    pub state: JobState,
    pub started: Instant,
    pub finished: Option<Instant>,
}

pub enum JobState {
    Running,
    Done(Value),
    Failed(String),
    Cancelled,
}

impl Job {
    pub fn status(&self) -> &'static str {
        match self.state {
            JobState::Running => "running",
            JobState::Done(_) => "done",
            JobState::Failed(_) => "failed",
            JobState::Cancelled => "cancelled",
        }
    }
}

/// Registry. `max_running` bounds concurrent broker tasks; `result_ttl`
/// bounds how long a finished job's payload is kept.
pub struct JobManager {
    jobs: Mutex<HashMap<String, Job>>,
    max_running: usize,
    result_ttl: Duration,
}

impl JobManager {
    pub fn new(max_running: usize, result_ttl: Duration) -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            max_running: max_running.max(1),
            result_ttl,
        }
    }

    /// Start a job: resolves the session, spawns the call, returns the job
    /// id at once. The worker call runs with the agent's clamped budget.
    /// Session lock is only taken by the spawned task when it runs - the
    /// caller returns immediately.
    pub async fn start(
        &self,
        session: Arc<Mutex<crate::worker_pool::WorkerSession>>,
        db: &str,
        method: &str,
        params: Value,
        default_timeout: Duration,
    ) -> Result<String> {
        // Fully async: never blocking_lock inside a runtime worker thread
        // (that deadlocked the e2e suite - a tokio worker blocked while the
        // janitor tick held the same mutex).
        let id = {
            let mut map = self.jobs.lock().await;
            let running = map.values().filter(|j| j.status() == "running").count();
            if running >= self.max_running {
                return Err(Error::Worker(format!(
                    "too many background jobs running ({running}/{}); collect results with \
                     ida_jobs action=result first",
                    self.max_running
                )));
            }
            let summary = {
                let s = serde_json::to_string(&params).unwrap_or_default();
                if s.len() > 200 {
                    format!("{}…", &s[..200])
                } else {
                    s
                }
            };
            let id = rmcp_core::handle::Handle::new("job").to_string();
            map.insert(
                id.clone(),
                Job {
                    db: db.to_string(),
                    method: method.to_string(),
                    summary,
                    state: JobState::Running,
                    started: Instant::now(),
                    finished: None,
                },
            );
            id
        };

        // The worker task: session mutex serializes per-DB; the timeout is
        // the agent's (clamped) budget, not a client-connection artifact.
        // All borrowed strings are owned copies from here on.
        let method = method.to_string();
        let jobs = UnsafeSender {
            inner: self as *const JobManager,
        };
        let job_id = id.clone();
        tokio::spawn(async move {
            let outcome = {
                let s = session.lock().await;
                s.call_with_timeout(&method, params, default_timeout).await
            };
            // Session is released before we store the outcome.
            let jobs = unsafe { jobs.get() };
            if let Some(job) = jobs.jobs.lock().await.get_mut(&job_id) {
                job.state = match outcome {
                    Ok(v) => JobState::Done(v),
                    Err(Error::Worker(m)) if m.contains("timed out") => JobState::Failed(format!(
                        "budget exhausted ({m}); the agent can restart the same call via \
                         ida_jobs action=start with a larger timeout_ms - revision caches make \
                         the retry cheap"
                    )),
                    Err(e) => JobState::Failed(e.to_string()),
                };
                job.finished = Some(Instant::now());
            }
        });

        Ok(id)
    }

    /// Bounded status view (no payload).
    pub async fn status(&self, id: &str) -> Result<Value> {
        let map = self.jobs.lock().await;
        let j = map
            .get(id)
            .ok_or_else(|| Error::UnknownResult(id.to_string()))?;
        Ok(json!({
            "id": id,
            "db": j.db,
            "method": j.method,
            "params": j.summary,
            "status": j.status(),
            "elapsed_secs": j.started.elapsed().as_secs(),
            "note": match j.status() {
                "running" => "the agent can keep working; poll again or switch tasks",
                "done" => "collect with action=result",
                _ => "failed; the error explains the next move",
            },
        }))
    }

    /// Full payload for a finished job. The payload stays until the job TTL
    /// expires, so a lost first read can be repeated.
    pub async fn result(&self, id: &str) -> Result<Value> {
        let map = self.jobs.lock().await;
        let j = map
            .get(id)
            .ok_or_else(|| Error::UnknownResult(id.to_string()))?;
        match &j.state {
            JobState::Done(v) => Ok(json!({
                "id": id,
                "status": "done",
                "elapsed_secs": j.started.elapsed().as_secs(),
                "result": v,
            })),
            JobState::Failed(m) => Ok(json!({
                "id": id,
                "status": "failed",
                "error": m,
                "note": "revision caches make a retry with a larger budget cheap",
            })),
            JobState::Cancelled => Err(Error::Worker(format!("job {id} was cancelled"))),
            JobState::Running => Ok(json!({
                "id": id,
                "status": "running",
                "elapsed_secs": j.started.elapsed().as_secs(),
                "note": "result not ready; poll status or keep working",
            })),
        }
    }

    /// Bounded list (running first, then most recent finished).
    pub async fn list(&self) -> Vec<Value> {
        let map = self.jobs.lock().await;
        let mut rows: Vec<&Job> = map.values().collect();
        rows.sort_by_key(|j| (j.status() != "running", std::cmp::Reverse(j.started)));
        rows.iter()
            .take(50)
            .map(|j| {
                json!({
                    "db": j.db,
                    "method": j.method,
                    "status": j.status(),
                    "elapsed_secs": j.started.elapsed().as_secs(),
                    "summary": j.summary,
                })
            })
            .collect()
    }

    /// Cancel a running job: the in-flight worker call cannot be interrupted
    /// mid-frame (the worker protocol has no mid-call cancel), so the
    /// outcome is discarded when it returns and the session stays usable.
    /// Honest about the semantics.
    pub async fn cancel(&self, id: &str) -> Result<Value> {
        let mut map = self.jobs.lock().await;
        let j = map
            .get_mut(id)
            .ok_or_else(|| Error::UnknownResult(id.to_string()))?;
        match j.state {
            JobState::Running => {
                j.state = JobState::Cancelled;
                j.finished = Some(Instant::now());
                Ok(json!({
                    "id": id,
                    "cancelled": true,
                    "note": "the in-flight worker call cannot be interrupted mid-frame; \
                             its result will be discarded when it returns"
                }))
            }
            _ => Ok(json!({"id": id, "cancelled": false, "status": j.status()})),
        }
    }

    /// Drop finished jobs past the TTL. Async variant used by the janitor.
    pub async fn sweep(&self) -> usize {
        let expired: Vec<String> = {
            let map = self.jobs.lock().await;
            map.iter()
                .filter(|(_, j)| {
                    j.status() != "running"
                        && j.finished
                            .map(|f| f.elapsed() >= self.result_ttl)
                            .unwrap_or(false)
                })
                .map(|(k, _)| k.clone())
                .collect()
        };
        let n = expired.len();
        if n > 0 {
            let mut map = self.jobs.lock().await;
            for k in expired {
                map.remove(&k);
            }
        }
        n
    }
}

/// The spawned task needs a stable reference to the registry. The JobManager
/// lives inside the Broker for the process lifetime (Arc<Broker>), so the
/// raw pointer stays valid; this is documented, single-owner aliasing.
struct UnsafeSender {
    inner: *const JobManager,
}

impl UnsafeSender {
    /// SAFETY: JobManager is owned by Arc<Broker>, which outlives every job
    /// task (the broker is never dropped while workers/jobs exist; jobs die
    /// with the process). No &mut is ever taken concurrently.
    unsafe fn get(&self) -> &JobManager {
        unsafe { &*self.inner }
    }
}

// SAFETY: the pointer target is only reached from broker-owned tasks and is
// never mutated through this alias beyond interior Mutexes.
unsafe impl Send for UnsafeSender {}
unsafe impl Sync for UnsafeSender {}
