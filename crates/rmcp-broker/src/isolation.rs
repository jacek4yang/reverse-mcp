//! #72 hard-timeout isolation: disposable read-only analysis workers.
//!
//! Risky Hex-Rays operations (whole-function decompile, region snippet,
//! microcode on giant functions) run in a *disposable* worker process so a
//! native hang/crash never takes down the stable DB worker or wedges the
//! broker.
//!
//! Leak-proofness is enforced structurally, not by discipline:
//! - the spawned child is bound to a Windows Job Object (kill-on-close +
//!   2 GiB memory ceiling) at creation; tree-kill destroys the worker and
//!   anything it spawned;
//! - the [`DisposableGuard`] owns the kill switch; Drop kills + reaps
//!   synchronously (any `?`/panic unwinds through it);
//! - a process-wide semaphore caps concurrent disposable workers (hard max
//!   2) so a burst of failures cannot become a process storm;
//! - spawn/kill/timeout counts live in [`iso_stats`], surfaced by
//!   `ida_health`; the leak probe asserts the ledger balances.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::process::Child;
use tokio::sync::Semaphore;

use rmcp_core::error::{Error, Result};
use rmcp_core::protocol::r#async::{AsyncFrameReader, write_frame_async};
use rmcp_core::protocol::{PROTOCOL_VERSION, WorkerHello, WorkerRequest, WorkerResponse};

/// Observability counters (process-lifetime totals).
#[derive(Debug, Default)]
pub struct IsoStats {
    pub spawned: AtomicU64,
    pub killed_timeout: AtomicU64,
    pub killed_crash: AtomicU64,
    pub exited_clean: AtomicU64,
    pub rejected_cap: AtomicU64,
}

impl IsoStats {
    /// Point-in-time JSON snapshot for tool responses.
    pub fn snapshot(&self) -> Value {
        let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
        json!({
            "spawned": load(&self.spawned),
            "killed_timeout": load(&self.killed_timeout),
            "killed_crash": load(&self.killed_crash),
            "exited_clean": load(&self.exited_clean),
            "rejected_cap": load(&self.rejected_cap),
        })
    }
}

/// Outcome of one disposable run.
#[derive(Debug)]
pub enum DisposableOutcome {
    /// Worker answered within the budget.
    Ok(Value),
    /// Hard timeout: the process tree was killed; primary session untouched.
    Timeout {
        after: Duration,
        stage: &'static str,
    },
    /// Worker died mid-run (Hex-Rays crash, OOM, loader failure).
    Crashed { detail: String, stage: &'static str },
    /// Worker answered with a structured error (not a crash).
    BadResponse { detail: String, stage: &'static str },
}

static ISO_STATS: std::sync::OnceLock<IsoStats> = std::sync::OnceLock::new();

pub fn iso_stats() -> &'static IsoStats {
    ISO_STATS.get_or_init(IsoStats::default)
}

/// Hard cap on concurrent disposable workers (process-wide; leak line).
const MAX_CONCURRENT: usize = 2;

fn iso_semaphore() -> &'static Arc<Semaphore> {
    static SEM: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT)))
}

/// Owns a disposable worker child for the duration of one risky call.
/// Drop = synchronous kill + reap (leak line: nothing survives a `?`).
pub struct DisposableGuard {
    /// Windows Job Object handle; None on non-Windows.
    job: Option<isize>,
    child: Option<Child>,
    accounted: bool,
}

impl DisposableGuard {
    /// Tree-kill: terminate the job, kill the child, reap it. Idempotent.
    pub async fn kill_tree(&mut self) {
        if let Some(job) = self.job.take() {
            crate::job_object::terminate_job(job);
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            // Reap: the Job Object makes termination deterministic, so a
            // bounded wait is generous enough.
            let _ = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        }
    }
}

impl Drop for DisposableGuard {
    fn drop(&mut self) {
        if !self.accounted {
            // Unknown outcome (early return/panic): count as crash-kill so
            // the spawned == terminal ledger stays balanced.
            iso_stats().killed_crash.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(job) = self.job.take() {
            crate::job_object::terminate_job(job);
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
    }
}

/// Run one risky worker request in a disposable process.
pub async fn run_isolated(
    worker_exe: &std::path::Path,
    ida_dir: Option<&std::path::Path>,
    db_path: &str,
    method: &str,
    params: Value,
    hard_timeout: Duration,
) -> Result<DisposableOutcome> {
    let permit = match iso_semaphore().clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            iso_stats().rejected_cap.fetch_add(1, Ordering::Relaxed);
            return Err(Error::Worker(format!(
                "disposable analysis worker cap ({MAX_CONCURRENT}) reached; retry shortly"
            )));
        }
    };

    let mut cmd = tokio::process::Command::new(worker_exe);
    cmd.arg("worker");
    if let Some(dir) = ida_dir {
        cmd.env("REVERSE_MCP_IDA_DIR", dir);
        let path = std::env::var(rmcp_core::platform::path_env()).unwrap_or_default();
        cmd.env(
            rmcp_core::platform::path_env(),
            rmcp_core::platform::prepend_path(dir, &path),
        );
        let pyhome = dir.join(rmcp_core::platform::python_home_dirname());
        if pyhome.is_dir() {
            cmd.env("PYTHONHOME", &pyhome);
        }
    }
    cmd.env("IDAUSR", rmcp_core::layout::plugins_dir());
    cmd.env("REVERSE_MCP_DISPOSABLE", "1");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    // Bind the child to a Job Object before it can spawn anything.
    let child = cmd
        .spawn()
        .map_err(|e| Error::Worker(format!("spawn disposable worker: {e}")))?;
    let job = crate::job_object::assign_child(&child);
    let mut guard = DisposableGuard {
        job,
        child: Some(child),
        accounted: false,
    };
    iso_stats().spawned.fetch_add(1, Ordering::Relaxed);

    // Take stdin/stdout for the duration of the sequence; the guard still
    // owns the Child for kill/reap.
    let mut stdin = guard
        .child
        .as_mut()
        .expect("just spawned")
        .stdin
        .take()
        .ok_or_else(|| Error::Worker("no disposable stdin".into()))?;
    let stdout = guard
        .child
        .as_mut()
        .expect("just spawned")
        .stdout
        .take()
        .ok_or_else(|| Error::Worker("no disposable stdout".into()))?;
    let mut reader = AsyncFrameReader::new(tokio::io::BufReader::new(stdout));

    // Startup budget: at most half the hard timeout (so the risky call
    // always has budget left), capped at 120s.
    let hello_budget = hard_timeout.min(Duration::from_secs(120)) / 2;
    let hello: WorkerHello = match tokio::time::timeout(hello_budget, reader.read()).await {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => {
            return Ok(DisposableOutcome::Crashed {
                detail: "disposable worker died before hello".into(),
                stage: "startup",
            });
        }
        Ok(Err(e)) => {
            return Ok(DisposableOutcome::Crashed {
                detail: format!("disposable hello frame: {e}"),
                stage: "startup",
            });
        }
        Err(_) => {
            iso_stats().killed_timeout.fetch_add(1, Ordering::Relaxed);
            guard.accounted = true;
            guard.kill_tree().await;
            return Ok(DisposableOutcome::Timeout {
                after: hello_budget,
                stage: "startup",
            });
        }
    };
    if hello.protocol != PROTOCOL_VERSION {
        return Ok(DisposableOutcome::Crashed {
            detail: format!(
                "disposable protocol {} != {PROTOCOL_VERSION}",
                hello.protocol
            ),
            stage: "startup",
        });
    }

    // The three requests, answered strictly in order; one clock for all.
    let select = WorkerRequest {
        id: 1,
        method: "backend.select".into(),
        params: serde_json::json!({"kind": "mock"}),
    };
    let open = WorkerRequest {
        id: 2,
        method: "db.open".into(),
        params: serde_json::json!({"path": db_path}),
    };
    let risky = WorkerRequest {
        id: 3,
        method: method.to_string(),
        params,
    };
    let sequence: [&WorkerRequest; 3] = [&select, &open, &risky];

    let remaining = hard_timeout.saturating_sub(hello_budget);
    let outcome = tokio::time::timeout(remaining, async {
        for (i, req) in sequence.iter().enumerate() {
            write_frame_async(&mut stdin, req)
                .await
                .map_err(|e| Error::Worker(format!("stdin write: {e}")))?;
            let r = reader
                .read::<WorkerResponse>()
                .await
                .map_err(|e| Error::Worker(format!("frame error: {e}")))?
                .ok_or_else(|| Error::Worker("disposable worker died mid-sequence".into()))?;
            if let Some(e) = r.error {
                return Err(Error::Worker(format!(
                    "{}: {} {}",
                    req.method, e.code, e.message
                )));
            }
            if i == 2 {
                return Ok(Some(r.result.unwrap_or(Value::Null)));
            }
        }
        Ok(None)
    })
    .await;

    let final_outcome = match outcome {
        Err(_) => {
            iso_stats().killed_timeout.fetch_add(1, Ordering::Relaxed);
            guard.accounted = true;
            guard.kill_tree().await;
            drop(permit);
            return Ok(DisposableOutcome::Timeout {
                after: hard_timeout,
                stage: "risky",
            });
        }
        Ok(Err(e)) => {
            let detail = e.to_string();
            let stage = if detail.starts_with("backend.select:") || detail.starts_with("db.open:") {
                "open"
            } else {
                "risky"
            };
            DisposableOutcome::BadResponse { detail, stage }
        }
        Ok(Ok(Some(v))) => DisposableOutcome::Ok(v),
        Ok(Ok(None)) => DisposableOutcome::BadResponse {
            detail: "no response".into(),
            stage: "risky",
        },
    };

    finish(&mut guard, &final_outcome).await;
    drop(permit);
    Ok(final_outcome)
}

async fn finish(guard: &mut DisposableGuard, o: &DisposableOutcome) {
    match o {
        DisposableOutcome::Ok(_) | DisposableOutcome::BadResponse { .. } => {
            iso_stats().exited_clean.fetch_add(1, Ordering::Relaxed);
        }
        DisposableOutcome::Timeout { .. } => {
            iso_stats().killed_timeout.fetch_add(1, Ordering::Relaxed);
        }
        DisposableOutcome::Crashed { .. } => {
            iso_stats().killed_crash.fetch_add(1, Ordering::Relaxed);
        }
    }
    guard.accounted = true;
    // A disposable worker is never reused and never left running.
    guard.kill_tree().await;
}
