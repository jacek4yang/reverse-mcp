//! Worker process pool: spawn this same executable in `worker` mode (single-
//! exe architecture), perform the hello handshake, route one request at a
//! time per session, detect crashes, respawn, and enforce `max_workers`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{Mutex, mpsc, oneshot};

use rmcp_core::error::{Error, Result};
use rmcp_core::protocol::r#async::{AsyncFrameReader, write_frame_async};
use rmcp_core::protocol::{PROTOCOL_VERSION, WorkerHello, WorkerRequest, WorkerResponse};

/// One worker process + its request channel + recovery state.
pub struct WorkerSession {
    tx: Option<mpsc::Sender<(WorkerRequest, oneshot::Sender<Result<Value>>)>>,
    hello: WorkerHello,
    db_path: Option<String>,
    /// Session metadata persisted for crash recovery.
    meta: Option<crate::recovery::SessionMeta>,
    /// Lifecycle state (Healthy → Crashed → Recovering → Healthy/Dead).
    health: crate::recovery::WorkerHealth,
    /// Consecutive restart failures for the bounded-restart policy.
    restart_failures: u32,
}

impl WorkerSession {
    /// Send a request and await its response (2 min timeout).
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| Error::Worker("worker is dead; close and reopen the db".into()))?;
        let (tx_back, rx_back) = oneshot::channel();
        tx.send((
            WorkerRequest {
                id: next_call_id(),
                method: method.into(),
                params,
            },
            tx_back,
        ))
        .await
        .map_err(|_| Error::Worker("worker request channel closed".into()))?;
        match tokio::time::timeout(Duration::from_secs(120), rx_back).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => Err(Error::Worker("worker dropped response (crashed?)".into())),
            Err(_) => Err(Error::Worker("worker timed out".into())),
        }
    }

    pub fn hello(&self) -> &WorkerHello {
        &self.hello
    }

    pub fn db_path(&self) -> Option<&str> {
        self.db_path.as_deref()
    }

    /// Lifecycle state of the underlying worker process.
    pub fn health(&self) -> crate::recovery::WorkerHealth {
        self.health
    }

    /// Session metadata used to respawn the same backend/DB after a crash.
    pub fn meta(&self) -> Option<&crate::recovery::SessionMeta> {
        self.meta.as_ref()
    }

    /// Mark the session Crashed (called by the pump monitor on worker EOF).
    pub fn mark_crashed(&mut self) {
        self.tx = None;
        self.health = crate::recovery::WorkerHealth::Crashed;
    }

    /// Test-only: point the recovery metadata at a path that can never be
    /// opened, so recovery attempts deterministically fail.
    pub fn kill_for_test(&mut self) {
        if let Some(meta) = &mut self.meta {
            meta.db_path = "Z:/definitely/not/a/real/db.i64".into();
        }
    }
}

fn next_call_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Pool of sessions keyed by db handle string.
pub struct WorkerPool {
    pub sessions: Vec<(String, Arc<Mutex<WorkerSession>>)>,
    worker_exe: Option<PathBuf>,
    /// Result of trying to locate the worker binary at startup.
    pub worker_exe_error: Option<String>,
    ida_dir: Option<PathBuf>,
    /// Cached idalib-feature detection for the worker binary.
    idalib_feature: Option<bool>,
}
impl WorkerPool {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            worker_exe: None,
            worker_exe_error: None,
            ida_dir: None,
            idalib_feature: None,
        }
    }

    /// Locate the worker binary: the single-exe architecture runs the worker
    /// as this same executable (`<exe> worker`). When running inside a test
    /// binary, `current_exe` is the test itself, so fall back to a
    /// `reverse-mcp(.exe)` sibling in the same or parent directory.
    pub fn ensure_worker_exe(&mut self) -> Result<PathBuf> {
        if let Some(p) = &self.worker_exe {
            return Ok(p.clone());
        }
        let exe_dir = rmcp_core::layout::exe_dir();
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(cur) = std::env::current_exe() {
            candidates.push(cur);
        }
        let sibling = if cfg!(windows) {
            "reverse-mcp.exe"
        } else {
            "reverse-mcp"
        };
        candidates.push(exe_dir.join(sibling));
        if let Some(parent) = exe_dir.parent() {
            candidates.push(parent.join(sibling));
        }
        for c in candidates {
            // A valid worker exe answers the mock probe with exit 0.
            let probed = std::process::Command::new(&c)
                .args(["worker", "--probe-backend", "mock"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output();
            if probed.is_ok_and(|out| out.status.success()) {
                self.worker_exe = Some(c.clone());
                return Ok(c);
            }
        }
        let msg = "no worker-capable exe found (expected reverse-mcp with `worker` subcommand)";
        self.worker_exe_error = Some(msg.to_string());
        Err(Error::Worker(msg.to_string()))
    }

    pub fn set_ida_dir(&mut self, dir: PathBuf) {
        self.ida_dir = Some(dir);
    }

    pub async fn session(&self, db: &str) -> Option<Arc<Mutex<WorkerSession>>> {
        self.sessions
            .iter()
            .find(|(h, _)| h == db)
            .map(|(_, s)| s.clone())
    }

    pub async fn list(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (h, s) in &self.sessions {
            let s = s.lock().await;
            out.push((h.clone(), s.db_path().unwrap_or("").to_string()));
        }
        out
    }

    /// Spawn a worker for `db_path`, handshake, select backend, open the DB.
    /// `ida_version` may be empty (auto-select), "9.2", "latest" or a range
    /// like ">=9.2,<9.4" — parsed by `IdaRequirement`.
    /// Returns the new db handle.
    pub async fn spawn_for(
        &mut self,
        db_path: &str,
        max_workers: usize,
        backend_kind: &str,
        ida_version: &str,
    ) -> Result<String> {
        if self.sessions.len() >= max_workers {
            return Err(Error::Worker(format!(
                "max_workers={} reached; close a database first",
                max_workers
            )));
        }
        let worker_exe = self.ensure_worker_exe()?;
        // Resolve the IDA install (multi-version aware; discovery may hit
        // the drive scan). An explicitly configured dir wins. A mock backend
        // needs no IDA at all — skip discovery so CI / IDA-less machines work.
        let (ida_dir, backend_kind) = if backend_kind == "mock" {
            (None, backend_kind.to_string())
        } else {
            let requirement = rmcp_core::discovery::IdaRequirement::parse(ida_version)?;
            let explicit = self.ida_dir.clone();
            let install = if let Some(d) = explicit.as_deref() {
                rmcp_core::discovery::resolve_with(Some(d), &requirement)?
            } else {
                rmcp_core::discovery::resolve(&requirement)?
            };
            let dir = install.root.clone();
            // The worker must run a backend matching this install version.
            let kind = if backend_kind == "idalib" && !install.backend_ready() {
                return Err(Error::CapabilityUnavailable {
                    capability: "idalib".into(),
                    reason: format!(
                        "IDA {} is installed but no verified backend ships for it (only 9.2); pick another version or upgrade reverse-mcp",
                        install.version
                    ),
                });
            } else if backend_kind == "auto" {
                // auto = real backend when (a) this install is backend-ready
                // and (b) the worker binary actually ships the idalib feature;
                // mock otherwise (probed at worker side).
                if install.backend_ready() && self.worker_has_idalib_feature() {
                    "idalib".to_string()
                } else {
                    "mock".to_string()
                }
            } else {
                backend_kind.to_string()
            };
            (Some(dir), kind)
        };
        let plugins_dir = rmcp_core::layout::plugins_dir();

        // Single-exe architecture: the worker is this same binary invoked
        // with the internal `worker` subcommand.
        let mut cmd = Command::new(&worker_exe);
        cmd.arg("worker");
        if let Some(dir) = &ida_dir {
            cmd.env("REVERSE_MCP_IDA_DIR", dir);
            // The worker links ida.dll/idalib.dll; add the IDA dir to PATH so
            // the loader resolves them without a system-wide PATH entry.
            let path = std::env::var("PATH").unwrap_or_default();
            cmd.env("PATH", format!("{};{}", dir.display(), path));
            // IDA's embedded Python needs a home or its init fails and the
            // worker dies; point it at the interpreter bundled with IDA.
            let pyhome = dir.join("Python311");
            if pyhome.is_dir() {
                cmd.env("PYTHONHOME", &pyhome);
            }
        }
        // Portable plugins: IDAUSR points at the exe-relative plugins dir so
        // plugins come only from reverse-mcp's layout, never the IDA install
        // dir or %APPDATA%\.idapro.
        cmd.env("IDAUSR", &plugins_dir);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::null());
        let mut child = cmd
            .spawn()
            .map_err(|e| Error::Worker(format!("spawn worker: {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Worker("no worker stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Worker("no worker stdout".into()))?;

        // Read the hello frame.
        let mut reader = AsyncFrameReader::new(tokio::io::BufReader::new(stdout));
        let hello: WorkerHello = reader
            .read()
            .await?
            .ok_or_else(|| Error::Worker("worker exited before hello".into()))?;
        if hello.protocol != PROTOCOL_VERSION {
            return Err(Error::Worker(format!(
                "worker protocol {} != broker protocol {}",
                hello.protocol, PROTOCOL_VERSION
            )));
        }

        let (tx, rx) = mpsc::channel::<(WorkerRequest, oneshot::Sender<Result<Value>>)>(64);
        let pump_stdout = reader.into_inner();
        let session = Arc::new(Mutex::new(WorkerSession {
            tx: Some(tx),
            hello,
            db_path: Some(db_path.to_string()),
            meta: Some(crate::recovery::SessionMeta::new(
                db_path,
                &backend_kind,
                ida_version,
            )),
            health: crate::recovery::WorkerHealth::Healthy,
            restart_failures: 0,
        }));

        // Pump task owns the child; a crash surfaces as a dropped oneshot and
        // is reported through the crash channel so the session flips to
        // Crashed.
        let (crash_tx, mut crash_rx) = mpsc::channel::<String>(1);
        let _pump = tokio::spawn(pump_task(Box::new(pump_stdout), rx, stdin, child, crash_tx));
        let crash_session = Arc::clone(&session);
        tokio::spawn(async move {
            // One-shot: the first EOF flips the session to Crashed.
            if crash_rx.recv().await.is_some() {
                crash_session.lock().await.mark_crashed();
            }
        });

        {
            let s = session.lock().await;
            s.call("backend.select", serde_json::json!({"kind": backend_kind}))
                .await?;
            s.call("db.open", serde_json::json!({"path": db_path}))
                .await?;
        }

        let handle = rmcp_core::handle::Handle::new("db").to_string();
        self.sessions.push((handle.clone(), session));
        Ok(handle)
    }

    /// Does this exe support the idalib backend? Probed once by running
    /// `<exe> worker --probe-backend idalib` (the worker prints `idalib` and
    /// exits 0). Falls back to false.
    fn worker_has_idalib_feature(&mut self) -> bool {
        if let Some(flag) = self.idalib_feature {
            return flag;
        }
        let detected = self
            .worker_exe
            .as_ref()
            .and_then(|exe| {
                let out = std::process::Command::new(exe)
                    .args(["worker", "--probe-backend", "idalib"])
                    .output()
                    .ok()?;
                let s = String::from_utf8_lossy(&out.stdout);
                Some(s.trim() == "idalib")
            })
            .unwrap_or(false);
        self.idalib_feature = Some(detected);
        detected
    }

    pub async fn close(&mut self, db: &str) -> Result<()> {
        let idx = self
            .sessions
            .iter()
            .position(|(h, _)| h == db)
            .ok_or_else(|| Error::UnknownDb(db.to_string()))?;
        let (_, session) = self.sessions.remove(idx);
        let s = session.lock().await;
        let _ = s.call("db.save", serde_json::json!({})).await;
        let _ = s.call("db.close", serde_json::json!({})).await;
        let _ = s.call("shutdown", serde_json::json!({})).await;
        Ok(())
    }

    /// Worker lifecycle states, exposed for health reporting.
    pub async fn health(&self, db: &str) -> Result<crate::recovery::WorkerHealth> {
        let s = self
            .session(db)
            .await
            .ok_or_else(|| Error::UnknownDb(db.to_string()))?;
        Ok(s.lock().await.health())
    }

    /// Recover a crashed worker while preserving the public db handle:
    /// respawn the same backend/IDA version and reopen the same database.
    /// Bounded by `RestartPolicy` (consecutive failures + backoff); a session
    /// that exhausts the budget goes to `Dead` and must be closed/reopened by
    /// the caller. Mutations whose outcome is unknown are NOT replayed; the
    /// caller receives `mutation_outcome_unknown` if the crash happened while
    /// such a mutation was in flight.
    pub async fn recover(
        &mut self,
        db: &str,
        policy: &crate::recovery::RestartPolicy,
    ) -> Result<()> {
        let idx = self
            .sessions
            .iter()
            .position(|(h, _)| h == db)
            .ok_or_else(|| Error::UnknownDb(db.to_string()))?;
        let session = self.sessions[idx].1.clone();
        {
            let mut s = session.lock().await;
            if s.health() == crate::recovery::WorkerHealth::Healthy {
                return Ok(());
            }
            if s.health() == crate::recovery::WorkerHealth::Dead {
                return Err(Error::Worker(
                    "worker recovery budget exhausted; close and reopen the db".into(),
                ));
            }
            s.health = crate::recovery::WorkerHealth::Recovering;
        }

        let meta = session
            .lock()
            .await
            .meta()
            .cloned()
            .ok_or_else(|| Error::Worker("no session metadata; cannot recover".into()))?;

        loop {
            tokio::time::sleep(policy.backoff).await;
            match self
                .spawn_for(
                    &meta.db_path,
                    usize::MAX,
                    &meta.backend_kind,
                    &meta.ida_version,
                )
                .await
            {
                Ok(new_handle) => {
                    // Swap the old session (same slot, preserved handle) for
                    // the fresh one.
                    let idx = self
                        .sessions
                        .iter()
                        .position(|(h, _)| *h == new_handle)
                        .expect("just-pushed handle exists");
                    let fresh = self.sessions.remove(idx).1;
                    let slot = self
                        .sessions
                        .iter_mut()
                        .find(|(h, _)| h == db)
                        .expect("recovered handle still registered");
                    *slot = (db.to_string(), fresh);
                    return Ok(());
                }
                Err(_) => {
                    let mut s = session.lock().await;
                    s.restart_failures += 1;
                    if s.restart_failures > policy.max_restarts {
                        s.health = crate::recovery::WorkerHealth::Dead;
                        return Err(Error::Worker(format!(
                            "worker recovery failed after {} attempts",
                            s.restart_failures
                        )));
                    }
                }
            }
        }
    }

    /// Convenience: recover with the default policy.
    pub async fn recover_default(&mut self, db: &str) -> Result<()> {
        self.recover(db, &crate::recovery::RestartPolicy::default())
            .await
    }
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Pump: forward requests to worker stdin, route responses to callers.
/// Exits (killing the child) when the request channel closes; reports the
/// reason through `crash_tx` so the session can flip to Crashed.
async fn pump_task(
    stdout: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    mut rx: mpsc::Receiver<(WorkerRequest, oneshot::Sender<Result<Value>>)>,
    mut stdin: ChildStdin,
    mut child: Child,
    crash_tx: mpsc::Sender<String>,
) {
    let mut reader = AsyncFrameReader::new(tokio::io::BufReader::new(stdout));
    let mut pending: HashMap<u64, oneshot::Sender<Result<Value>>> = HashMap::new();

    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some((req, back)) => {
                        pending.insert(req.id, back);
                        if write_frame_async(&mut stdin, &req).await.is_err() {
                            fail_all(&mut pending, "worker stdin write failed");
                            break;
                        }
                    }
                    None => break, // pool dropped the channel: shut down
                }
            }
            resp = reader.read::<WorkerResponse>() => {
                match resp {
                    Ok(Some(r)) => {
                        if let Some(back) = pending.remove(&r.id) {
                            let value = match r.result {
                                Some(v) => Ok(v),
                                None => Err(match r.error {
                                    Some(e) => error_from_code(&e.code, &e.message),
                                    None => Error::Worker("worker error".into()),
                                }),
                            };
                            let _ = back.send(value);
                        }
                    }
                    Ok(None) => {
                        // EOF: worker exited
                        fail_all(&mut pending, "worker exited unexpectedly");
                        let _ = crash_tx.send("worker exited unexpectedly".into()).await;
                        break;
                    }
                    Err(e) => {
                        fail_all(&mut pending, &format!("worker frame error: {e}"));
                        let _ = crash_tx.send(format!("worker frame error: {e}")).await;
                        break;
                    }
                }
            }
        }
    }
    let _ = child.kill().await;
    let _ = stdin.shutdown().await;
}

fn fail_all(pending: &mut HashMap<u64, oneshot::Sender<Result<Value>>>, why: &str) {
    for (_, back) in pending.drain() {
        let _ = back.send(Err(Error::Worker(why.to_string())));
    }
}

/// Rebuild a structured error from a worker's stable error code so agents
/// can keep matching on codes like `revision_conflict` across the broker
/// boundary. Unrecognized codes stay generic `worker_failure`.
fn error_from_code(code: &str, message: &str) -> Error {
    match code {
        // Stable codes that agents match on:
        "revision_conflict" => {
            // message: "revision conflict: expected N, current M"
            let parsed = (|| {
                let rest = message.strip_prefix("revision conflict: expected ")?;
                let (expected, current) = rest.split_once(", current ")?;
                Some(Error::RevisionConflict {
                    expected: expected.trim().parse().ok()?,
                    current: current.trim().parse().ok()?,
                })
            })();
            parsed.unwrap_or_else(|| Error::Worker(message.to_string()))
        }
        "unknown_db" => {
            let handle = message
                .strip_prefix("db handle '")
                .and_then(|s| s.strip_suffix("' is unknown or closed"))
                .unwrap_or(message);
            Error::UnknownDb(handle.to_string())
        }
        "capability_unavailable" => {
            // message: "capability unavailable: <capability>: <reason>"
            let parsed = (|| {
                let rest = message.strip_prefix("capability unavailable: ")?;
                let (capability, reason) = rest.split_once(": ")?;
                Some(Error::CapabilityUnavailable {
                    capability: capability.to_string(),
                    reason: reason.to_string(),
                })
            })();
            parsed.unwrap_or_else(|| Error::Worker(message.to_string()))
        }
        "db_ambiguous" => Error::DbAmbiguous {
            count: 0,
            candidates: String::new(),
        },
        _ => Error::Worker(message.to_string()),
    }
}
