//! Worker process pool: spawn `reverse-mcp-worker` children, perform the
//! hello handshake, route one request at a time per session, detect crashes,
//! respawn, and enforce `max_workers`.

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

/// One worker process + its request channel.
pub struct WorkerSession {
    tx: mpsc::Sender<(WorkerRequest, oneshot::Sender<Result<Value>>)>,
    hello: WorkerHello,
    db_path: Option<String>,
}

impl WorkerSession {
    /// Send a request and await its response (2 min timeout).
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let (tx_back, rx_back) = oneshot::channel();
        let id = next_call_id();
        self.tx
            .send((
                WorkerRequest {
                    id,
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
}

impl WorkerPool {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            worker_exe: None,
            worker_exe_error: None,
            ida_dir: None,
        }
    }

    /// Locate the worker binary next to this exe (portable layout). Also
    /// checks the parent dir so `target/debug/deps` test binaries find
    /// `target/debug/reverse-mcp-worker.exe`.
    pub fn ensure_worker_exe(&mut self) -> Result<PathBuf> {
        if let Some(p) = &self.worker_exe {
            return Ok(p.clone());
        }
        let exe_dir = rmcp_core::layout::exe_dir();
        let name = if cfg!(windows) {
            "reverse-mcp-worker.exe"
        } else {
            "reverse-mcp-worker"
        };
        let mut candidates = vec![exe_dir.join(name)];
        if let Some(parent) = exe_dir.parent() {
            candidates.push(parent.join(name));
        }
        for p in candidates {
            if p.is_file() {
                self.worker_exe = Some(p.clone());
                return Ok(p);
            }
        }
        self.worker_exe_error = Some(format!(
            "worker binary not found near {}",
            exe_dir.display()
        ));
        Err(Error::Worker(self.worker_exe_error.clone().unwrap()))
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
    /// Returns the new db handle.
    pub async fn spawn_for(
        &mut self,
        db_path: &str,
        max_workers: usize,
        backend_kind: &str,
    ) -> Result<String> {
        if self.sessions.len() >= max_workers {
            return Err(Error::Worker(format!(
                "max_workers={} reached; close a database first",
                max_workers
            )));
        }
        let worker_exe = self.ensure_worker_exe()?;
        let ida_dir = self.ida_dir.clone();
        let plugins_dir = rmcp_core::layout::plugins_dir();

        let mut cmd = Command::new(&worker_exe);
        if let Some(dir) = &ida_dir {
            cmd.env("REVERSE_MCP_IDA_DIR", dir);
        }
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
        // Pump task owns the child; a crash surfaces as a dropped oneshot.
        let _pump = tokio::spawn(pump_task(Box::new(pump_stdout), rx, stdin, child));

        let session = Arc::new(Mutex::new(WorkerSession {
            tx,
            hello,
            db_path: Some(db_path.to_string()),
        }));

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
}

impl Default for WorkerPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Pump: forward requests to worker stdin, route responses to callers.
/// Exits (killing the child) when the request channel closes.
async fn pump_task(
    stdout: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    mut rx: mpsc::Receiver<(WorkerRequest, oneshot::Sender<Result<Value>>)>,
    mut stdin: ChildStdin,
    mut child: Child,
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
                                None => Err(Error::Worker(
                                    r.error
                                        .map(|e| format!("{}: {}", e.code, e.message))
                                        .unwrap_or_else(|| "worker error".into()),
                                )),
                            };
                            let _ = back.send(value);
                        }
                    }
                    Ok(None) => {
                        // EOF: worker exited
                        fail_all(&mut pending, "worker exited unexpectedly");
                        break;
                    }
                    Err(e) => {
                        fail_all(&mut pending, &format!("worker frame error: {e}"));
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
