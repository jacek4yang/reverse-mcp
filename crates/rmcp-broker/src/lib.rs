//! Broker: manages worker processes and exposes the MCP server.
//!
//! Tool call flow: MCP tool args → broker validates (db handle resolution,
//! expected_revision) → worker request → response → bounded output through
//! the result store.

use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams,
    GetPromptResponse, Implementation, ListPromptsResult, ListResourceTemplatesResult,
    ListResourcesResult, ListToolsResult, ReadResourceRequestParams, ReadResourceResponse,
    ServerCapabilities, ServerInfo,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::{ErrorData as McpError, ServerHandler};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use rmcp_core::config::Config;
use rmcp_core::result_store::ResultStore;

pub mod isolation;
pub mod job_object;
pub mod jobs;
pub mod prompts;
pub mod recovery;
pub mod registry;
pub mod resources;
pub mod tools;
pub mod worker_pool;

pub use worker_pool::WorkerPool;

// ---------------------------------------------------------------------------
// Shared helpers used by tools.rs
// ---------------------------------------------------------------------------

/// Resolve db param or fail when ambiguous.
pub async fn resolve_db(
    broker: &Broker,
    db: Option<&str>,
) -> Result<(String, Arc<Mutex<worker_pool::WorkerSession>>), McpError> {
    let open = broker.open_dbs.lock().await.clone();
    match (db, open.len()) {
        (Some(h), _) => {
            let session = broker.pool.lock().await.session(h).await.ok_or_else(|| {
                mcp_code(
                    "unknown_db",
                    &format!("db handle '{h}' is unknown or closed"),
                )
            })?;
            Ok((h.to_string(), session))
        }
        (None, 1) => {
            let (h, _) = &open[0];
            let session = broker
                .pool
                .lock()
                .await
                .session(h)
                .await
                .ok_or_else(|| mcp_code("unknown_db", "session gone"))?;
            Ok((h.clone(), session))
        }
        (None, 0) => Err(mcp_code(
            "unknown_db",
            "no db open; call ida_db(action=open) first",
        )),
        (None, n) => {
            let candidates = open
                .iter()
                .map(|(h, _)| h.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(mcp_code(
                "db_ambiguous",
                &format!("db handle omitted and {n} DBs are open; specify one of: {candidates}"),
            ))
        }
    }
}

pub fn mcp_code(code: &str, message: &str) -> McpError {
    McpError::invalid_params(format!("[{code}] {message}"), None)
}

/// Compact a result through the store: inline JSON or handle+preview.
pub fn bound_output(broker: &Broker, tool: &str, payload: Value) -> Value {
    let (handle, preview, spilled) =
        broker
            .store
            .put(tool, payload.clone(), broker.config.result_threshold);
    if !spilled {
        return payload;
    }
    json!({
        "result_ref": handle,
        "preview": preview,
        "hint": "payload exceeded output budget; read it with ida_result(handle)",
    })
}

pub fn arg_str<'a>(args: &'a Value, name: &str) -> Option<&'a str> {
    args.get(name).and_then(|v| v.as_str())
}

pub fn arg_u64(args: &Value, name: &str, default: u64) -> u64 {
    args.get(name).and_then(|v| v.as_u64()).unwrap_or(default)
}

/// Shared broker state.
pub struct Broker {
    pub config: Config,
    pub store: ResultStore,
    pub pool: Mutex<WorkerPool>,
    /// db handle string -> opened path (for sessions listing).
    pub open_dbs: Mutex<Vec<(String, String)>>,
    /// Entries removed by the store janitor (lifetime total; observability).
    pub janitor_swept: Mutex<u64>,
    /// #57 background analysis jobs (agent autonomy: start/status/result/
    /// list/cancel) - outcome stored until read or TTL; never lost.
    pub jobs: jobs::JobManager,
}

impl Broker {
    pub fn new(config: Config) -> Arc<Self> {
        let ttl = config.result_ttl;
        let jobs = jobs::JobManager::new(4, ttl);
        Arc::new(Self {
            store: ResultStore::new(ttl),
            jobs,
            config,
            pool: Mutex::new(WorkerPool::new()),
            open_dbs: Mutex::new(Vec::new()),
            janitor_swept: Mutex::new(0),
        })
    }

    /// Background janitor: sweeps expired result-store entries and enforces
    /// the hard entry cap every `interval`. Runs for the broker's lifetime
    /// so a soak-scale session cannot accumulate dead payloads (#57).
    pub fn spawn_store_janitor(
        self: &Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let broker = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let swept = broker.store.sweep();
                let jobs_swept = broker.jobs.sweep().await;
                let max = broker.config.result_max_entries;
                let capped = if max > 0 {
                    broker.store.enforce_cap(max)
                } else {
                    0
                };
                if swept + capped + jobs_swept > 0 {
                    // Low-noise observability: janitor work is visible via
                    // ida_health's janitor counters, not stderr spam.
                    let mut n = broker.janitor_swept.lock().await;
                    *n += (swept + capped + jobs_swept) as u64;
                }
            }
        })
    }

    /// Serve MCP over stdio. Returns when stdin closes.
    pub async fn serve_stdio(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error>> {
        // #57 long-run reliability: janitor keeps the result store bounded.
        self.spawn_store_janitor(Duration::from_secs(60));
        use rmcp::ServiceExt;
        let service = ReverseMcpServer::new(self.clone());
        let stdio = rmcp::transport::stdio();
        let running = service.serve(stdio).await?;
        running.waiting().await?;
        Ok(())
    }

    /// Serve MCP over Streamable HTTP, bound to `addr` (loopback by default).
    /// Multiple MCP clients share this broker: each HTTP client negotiates
    /// its own MCP session via the rmcp session manager, while the broker
    /// serializes per-DB worker access across all of them.
    pub async fn serve_http(
        self: Arc<Self>,
        addr: std::net::SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // #57: same janitor for the long-lived HTTP broker.
        self.spawn_store_janitor(Duration::from_secs(60));
        use rmcp::transport::streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
        };

        let session_manager = Arc::new(LocalSessionManager::default());
        let config = StreamableHttpServerConfig::default();
        let broker = self.clone();

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        eprintln!("reverse-mcp: Streamable HTTP listening on {addr}");
        loop {
            let (stream, _peer) = listener.accept().await?;
            let io = hyper_util::rt::TokioIo::new(stream);
            // StreamableHttpService is Clone and its Service impl takes &mut
            // self, so a fresh clone per connection is enough.
            let service = StreamableHttpService::new(
                {
                    let broker = Arc::clone(&broker);
                    move || Ok(ReverseMcpServer::new(broker.clone()))
                },
                Arc::clone(&session_manager),
                config.clone(),
            );
            tokio::spawn(async move {
                let handler = hyper::service::service_fn(move |req| {
                    let mut service = service.clone();
                    async move {
                        use tower::Service as _;
                        service.call(req).await.map_err(std::io::Error::other)
                    }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                );
                let _ = builder.serve_connection_with_upgrades(io, handler).await;
            });
        }
    }
}

/// rmcp ServerHandler implementation.
pub struct ReverseMcpServer {
    pub broker: Arc<Broker>,
}

impl ReverseMcpServer {
    pub fn new(broker: Arc<Broker>) -> Self {
        Self { broker }
    }
}

impl ServerHandler for ReverseMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        )
        .with_server_info(Implementation::from_build_env())
        .with_instructions(
            "Reverse engineering over IDA Pro. Open a database with ida_db(action=open) \
             first; use the returned db handle (db1, db2, ...) on every other tool. \
             Large outputs spill to result handles (r1, ...) — read them with ida_result. \
             Prefer resources (ida://db/{id}/...) for frequently-read state, ida_mutation \
             action=plan for change batches, and the workflow prompts (survey, deep-dive, \
             refactor) before chaining atomic calls.",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(resources::list())
    }

    async fn list_resource_templates(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(resources::templates())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        resources::read(&self.broker, request.uri.as_ref())
            .await
            .map(Into::into)
    }

    async fn list_prompts(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(prompts::list())
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        prompts::get(&request).map(Into::into)
    }

    async fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(registry::tool_list()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let args = Value::Object(request.arguments.clone().unwrap_or_default());
        let structured = registry::call(&self.broker, request.name.as_ref(), args).await;
        match structured {
            Ok(v) => {
                let text = serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".to_string());
                Ok(Into::into(CallToolResult::success(vec![
                    ContentBlock::text(text),
                ])))
            }
            Err(e) => {
                // Tool-level error: reached the tool, execution failed. The
                // stable code stays visible to the agent in the content.
                let text = serde_json::to_string_pretty(&serde_json::json!({
                    "error": {"code": e.code, "message": e.message},
                }))
                .unwrap_or_default();
                Ok(Into::into(CallToolResult::error(vec![ContentBlock::text(
                    text,
                )])))
            }
        }
    }
}
