//! #20 MCP resources: read-only, cache-friendly views of frequently browsed
//! DB state, so agents can pull context without burning tool calls.
//!
//! URI shape (issue #20):
//!   ida://db/{id}/metadata
//!   ida://db/{id}/segments
//!   ida://db/{id}/entrypoints
//!   ida://db/{id}/imports
//!   ida://db/{id}/exports
//!   ida://db/{id}/info
//!
//! Content is bounded through the same result-store budget as tools, so a
//! huge import table can never flood the context window.

use std::sync::Arc;

use rmcp::model::{
    ListResourceTemplatesResult, ListResourcesResult, ReadResourceResult, Resource,
    ResourceContents, ResourceTemplate,
};
use serde_json::json;
use tokio::sync::Mutex;

use crate::worker_pool::WorkerSession;
use crate::{Broker, bound_output, mcp_code};

/// No static instances: everything is per-open-DB and served via templates.
pub fn list() -> ListResourcesResult {
    ListResourcesResult::with_all_items(Vec::<Resource>::new())
}

pub fn templates() -> ListResourceTemplatesResult {
    let kinds = [
        (
            "metadata",
            "extended metadata: hashes, image base, entry points",
        ),
        ("segments", "all segments"),
        ("entrypoints", "entry points (ordinal/ea/name)"),
        ("imports", "imported modules and entries (paginated)"),
        ("exports", "export view (entry points)"),
        ("info", "basic DB info: function count, processor, bits"),
    ];
    let tpls: Vec<ResourceTemplate> = kinds
        .iter()
        .map(|(kind, desc)| {
            ResourceTemplate::new(format!("ida://db/{{id}}/{kind}"), format!("ida-db-{kind}"))
                .with_description(format!("Read-only {desc} for an open database."))
                .with_mime_type("application/json")
        })
        .collect();
    ListResourceTemplatesResult::with_all_items(tpls)
}

async fn session_for(
    broker: &Broker,
    id: &str,
) -> Result<Arc<Mutex<WorkerSession>>, rmcp::ErrorData> {
    broker.pool.lock().await.session(id).await.ok_or_else(|| {
        mcp_code(
            "unknown_db",
            &format!("db handle '{id}' is unknown or closed"),
        )
    })
}

async fn call_session(
    broker: &Broker,
    id: &str,
    method: &str,
) -> Result<serde_json::Value, rmcp::ErrorData> {
    let session = session_for(broker, id).await?;
    let s = session.lock().await;
    s.call(method, json!({}))
        .await
        .map_err(crate::tools::err_from)
}

/// Read one resource URI. Bounded like tool outputs.
pub async fn read(broker: &Broker, uri: &str) -> Result<ReadResourceResult, rmcp::ErrorData> {
    let rest = uri.strip_prefix("ida://db/").ok_or_else(|| {
        mcp_code(
            "invalid_args",
            "unsupported resource URI (want ida://db/{id}/{kind})",
        )
    })?;
    let (id, kind) = rest
        .split_once('/')
        .ok_or_else(|| mcp_code("invalid_args", "URI must be ida://db/{id}/{kind}"))?;

    let payload = match kind {
        "metadata" => call_session(broker, id, "db.metadata").await?,
        "segments" => call_session(broker, id, "segments").await?,
        // entrypoints/exports are views over db.metadata's entries list.
        "entrypoints" | "exports" => call_session(broker, id, "db.metadata").await?,
        "imports" => call_session(broker, id, "imports.list").await?,
        "info" => call_session(broker, id, "db.info").await?,
        other => {
            return Err(mcp_code(
                "invalid_args",
                &format!(
                    "unknown resource kind '{other}' (metadata|segments|entrypoints|imports|exports|info)"
                ),
            ));
        }
    };

    let payload = bound_output(broker, &format!("resource:{kind}"), payload);
    let text = serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string());
    Ok(ReadResourceResult::new(vec![
        ResourceContents::text(text, uri).with_mime_type("application/json"),
    ]))
}
