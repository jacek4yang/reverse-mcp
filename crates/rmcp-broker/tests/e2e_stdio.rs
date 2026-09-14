//! End-to-end test: broker MCP server driven by an in-process MCP client
//! over a duplex transport. Uses the mock backend so it runs anywhere.

use serde_json::json;
use tokio::io::duplex;

use rmcp::model::{CallToolRequestParams, ClientInfo, Implementation};
use rmcp::transport::async_rw::AsyncRwTransport;

#[tokio::test]
async fn e2e_stdio_mock_wired() {
    // The worker child process must exist; build it on demand for test runs.
    ensure_worker_built().await;
    // Pair 1: server-read <- client-write
    let (server_read, client_write) = duplex(64 * 1024);
    // Pair 2: client-read <- server-write
    let (client_read, server_write) = duplex(64 * 1024);

    let broker = rmcp_broker::Broker::new(rmcp_core::config::Config::default());
    let server_task = tokio::spawn(async move {
        use rmcp::ServiceExt;
        let service = rmcp_broker::ReverseMcpServer::new(broker);
        let transport = AsyncRwTransport::new(server_read, server_write);
        let running = service.serve(transport).await?;
        running.waiting().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });

    let client_transport = AsyncRwTransport::new(client_read, client_write);
    let client_info = ClientInfo::new(
        rmcp::model::ClientCapabilities::default(),
        Implementation::new("test-client", "0.1.0"),
    );
    let client = rmcp::service::serve_client(client_info, client_transport)
        .await
        .expect("client init");
    let server_info = client.peer_info().expect("peer info");
    assert!(
        server_info
            .server_info
            .as_ref()
            .map(|i| !i.name.is_empty())
            .unwrap_or(false)
    );

    // list tools
    let tools = client
        .list_tools(Default::default())
        .await
        .expect("list_tools");
    let names: Vec<String> = tools.tools.iter().map(|t| t.name.to_string()).collect();
    assert_eq!(names.len(), 17, "expected 17 tools, got {names:?}");
    assert!(names.contains(&"ida_decompile".to_string()));
    assert!(names.contains(&"ida_result".to_string()));
    assert!(names.contains(&"ida_segments".to_string()));
    assert!(names.contains(&"ida_installations".to_string()));

    // open db (mock backend explicitly; default is idalib)
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_db").with_arguments(
                json!({"action": "open", "path": "fixture.i64", "backend": "mock"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("open");
    let text = first_text(&resp);
    assert!(text.contains("\"db1\""), "open response: {text}");

    // list functions
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_functions").with_arguments(
                json!({"db": "db1", "offset": 0, "limit": 3})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("functions");
    let text = first_text(&resp);
    assert!(text.contains("main"), "functions response: {text}");

    // decompile
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_decompile").with_arguments(
                json!({"db": "db1", "ea": "0x401200"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("decompile");
    let text = first_text(&resp);
    assert!(
        text.contains("decrypt_packet"),
        "decompile response: {text}"
    );

    // edit (rename) then verify revision
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_edit").with_arguments(
                json!({"db": "db1", "ea": "0x401100", "rename": "helper_renamed"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("edit");
    let text = first_text(&resp);
    assert!(text.contains("revision_after"), "edit response: {text}");

    // db ambiguity error with two DBs
    let _ = client
        .call_tool(
            CallToolRequestParams::new("ida_db").with_arguments(
                json!({"action": "open", "path": "fixture2.i64", "backend": "mock"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("open second");
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_functions")
                .with_arguments(json!({}).as_object().unwrap().clone()),
        )
        .await
        .expect("ambiguous call yields tool-level error");
    let text = first_text(&resp);
    assert!(text.contains("db_ambiguous"), "ambiguity response: {text}");

    // close db1 cleanly
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_db").with_arguments(
                json!({"action": "close", "db": "db1"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("close");
    let text = first_text(&resp);
    assert!(text.contains("closed"), "close response: {text}");

    let _ = client.cancel().await;
    server_task.abort();
}

fn first_text(resp: &rmcp::model::CallToolResult) -> String {
    resp.content
        .iter()
        .find_map(|c| match c {
            rmcp::model::ContentBlock::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Ensure the worker binary exists near this test binary (target/debug).
/// cargo does not build other bins for integration tests, so do it once.
async fn ensure_worker_built() {
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
    if candidates.iter().any(|p| p.is_file()) {
        return;
    }
    let status = tokio::process::Command::new("cargo")
        .args(["build", "-p", "rmcp-worker"])
        .status()
        .await
        .expect("run cargo build -p rmcp-worker");
    assert!(status.success(), "failed to build rmcp-worker for e2e test");
}
