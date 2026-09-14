//! Streamable HTTP MCP integration tests (mock backend, no IDA needed):
//! two simultaneous MCP clients negotiate sessions over HTTP and share the
//! broker. Exercises issue #15's multi-client transport requirement.

use std::time::Duration;

use hyper::{HeaderMap, StatusCode};
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;

const TEST_PORT: u16 = 18750;

type HttpClient = LegacyClient<
    hyper_util::client::legacy::connect::HttpConnector,
    http_body_util::Full<bytes::Bytes>,
>;

fn client() -> HttpClient {
    hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http()
}

async fn spawn_server() -> std::net::SocketAddr {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{TEST_PORT}").parse().unwrap();
    let broker = rmcp_broker::Broker::new(rmcp_core::config::Config::default());
    tokio::spawn(async move {
        let _ = broker.serve_http(addr).await;
    });
    // Wait for the listener.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("http server did not come up");
}

/// One POST to the MCP endpoint. Returns status, headers, and body text.
async fn post(
    addr: std::net::SocketAddr,
    sid: Option<&str>,
    body: serde_json::Value,
) -> Result<(StatusCode, HeaderMap, String), Box<dyn std::error::Error>> {
    let uri = format!("http://{addr}/");
    let mut req = hyper::Request::builder()
        .method("POST")
        .uri(&uri)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(sid) = sid {
        req = req.header("mcp-session-id", sid);
    }
    let req = req.body(http_body_util::Full::new(bytes::Bytes::from(
        body.to_string(),
    )))?;
    let resp = client().request(req).await?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await?
        .to_bytes();
    Ok((
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    ))
}

fn session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

fn init_request() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "it-client", "version": "0.1"}
        }
    })
}

fn call_request(id: u64, name: &str, args: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": args}
    })
}

#[tokio::test]
async fn two_http_clients_share_broker() {
    let addr = spawn_server().await;

    // Client 1: initialize, get its session id.
    let (status, headers, body) = post(addr, None, init_request()).await.expect("init 1");
    assert_eq!(status, StatusCode::OK, "init 1: {body}");
    let sid1 = session_id(&headers).expect("session id from client 1");

    // Client 2: initialize, independent session.
    let (status, headers, body) = post(addr, None, init_request()).await.expect("init 2");
    assert_eq!(status, StatusCode::OK, "init 2: {body}");
    let sid2 = session_id(&headers).expect("session id from client 2");
    assert_ne!(sid1, sid2, "each client must negotiate its own session");

    // Client 1 opens a DB (mock backend; CI has no IDA).
    let (status, _, body) = post(
        addr,
        Some(&sid1),
        call_request(
            2,
            "ida_db",
            serde_json::json!({"action": "open", "path": "http-it.i64", "backend": "mock"}),
        ),
    )
    .await
    .expect("open call");
    assert_eq!(status, StatusCode::OK, "open: {body}");
    assert!(body.contains("db1"), "open response: {body}");

    // Client 2 shares the broker: its ida_db list sees client 1's DB.
    let (status, _, body) = post(
        addr,
        Some(&sid2),
        call_request(2, "ida_db", serde_json::json!({"action": "list"})),
    )
    .await
    .expect("list call");
    assert_eq!(status, StatusCode::OK, "list: {body}");
    assert!(body.contains("http-it.i64"), "shared state: {body}");

    // Client 2 also performs a read through the shared broker.
    let (status, _, body) = post(
        addr,
        Some(&sid2),
        call_request(3, "ida_capabilities", serde_json::json!({})),
    )
    .await
    .expect("caps call");
    assert_eq!(status, StatusCode::OK, "caps: {body}");
    assert!(body.contains("decompile"), "caps body: {body}");
}
