//! End-to-end test: broker MCP server driven by an in-process MCP client
//! over a duplex transport. Uses the mock backend so it runs anywhere.

use serde_json::json;
use tokio::io::duplex;

use rmcp::model::{CallToolRequestParams, ClientInfo, Implementation};
use rmcp::transport::async_rw::AsyncRwTransport;

/// The DB handle counter is process-global, so tests that open databases must
/// not run in parallel (otherwise one test sees db2 when it expects db1).
static DB_COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn e2e_stdio_mock_wired() {
    let _guard = DB_COUNTER_LOCK.lock().await;
    // Single-exe architecture: no separate worker binary to build.
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
    assert_eq!(names.len(), 36, "expected 35 tools, got {names:?}");
    assert!(names.contains(&"ida_decompile".to_string()));
    assert!(names.contains(&"ida_result".to_string()));
    assert!(names.contains(&"ida_segments".to_string()));
    assert!(names.contains(&"ida_installations".to_string()));
    // #19 capability-gap tools
    assert!(names.contains(&"ida_metadata".to_string()));
    assert!(names.contains(&"ida_imports".to_string()));
    assert!(names.contains(&"ida_fixups".to_string()));
    assert!(names.contains(&"ida_filemap".to_string()));
    assert!(names.contains(&"ida_func".to_string()));
    assert!(names.contains(&"ida_hr".to_string()));
    assert!(names.contains(&"ida_insn".to_string()));
    // #28 self-diagnosis tool
    assert!(names.contains(&"ida_health".to_string()));
    // #16 mutation layer
    assert!(names.contains(&"ida_mutation".to_string()));
    // #10 deep analysis
    assert!(names.contains(&"ida_deep".to_string()));
    // #11 type recovery
    assert!(names.contains(&"ida_type_recovery".to_string()));
    // #12 binary intelligence
    assert!(names.contains(&"ida_intel".to_string()));
    // #9 deobfuscation
    assert!(names.contains(&"ida_deobfuscate".to_string()));
    // #13 signatures
    assert!(names.contains(&"ida_sig".to_string()));

    // ida_health: must succeed on an IDA-less machine (CI) and report a
    // structured diagnosis (worker probe + at least discovery shape).
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_health")
                .with_arguments(json!({}).as_object().unwrap().clone()),
        )
        .await
        .expect("ida_health");
    let text = first_text(&resp);
    assert!(text.contains("\"healthy\""), "health response: {text}");
    assert!(
        text.contains("\"worker_probe_ok\""),
        "health response: {text}"
    );
    assert!(
        text.contains("\"hint\""),
        "health response must carry a remediation hint: {text}"
    );

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
    // Handle names are process-global (db1, db2, ...); parse ours.
    let handle: String = text
        .split("\"db\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("db1")
        .to_string();

    // list functions
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_functions").with_arguments(
                json!({"db": handle, "offset": 0, "limit": 3})
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
                json!({"db": handle, "ea": "0x401200"})
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

    // #43: microcode dump through ida_hr (mock backend -> deterministic mba)
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_hr").with_arguments(
                json!({"db": handle, "action": "microcode", "ea": "0x401200", "max_insns": 2})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("ida_hr microcode");
    let text = first_text(&resp);
    assert!(
        text.contains("\"maturity\"") && text.contains("\"insns\""),
        "microcode response: {text}"
    );
    assert!(
        text.contains("\"truncated\": true"),
        "max_insns=2 must truncate the 3-insn fake mba: {text}"
    );

    // #44: value propagation through ida_value (mock -> bounded rows, cached)
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_value").with_arguments(
                json!({"db": handle, "ea": "0x401200", "depth": 2, "max_calls": 8})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("ida_value");
    let text = first_text(&resp);
    assert!(
        text.contains("\"targets\"") && text.contains("\"indirect\""),
        "value response: {text}"
    );
    assert!(
        text.contains("\"cached\": false"),
        "first value call must be a cache miss: {text}"
    );
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_value").with_arguments(
                json!({"db": handle, "ea": "0x401200", "depth": 2, "max_calls": 8})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("ida_value cached");
    let text = first_text(&resp);
    assert!(
        text.contains("\"cached\": true"),
        "identical repeat on unchanged revision must hit the cache: {text}"
    );

    // #46: transform round trip: propose -> validate -> apply -> rollback.
    // The mock graph carries no junk roundtrips, so propose returns an
    // empty-but-wellformed plan; apply of a synthetic validated plan is
    // covered in the worker tests. Here we drive the full MCP shape.
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_deobfuscate").with_arguments(
                json!({"db": handle, "task": "propose", "target": "0x401200", "kind": "T2_junk_removal"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("deob propose");
    let text = first_text(&resp);
    assert!(
        text.contains("\"kind\": \"T2_junk_removal\"") && text.contains("\"operations\""),
        "propose response: {text}"
    );

    // validate a synthetic in-function plan: mock has bytes at 0x401000.
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_deobfuscate").with_arguments(
                json!({"db": handle, "task": "validate",
                       "plan": {"kind": "T2_junk_removal", "target": "0x401000",
                                "operations": [{"kind": "patch_bytes", "ea": "0x401000", "hex": "9090"}]}})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("deob validate");
    let text = first_text(&resp);
    assert!(
        text.contains("\"valid\""),
        "validate response must carry a valid flag: {text}"
    );

    // #57: background jobs - start a slow analysis, keep working, collect.
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_jobs").with_arguments(
                json!({"action": "start", "db": handle, "method": "deob.propose",
                       "params": {"target": "0x401000", "kind": "T2_junk_removal"}})
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .expect("ida_jobs start");
    let text = first_text(&resp);
    assert!(
        text.contains("\"job\"") && text.contains("\"status\": \"running\"")
            || text.contains("\"running\""),
        "job start response: {text}"
    );
    // Extract the job id from the response text.
    let job_id: String = {
        let v: serde_json::Value = serde_json::from_str(&text).unwrap_or(json!({}));
        v["job"].as_str().unwrap_or_default().to_string()
    };
    assert!(!job_id.is_empty(), "job id must be returned: {text}");

    // The agent does other work here (already interleaved in this test).
    // Poll status until done (mock backend: near-instant).
    let mut done = false;
    for _ in 0..40 {
        let resp = client
            .call_tool(
                CallToolRequestParams::new("ida_jobs").with_arguments(
                    json!({"action": "status", "job": job_id})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
            )
            .await
            .expect("ida_jobs status");
        let text = first_text(&resp);
        if text.contains("\"status\": \"done\"") {
            done = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(done, "job must finish");

    // Collect the full result: same payload shape as a foreground call.
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_jobs").with_arguments(
                json!({"action": "result", "job": job_id})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("ida_jobs result");
    let text = first_text(&resp);
    assert!(
        text.contains("\"kind\": \"T2_junk_removal\"") || text.contains("T2_junk_removal"),
        "job result must carry the analysis payload: {text}"
    );

    // List shows the finished job.
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_jobs")
                .with_arguments(json!({"action": "list"}).as_object().unwrap().clone()),
        )
        .await
        .expect("ida_jobs list");
    assert!(
        first_text(&resp).contains(&job_id) || first_text(&resp).contains("deob.propose"),
        "job list: {}",
        first_text(&resp)
    );

    // Mutations cannot be backgrounded (safe-mutation principle).
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_jobs").with_arguments(
                json!({"action": "start", "db": handle, "method": "rename",
                       "params": {"ea": "0x401100", "name": "x"}})
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .expect("ida_jobs mutation guard");
    assert!(
        first_text(&resp).contains("cannot be backgrounded"),
        "mutation must be refused: {}",
        first_text(&resp)
    );

    // edit (rename) then verify revision
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_edit").with_arguments(
                json!({"db": handle, "ea": "0x401100", "rename": "helper_renamed"})
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

    // close cleanly
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_db").with_arguments(
                json!({"action": "close", "db": handle})
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

/// #16 mutation layer end to end over MCP stdio: plan -> apply -> audit ->
/// snapshot/rollback, on the mock backend.
#[tokio::test]
async fn e2e_stdio_mutation_layer() {
    let _guard = DB_COUNTER_LOCK.lock().await;
    let (server_read, client_write) = duplex(64 * 1024);
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

    let client_info = rmcp::model::ClientInfo::default();
    let client = rmcp::service::serve_client(client_info, (client_read, client_write))
        .await
        .expect("client init");

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
    let open_text = first_text(&resp);
    // Handle names are process-global (db1, db2, ...); parse ours.
    let handle: String = open_text
        .split("\"db\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("db1")
        .to_string();

    // plan: validates + previews, no revision bump
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_mutation").with_arguments(
                json!({
                    "db": handle,
                    "action": "plan",
                    "operations": [
                        {"ea": "0x401100", "kind": "rename", "name": "helper_planned"},
                        {"ea": "0x401000", "kind": "comment", "comment": "planned note"}
                    ]
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .expect("plan");
    let text = first_text(&resp);
    assert!(
        text.contains("\"operations\": 2") || text.contains("\"operations\":2"),
        "plan response: {text}"
    );

    // apply with a stale revision must be rejected before any op runs
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_mutation").with_arguments(
                json!({
                    "db": handle,
                    "action": "apply",
                    "expected_revision": 99,
                    "operations": [
                        {"ea": "0x401100", "kind": "rename", "name": "too_late"}
                    ]
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .expect("stale apply");
    let text = first_text(&resp);
    assert!(
        text.contains("revision_conflict"),
        "stale apply must be rejected: {text}"
    );

    // apply valid plan
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_mutation").with_arguments(
                json!({
                    "db": handle,
                    "action": "apply",
                    "operations": [
                        {"ea": "0x401100", "kind": "rename", "name": "helper_planned"},
                        {"ea": "0x401000", "kind": "comment", "comment": "planned note"}
                    ]
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        )
        .await
        .expect("apply");
    let text = first_text(&resp);
    assert!(
        text.contains("\"applied\": 2") || text.contains("\"applied\":2"),
        "apply response: {text}"
    );
    assert!(
        text.contains("\"partial\": false"),
        "apply response: {text}"
    );

    // audit trail shows both ops
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_mutation").with_arguments(
                json!({"db": handle, "action": "audit"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("audit");
    let text = first_text(&resp);
    assert!(text.contains("rename"), "audit response: {text}");
    assert!(text.contains("comment"), "audit response: {text}");

    // snapshot -> mutate -> rollback restores the pre-mutation name
    let _ = client
        .call_tool(
            CallToolRequestParams::new("ida_mutation").with_arguments(
                json!({"db": handle, "action": "snapshot"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("snapshot");
    let _ = client
        .call_tool(
            CallToolRequestParams::new("ida_edit").with_arguments(
                json!({"db": handle, "ea": "0x401100", "rename": "after_snapshot"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("mutate after snapshot");
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_mutation").with_arguments(
                json!({"db": handle, "action": "rollback"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("rollback");
    let text = first_text(&resp);
    assert!(
        text.contains("\"restored\": true") || text.contains("\"restored\":true"),
        "rollback response: {text}"
    );
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_functions").with_arguments(
                json!({"db": handle, "limit": 50})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("functions after rollback");
    let text = first_text(&resp);
    assert!(
        text.contains("helper_planned"),
        "rollback must restore the planned name: {text}"
    );

    let _ = client.cancel().await;
    server_task.abort();
}

/// #20 resources + prompts end to end over MCP stdio (mock backend).
#[tokio::test]
async fn e2e_stdio_resources_prompts() {
    let _guard = DB_COUNTER_LOCK.lock().await;
    let (server_read, client_write) = duplex(64 * 1024);
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

    let client_info = ClientInfo::default();
    let client = rmcp::service::serve_client(client_info, (client_read, client_write))
        .await
        .expect("client init");

    // open a mock db so resources have a target
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
    let open_text = first_text(&resp);
    let handle: String = open_text
        .split("\"db\": \"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .unwrap_or("db1")
        .to_string();

    // list resource templates: the ida://db/{id}/... family
    let tpls = client
        .list_resource_templates(Default::default())
        .await
        .expect("list_resource_templates");
    let tpl_uris: Vec<String> = tpls
        .resource_templates
        .iter()
        .map(|t| t.uri_template.clone())
        .collect();
    assert!(
        tpl_uris.iter().any(|u| u.contains("/metadata")),
        "templates: {tpl_uris:?}"
    );
    assert!(tpl_uris.iter().any(|u| u.contains("/imports")));

    // read metadata + info resources for the open db
    for kind in ["metadata", "info", "segments"] {
        let result = client
            .read_resource(rmcp::model::ReadResourceRequestParams::new(format!(
                "ida://db/{handle}/{kind}"
            )))
            .await
            .unwrap_or_else(|e| panic!("read {kind}: {e}"));
        let text = result
            .contents
            .first()
            .map(|c| match c {
                rmcp::model::ResourceContents::TextResourceContents { text, .. } => text.clone(),
                _ => String::new(),
            })
            .unwrap_or_default();
        assert!(!text.is_empty(), "resource {kind} must have content");
    }

    // reading an unknown db handle yields a stable error
    let err = client
        .read_resource(rmcp::model::ReadResourceRequestParams::new(
            "ida://db/db99/metadata",
        ))
        .await;
    assert!(err.is_err(), "unknown db must fail");

    // list prompts: workflow hints exist
    let prompts = client
        .list_prompts(Default::default())
        .await
        .expect("list_prompts");
    let names: Vec<String> = prompts.prompts.iter().map(|p| p.name.to_string()).collect();
    assert!(
        names.contains(&"ida_survey_binary".to_string()),
        "prompts: {names:?}"
    );
    assert!(names.contains(&"ida_analyze_function_deep".to_string()));
    assert!(names.contains(&"ida_safe_refactor".to_string()));

    // get one prompt: returns instruction text
    let prompt = client
        .get_prompt(
            rmcp::model::GetPromptRequestParams::new("ida_analyze_function_deep").with_arguments(
                json!({"ea": "0x401200", "db": handle})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("get_prompt");
    let prompt_text = prompt
        .messages
        .first()
        .map(|m| match &m.content {
            rmcp::model::ContentBlock::Text(t) => t.text.clone(),
            _ => String::new(),
        })
        .unwrap_or_default();
    assert!(
        prompt_text.contains("0x401200") && prompt_text.contains("ida_decompile"),
        "prompt must embed the ea and workflow: {prompt_text}"
    );

    // ida_evidence: build + query over the mock backend
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_evidence").with_arguments(
                json!({"db": handle, "action": "build"})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("evidence build");
    let text = first_text(&resp);
    assert!(text.contains("\"functions\""), "build: {text}");

    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_evidence").with_arguments(
                json!({"db": handle, "query": {"all": [{"name_contains": "main"}]}})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .expect("evidence query");
    let text = first_text(&resp);
    assert!(
        text.contains("\"matched\""),
        "query must carry evidence: {text}"
    );

    // capabilities tool exposes discovery info
    let resp = client
        .call_tool(
            CallToolRequestParams::new("ida_capabilities")
                .with_arguments(json!({"db": handle}).as_object().unwrap().clone()),
        )
        .await
        .expect("capabilities");
    let text = first_text(&resp);
    assert!(text.contains("\"identity\""), "caps: {text}");
    assert!(text.contains("\"budgets\""), "caps: {text}");

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
