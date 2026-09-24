//! i71a+i71b: WASM crash-fix verification through the production path.
//! Opens the audit fixture (audit_minimal.wasm) via the real idalib
//! backend and exercises the methods that crashed the worker before the
//! br_if hardening (issue #71 audit finding).
//!
//! Run explicitly with IDADIR set:
//!   cargo test -p reverse-mcp --features idalib --test wasm_real -- --ignored --test-threads=1

use std::path::PathBuf;

use rmcp_broker::WorkerPool;

/// The IDA version the real-IDA suites request: the ABI this test binary
/// was compiled with (idalib94 -> 9.4, otherwise the 9.2 default). Strict
/// pin either way - no silent fallback to another version.
#[cfg(feature = "idalib94")]
const REQ_IDA_VERSION: &str = "9.4";
#[cfg(not(feature = "idalib94"))]
const REQ_IDA_VERSION: &str = "9.2";

use serde_json::json;

fn worker_exe() -> PathBuf {
    if let Ok(p) = std::env::var("REVERSE_MCP_WORKER_EXE") {
        return p.into();
    }
    let cur = std::env::current_exe().expect("current_exe");
    let mut dir = cur.parent().map(|d| d.to_path_buf());
    for _ in 0..4 {
        if let Some(d) = dir {
            let cand = d.join("reverse-mcp.exe");
            if cand.exists() {
                return cand;
            }
            dir = d.parent().map(|d| d.to_path_buf());
        }
    }
    panic!("no reverse-mcp.exe found; set REVERSE_MCP_WORKER_EXE");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn wasm_db_full_chain() {
    let _ = worker_exe();
    let mut pool = WorkerPool::new();
    if let Ok(ida) = std::env::var("IDADIR") {
        pool.set_ida_dir(PathBuf::from(ida));
    }

    // Scratch copy: never share a .i64 between runs.
    let dir = std::env::temp_dir().join(format!("rmcp-wasm-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let wasm = dir.join("audit_minimal.wasm");
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wasm/audit_minimal.wasm"),
        &wasm,
    )
    .expect("copy fixture");

    let h = pool
        .spawn_for(&wasm.to_string_lossy(), 2, "idalib", REQ_IDA_VERSION)
        .await
        .expect("idalib open of wasm fixture");
    let session = pool.session(&h).await.expect("session");

    // 1. Module structure through IDA's native WASM loader.
    let s = session.lock().await;
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 100}))
        .await
        .expect("functions");
    let arr = fns.as_array().expect("functions array");
    assert_eq!(arr.len(), 6, "audit fixture defines 6 functions");
    let names: Vec<&str> = arr.iter().filter_map(|f| f["name"].as_str()).collect();
    for want in ["add", "sub", "mul", "dispatch", "loopsum", "cond"] {
        assert!(
            names.iter().any(|n| n.contains(want)),
            "function '{want}' missing; got {names:?}"
        );
    }

    // 2. Segments map the wasm sections (type/code/elem/data...) - the
    // stable wasm-index <-> file-offset mapping base.
    let segs = s
        .call("segments", json!({"offset": 0, "limit": 50}))
        .await
        .expect("segments");
    let seg_names: Vec<String> = segs
        .as_array()
        .expect("segments array")
        .iter()
        .filter_map(|s| s["name"].as_str().map(|s| s.to_string()))
        .collect();
    for want in ["type", "code", "elem", "data"] {
        assert!(
            seg_names.iter().any(|n| n == want),
            "segment '{want}' missing; got {seg_names:?}"
        );
    }

    // 3. THE CRASHER: disassembly of loopsum (br_if <depth> inside).
    // Before the fix this killed the worker process.
    let disasm = s
        .call("disassemble", json!({"ea": "0xa9", "max": 40}))
        .await
        .expect("disassemble of loopsum (br_if) - worker must survive");
    let insns = disasm.as_array().expect("disasm array");
    assert!(!insns.is_empty());
    let texts: Vec<String> = insns
        .iter()
        .filter_map(|i| i["text"].as_str().map(|t| t.to_string()))
        .collect();
    assert!(
        texts.iter().any(|t| t.starts_with("br_if")),
        "br_if must appear in the rendered walk: {texts:?}"
    );

    // 4. Whole-function CFG with br_if branches (also crashed pre-fix).
    let graph = s
        .call("graph", json!({"ea": "0xa9", "kind": "cfg"}))
        .await
        .expect("cfg of loopsum");
    assert!(graph["nodes"].as_array().unwrap().len() >= 4);

    // 5. Worker still healthy; protocol channel intact.
    let info = s.call("db.info", json!({})).await.expect("db.info after");
    assert_eq!(info["function_count"].as_u64(), Some(6));
    drop(s);

    let _ = pool.close(&h).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn wasm_ida_wasm_tool_actions() {
    // ida_wasm through the real registry: fused parser + IDA facts.
    use rmcp_broker::Broker;
    let _ = worker_exe();
    let config = rmcp_core::config::Config {
        max_workers: 2,
        ..Default::default()
    };
    let broker = Broker::new(config);
    if let Ok(ida) = std::env::var("IDADIR") {
        broker.pool.lock().await.set_ida_dir(PathBuf::from(ida));
    }

    let dir = std::env::temp_dir().join(format!("rmcp-wasm-tool-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let wasm = dir.join("audit_minimal.wasm");
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wasm/audit_minimal.wasm"),
        &wasm,
    )
    .expect("copy fixture");

    let open = rmcp_broker::registry::call(
        &broker,
        "ida_db",
        json!({"action": "open", "path": wasm.to_string_lossy(), "backend": "idalib", "ida_version": REQ_IDA_VERSION}),
    )
    .await
    .expect("open wasm via idalib");
    let handle = open["db"].as_str().expect("db handle").to_string();

    // info: cross-engine checks must confirm on the fixture.
    let info =
        rmcp_broker::registry::call(&broker, "ida_wasm", json!({"db": handle, "action": "info"}))
            .await
            .expect("ida_wasm info");
    let w = &info["wasm"];
    let payload = if w["result"].is_object() {
        &w["result"]
    } else {
        w
    };
    assert_eq!(
        payload["cross_check"]["function_count_confirmed"],
        json!(true)
    );
    assert_eq!(
        payload["cross_check"]["code_offset_mapping"],
        json!("confirmed")
    );
    assert!(
        payload["features"].is_object(),
        "feature map must be present"
    );
    assert!(
        payload["hexrays"]
            .as_str()
            .unwrap_or("")
            .contains("unavailable"),
        "Hex-Rays must be reported honestly as unavailable"
    );

    // functions: fused rows with per-row provenance.
    let fns = rmcp_broker::registry::call(
        &broker,
        "ida_wasm",
        json!({"db": handle, "action": "functions"}),
    )
    .await
    .expect("ida_wasm functions");
    let fw = &fns["wasm"];
    let fp = if fw["result"].is_object() {
        &fw["result"]
    } else {
        fw
    };
    let rows = fp["functions"].as_array().expect("function rows");
    assert_eq!(rows.len(), 6);
    let add_row = rows
        .iter()
        .find(|r| {
            r["ida_name"]
                .as_str()
                .map(|n| n.contains("add"))
                .unwrap_or(false)
                || r["name_parser"]
                    .as_str()
                    .map(|n| n.contains("add"))
                    .unwrap_or(false)
        })
        .expect("add function row");
    assert!(
        add_row["wasm_index"].is_u64(),
        "each row carries the wasm index space id"
    );

    // cfg: structured control flow for loopsum (has loop + br_if).
    let cfg = rmcp_broker::registry::call(
        &broker,
        "ida_wasm",
        json!({"db": handle, "action": "cfg", "index": "4"}),
    )
    .await
    .expect("ida_wasm cfg");
    let cw = &cfg["wasm"];
    let cp = if cw["result"].is_object() {
        &cw["result"]
    } else {
        cw
    };
    assert!(
        cp["regions"]
            .as_array()
            .map(|r| !r.is_empty())
            .unwrap_or(false),
        "structured CFG regions must be present: {cp}"
    );

    // pseudocode: deterministic renderer runs and is labeled non-Hex-Rays.
    let pseudo = rmcp_broker::registry::call(
        &broker,
        "ida_wasm",
        json!({"db": handle, "action": "pseudocode", "index": "0"}),
    )
    .await
    .expect("ida_wasm pseudocode");
    let pw = &pseudo["wasm"];
    let pp = if pw["result"].is_object() {
        &pw["result"]
    } else {
        pw
    };
    assert!(
        pp["engine"].as_str().unwrap_or("").contains("NOT Hex-Rays"),
        "pseudocode must be labeled as not Hex-Rays"
    );
    assert!(!pp["pseudocode"].as_str().unwrap_or("").is_empty());

    // indirect_targets: bounded evidence-based resolution on dispatch.
    let indirect = rmcp_broker::registry::call(
        &broker,
        "ida_wasm",
        json!({"db": handle, "action": "indirect_targets", "index": "3"}),
    )
    .await
    .expect("ida_wasm indirect_targets");
    let iw = &indirect["wasm"];
    let ip = if iw["result"].is_object() {
        &iw["result"]
    } else {
        iw
    };
    assert!(ip.is_array(), "indirect target list must be an array: {ip}");

    // Malformed module fails locally with a bounded diagnostic, not a crash.
    // The IDA loader itself refuses truncated modules (open fails) - that is
    // the bounded, local failure the issue requires. Either an open error or
    // a parse error is acceptable; neither may crash the broker.
    let bad = dir.join("bad.wasm");
    std::fs::write(&bad, b"\0asm\x01\x00\x00\x00\xff\xff\xff").expect("write bad");
    let open_bad = rmcp_broker::registry::call(
        &broker,
        "ida_db",
        json!({"action": "open", "path": bad.to_string_lossy(), "backend": "idalib", "ida_version": REQ_IDA_VERSION}),
    )
    .await;
    let bad_handle = match open_bad {
        Ok(v) => v["db"].as_str().expect("bad db handle").to_string(),
        Err(_) => {
            // Loader rejected it locally: acceptable bounded failure.
            let _ = rmcp_broker::registry::call(
                &broker,
                "ida_db",
                json!({"action": "close", "db": handle}),
            )
            .await;
            return;
        }
    };
    let r = rmcp_broker::registry::call(
        &broker,
        "ida_wasm",
        json!({"db": bad_handle, "action": "info"}),
    )
    .await;
    match r {
        Err(e) => assert!(
            e.to_string().contains("wasm_parse") || e.to_string().contains("parse"),
            "malformed module must fail with a bounded parse diagnostic, got: {e}"
        ),
        Ok(v) => {
            // If the loader salvaged something the parser still must not
            // hang/crash; any structured answer is acceptable.
            assert!(v.is_object(), "malformed module answered non-object: {v}");
        }
    }

    let _ =
        rmcp_broker::registry::call(&broker, "ida_db", json!({"action": "close", "db": handle}))
            .await;
    let _ = rmcp_broker::registry::call(
        &broker,
        "ida_db",
        json!({"action": "close", "db": bad_handle}),
    )
    .await;
}
