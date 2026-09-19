//! #72 real-IDA gate: hierarchical large-function analysis end to end on
//! the giant fixture (giant_switch_3000.dll: one 185k-byte function with
//! ~3000 basic blocks - a size the whole-function Hex-Rays path refuses
//! with `too big function` / `function frame is wrong`).
//!
//! Verifies the issue's acceptance criteria against the production path
//! (real Broker, real registry dispatch, disposable isolation workers):
//!   1. workflow=function_hierarchical classifies the giant WITHOUT
//!      Hex-Rays and reports real complexity facts;
//!   2. the overview carries per-region outcomes through disposable
//!      isolation workers - the primary session stays healthy afterwards;
//!   3. per-region evidence never blocks on Hex-Rays (raw-IDA fallback);
//!   4. workflow=function_region drills into one region;
//!   5. a NORMAL control function keeps the unchanged whole-function path;
//!   6. no worker processes leak (leak line).
//!
//! Run explicitly with IDADIR pointing at a licensed IDA 9.x:
//!   cargo test -p reverse-mcp --features idalib --test largefn_real -- --ignored --test-threads=1

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rmcp_broker::Broker;
use serde_json::json;

fn worker_exe() -> PathBuf {
    if let Ok(p) = std::env::var("REVERSE_MCP_WORKER_EXE") {
        return p.into();
    }
    // The combined exe in target/{debug,release} answers the worker probe;
    // walk upward from the test binary (deps dir) to find it.
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

fn count_our_worker_processes() -> usize {
    let want = worker_exe().to_string_lossy().to_lowercase();
    let out = std::process::Command::new(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    )
    .args([
        "-NoProfile",
        "-Command",
        "Get-CimInstance Win32_Process -Filter \"Name='reverse-mcp.exe'\" | Select-Object ExecutablePath | ConvertTo-Json -Compress",
    ])
    .output()
    .expect("powershell probe");
    String::from_utf8_lossy(&out.stdout).matches(&want).count()
}

async fn make_broker() -> Arc<Broker> {
    let mut config = rmcp_core::config::Config::default();
    config.max_workers = 4;
    let broker = Broker::new(config);
    if let Ok(ida_dir) = std::env::var("IDADIR") {
        broker.pool.lock().await.set_ida_dir(PathBuf::from(ida_dir));
    }
    broker
}

async fn open_db(broker: &Broker, src_name: &str) -> (String, PathBuf) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/largefn")
        .join(src_name);
    // Copy to a scratch path so parallel runs never share one .i64.
    let dst = std::env::temp_dir().join(format!("rmcp-largefn-{}-{src_name}", std::process::id()));
    std::fs::copy(&src, &dst).expect("copy fixture");
    let out = rmcp_broker::registry::call(
        broker,
        "ida_db",
        json!({"action": "open", "path": dst.to_string_lossy(), "backend": "idalib"}),
    )
    .await
    .expect("idalib open");
    let handle = out["db"].as_str().expect("db handle").to_string();
    (handle, dst)
}

fn giant_ea() -> u64 {
    // giant_switch_3000's dispatcher function; audit-verified address.
    0x180001000
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn hierarchical_overview_on_giant_function() {
    let before_procs = count_our_worker_processes();
    let broker = make_broker().await;
    let (handle, _dst) = open_db(&broker, "giant_switch_3000.dll").await;

    // 1+2. Hierarchical overview through the registry (production dispatch).
    // Bounded so a regression cannot hang CI: 4 regions x 60s hard timeout.
    let overview = rmcp_broker::registry::call(
        &broker,
        "ida_analyze",
        json!({
            "db": handle,
            "workflow": "function_hierarchical",
            "ea": format!("{:#x}", giant_ea()),
            "max_regions": 4,
            "hard_timeout_ms": 60_000,
        }),
    )
    .await
    .expect("hierarchical overview");

    let a = &overview["analysis"];
    let spilled;
    let payload = if a["result"].is_object() {
        a
    } else if a["result_ref"].is_string() {
        // Spilled to the result store: fetch the full payload (stored as
        // the analysis object itself).
        spilled = broker
            .store
            .get(a["result_ref"].as_str().unwrap())
            .expect("fetch spilled overview");
        &spilled
    } else {
        a
    };
    let mode = payload["mode"]
        .as_str()
        .unwrap_or_else(|| panic!("overview payload has no mode; payload: {payload:#?}"));
    assert!(
        mode == "large_region" || mode == "pathological",
        "giant must classify as large/pathological, got {mode}"
    );
    let complexity = &payload["complexity"];
    let blocks = complexity["blocks"].as_u64().expect("blocks");
    assert!(blocks >= 2500, "expected ~3000 blocks, got {blocks}");

    let regions = payload["important_regions"]
        .as_array()
        .expect("regions array");
    assert!(!regions.is_empty(), "at least one region outcome");
    // Every region must produce a usable outcome: complete (isolation worker
    // answered) or partial_fallback_raw (structured Hex-Rays failure with
    // raw-IDA degradation). Never a silent drop.
    for r in regions {
        let status = r["status"].as_str().unwrap_or("MISSING");
        assert!(
            matches!(status, "complete" | "partial_fallback_raw"),
            "region {} status {status} is not usable evidence: {r}",
            r["region_id"]
        );
    }
    assert_eq!(
        payload["analysis_status"].as_str(),
        Some("complete"),
        "all requested regions must be analyzed"
    );
    // Resumable frontier present (cross-region dataflow contract).
    assert!(payload["resume"]["frontier"].is_array());

    // 3. Primary session must be healthy after disposable workers ran.
    {
        let pool = broker.pool.lock().await;
        let session = pool.session(&handle).await.expect("session");
        let s = session.lock().await;
        assert_eq!(
            s.health(),
            rmcp_broker::recovery::WorkerHealth::Healthy,
            "primary session must survive the isolation layer"
        );
        let probe = s
            .call("db.info", json!({}))
            .await
            .expect("primary session still responsive after isolation runs");
        assert!(probe["function_count"].as_u64().unwrap_or(0) >= 1);
    }

    // 4. Region drill-in: first region from the overview.
    let region_id = regions[0]["region_id"]
        .as_str()
        .expect("region_id")
        .to_string();
    let drill_spilled;
    let drill = rmcp_broker::registry::call(
        &broker,
        "ida_analyze",
        json!({
            "db": handle,
            "workflow": "function_region",
            "ea": format!("{:#x}", giant_ea()),
            "region_id": region_id,
            "hard_timeout_ms": 60_000,
            "max_insns": 400,
        }),
    )
    .await
    .expect("region drill-in");
    let d = &drill["region"];
    let dp = if d["result"].is_object() {
        &d["result"]
    } else if d["result_ref"].is_string() {
        // Spilled to the result store: fetch the full payload.
        drill_spilled = broker
            .store
            .get(d["result_ref"].as_str().unwrap())
            .expect("fetch spilled drill-in");
        &drill_spilled
    } else {
        d
    };
    assert_eq!(dp["region_id"].as_str(), Some(region_id.as_str()));
    let disasm = dp["disassembly"]
        .as_array()
        .or_else(|| dp["disassembly"]["insns"].as_array())
        .or_else(|| dp["disassembly"]["result"]["insns"].as_array());
    assert!(
        disasm.map(|a| !a.is_empty()).unwrap_or(false),
        "drill-in must carry a disassembly window: {dp}"
    );

    // 5. Normal control: a small function keeps the whole-function path.
    let fns = {
        let pool = broker.pool.lock().await;
        let session = pool.session(&handle).await.expect("session");
        let s = session.lock().await;
        s.call("functions", json!({"offset": 0, "limit": 200}))
            .await
            .expect("functions")
    };
    let small = fns
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|f| {
                    let sz = f["size"].as_u64().unwrap_or(u64::MAX);
                    let ea = f["ea_start"].as_u64().unwrap_or(0);
                    sz > 0 && sz < 4096 && ea != giant_ea()
                })
                .cloned()
        })
        .expect("a small control function");
    let control_ea = small["ea_start"].as_u64().unwrap();
    let control = rmcp_broker::registry::call(
        &broker,
        "ida_analyze",
        json!({
            "db": handle,
            "workflow": "function_hierarchical",
            "ea": format!("{control_ea:#x}"),
        }),
    )
    .await
    .expect("control analysis");
    let ca = &control["analysis"];
    let cmode = control["mode"]
        .as_str()
        .or_else(|| ca["mode"].as_str())
        .or_else(|| ca["result"]["mode"].as_str());
    assert_eq!(
        cmode,
        Some("normal"),
        "small function must keep the unchanged whole-function path"
    );

    // 6. Leak line: zero of our worker processes left behind.
    let _ =
        rmcp_broker::registry::call(&broker, "ida_db", json!({"action": "close", "db": handle}))
            .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let after = count_our_worker_processes();
    assert_eq!(
        after, before_procs,
        "worker processes leaked: before={before_procs} after={after}"
    );
}
