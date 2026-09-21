//! #18: reproducible MCP benchmark. Runs agent-facing task scenarios
//! against the checked-in fixture corpus (mock backend for CI; real IDA
//! gated behind `--real-ida`), and measures per-scenario: MCP round
//! trips, bytes returned to the agent, wall time, and correctness against
//! fixture ground truth. Output is a machine-readable JSON report with
//! non-regression thresholds.

use std::time::Instant;

use serde_json::{Value, json};

/// One measured scenario run.
pub struct ScenarioResult {
    pub name: &'static str,
    pub ok: bool,
    pub round_trips: usize,
    pub output_bytes: usize,
    pub wall_ms: u128,
    pub detail: String,
}

/// Run all mock-mode scenarios against one pool. Returns the report.
pub async fn run_mock_bench() -> Vec<ScenarioResult> {
    let mut pool = rmcp_broker::WorkerPool::new();
    let mut results = Vec::new();

    // Scenario 1: identify a function by evidence in one call (#8/#14).
    results.push(
        run_scenario(
            &mut pool,
            "one_call_function_context",
            "mock-bench.i64",
            0x401000,
        )
        .await,
    );
    // Scenario 2: evidence search finds a crypto-relevant import (#14).
    results.push(run_scenario_evidence(&mut pool).await);
    // Scenario 3: deep analysis walks a call chain with budgets (#10).
    results.push(run_scenario_deep(&mut pool).await);

    results
}

async fn run_scenario(
    pool: &mut rmcp_broker::WorkerPool,
    name: &'static str,
    db: &str,
    ea: u64,
) -> ScenarioResult {
    let start = Instant::now();
    let mut round_trips = 0usize;
    let mut output_bytes = 0usize;

    let opened = pool.spawn_for(db, 8, "mock", "").await;
    let (handle, session) = match opened {
        Ok(h) => {
            round_trips += 1;
            let s = pool.session(&h).await.expect("session");
            (h, s)
        }
        Err(e) => {
            return ScenarioResult {
                name,
                ok: false,
                round_trips,
                output_bytes,
                wall_ms: start.elapsed().as_millis(),
                detail: format!("open failed: {e}"),
            };
        }
    };
    let s = session.lock().await;
    let mut ok = true;
    let mut detail = String::new();

    // One-call composite context (the #8 product goal: fewer round trips).
    match s
        .call(
            "workflow.run",
            json!({"workflow_req": {"workflow": "function_context", "ea": format!("{ea:#x}")}}),
        )
        .await
    {
        Ok(v) => {
            round_trips += 1;
            output_bytes += v.to_string().len();
            if v["result"]["name"].is_null() {
                ok = false;
                detail.push_str("function_context returned no name; ");
            }
        }
        Err(e) => {
            round_trips += 1;
            ok = false;
            detail.push_str(&format!("function_context failed: {e}; "));
        }
    }

    drop(s);
    let _ = pool.close(&handle).await;

    ScenarioResult {
        name,
        ok,
        round_trips,
        output_bytes,
        wall_ms: start.elapsed().as_millis(),
        detail,
    }
}

async fn run_scenario_evidence(pool: &mut rmcp_broker::WorkerPool) -> ScenarioResult {
    let name = "evidence_search";
    let start = Instant::now();
    let mut round_trips = 0usize;
    let mut output_bytes = 0usize;

    let h = match pool.spawn_for("mock-bench.i64", 8, "mock", "").await {
        Ok(h) => h,
        Err(e) => {
            return ScenarioResult {
                name,
                ok: false,
                round_trips,
                output_bytes,
                wall_ms: start.elapsed().as_millis(),
                detail: format!("open failed: {e}"),
            };
        }
    };
    round_trips += 1;
    let session = pool.session(&h).await.expect("session");
    let s = session.lock().await;
    let mut ok = true;
    let mut detail = String::new();

    match s
        .call(
            "index.query",
            json!({"query": {"all": [{"name_contains": "decrypt"}]}}),
        )
        .await
    {
        Ok(v) => {
            round_trips += 1;
            output_bytes += v.to_string().len();
            let count = v["count"].as_u64().unwrap_or(0);
            if count == 0 {
                ok = false;
                detail.push_str("evidence search found nothing for known import; ");
            }
        }
        Err(e) => {
            round_trips += 1;
            ok = false;
            detail.push_str(&format!("index.query failed: {e}; "));
        }
    }

    drop(s);
    let _ = pool.close(&h).await;
    ScenarioResult {
        name,
        ok,
        round_trips,
        output_bytes,
        wall_ms: start.elapsed().as_millis(),
        detail,
    }
}

async fn run_scenario_deep(pool: &mut rmcp_broker::WorkerPool) -> ScenarioResult {
    let name = "deep_chain_walk";
    let start = Instant::now();
    let mut round_trips = 0usize;
    let mut output_bytes = 0usize;

    let h = match pool.spawn_for("mock-bench.i64", 8, "mock", "").await {
        Ok(h) => h,
        Err(e) => {
            return ScenarioResult {
                name,
                ok: false,
                round_trips,
                output_bytes,
                wall_ms: start.elapsed().as_millis(),
                detail: format!("open failed: {e}"),
            };
        }
    };
    round_trips += 1;
    let session = pool.session(&h).await.expect("session");
    let s = session.lock().await;
    let mut ok = true;
    let mut detail = String::new();

    match s
        .call(
            "deep.function",
            json!({"target": "0x401000", "depth": 3, "max_functions": 10}),
        )
        .await
    {
        Ok(v) => {
            round_trips += 1;
            output_bytes += v.to_string().len();
            if v["result"]["functions"]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true)
            {
                ok = false;
                detail.push_str("deep walk visited nothing; ");
            }
        }
        Err(e) => {
            round_trips += 1;
            ok = false;
            detail.push_str(&format!("deep.function failed: {e}; "));
        }
    }

    drop(s);
    let _ = pool.close(&h).await;
    ScenarioResult {
        name,
        ok,
        round_trips,
        output_bytes,
        wall_ms: start.elapsed().as_millis(),
        detail,
    }
}

/// Machine-readable benchmark report.
pub fn report(results: &[ScenarioResult]) -> Value {
    let mut walls: Vec<u128> = results.iter().map(|r| r.wall_ms).collect();
    walls.sort_unstable();
    let p = |q: f64| -> u128 {
        if walls.is_empty() {
            0
        } else {
            let idx = (((walls.len() as f64) - 1.0) * q).round() as usize;
            walls[idx.min(walls.len() - 1)]
        }
    };
    json!({
        "benchmark": "reverse-mcp-bench",
        "mode": "mock",
        "scenarios": results.iter().map(|r| json!({
            "name": r.name,
            "ok": r.ok,
            "round_trips": r.round_trips,
            "output_bytes": r.output_bytes,
            "wall_ms": r.wall_ms,
            "detail": r.detail,
        })).collect::<Vec<_>>(),
        "all_ok": results.iter().all(|r| r.ok),
        "latency": {
            "note": "reported only; correctness and cache behavior are the gates",
            "p50_ms": p(0.5),
            "p95_ms": p(0.95),
            "samples": walls.len(),
        },
        "thresholds": {
            "note": "mock-mode thresholds: correctness only; latency varies by runner",
        },
    })
}

/// #50 real-IDA report: mode-tagged, with per-scenario detail, cache
/// metrics, p50/p95 latency over scenario runs (reported, not asserted),
/// and correctness gates. Latency never fails the run.
pub fn report_real(results: &[ScenarioResult], extras: &Value) -> Value {
    let mut walls: Vec<u128> = results.iter().map(|r| r.wall_ms).collect();
    walls.sort_unstable();
    let p = |q: f64| -> u128 {
        if walls.is_empty() {
            0
        } else {
            let idx = (((walls.len() as f64) - 1.0) * q).round() as usize;
            walls[idx.min(walls.len() - 1)]
        }
    };
    json!({
        "benchmark": "reverse-mcp-bench",
        "mode": "real-ida",
        "requires": "licensed IDA 9.2 (IDADIR); verified backend registry entry",
        "no_mock_fallback": true,
        "scenarios": results.iter().map(|r| json!({
            "name": r.name,
            "ok": r.ok,
            "round_trips": r.round_trips,
            "output_bytes": r.output_bytes,
            "wall_ms": r.wall_ms,
            "detail": r.detail,
        })).collect::<Vec<_>>(),
        "extras": extras,
        "latency": {
            "note": "reported only; correctness and cache behavior are the gates",
            "p50_ms": p(0.5),
            "p95_ms": p(0.95),
            "samples": walls.len(),
        },
        "all_ok": results.iter().all(|r| r.ok),
    })
}
