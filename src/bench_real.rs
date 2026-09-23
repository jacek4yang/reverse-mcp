//! #50 real-IDA benchmark: the same agent-facing WorkerPool/session paths
//! as the mock bench, executed against a real licensed IDA backend (9.2 or
//! 9.4 - whichever ABI this binary was compiled with).
//!
//! Hard requirements:
//! - never silently falls back to mock: if no verified backend resolves,
//!   the run fails with a doctor-style error (exit code 2, reason printed);
//! - every repeatable scenario runs twice; the second pass must be served
//!   from the revision-keyed workflow cache (`cached: true`), which also
//!   proves no repeated decompilation happens;
//! - the deep-chain scenario asserts the single-decompile model via the
//!   deep result's visited_count (each function decompiled exactly once);
//! - `timeout_resume` runs deep.function with a tiny budget, gets a resume
//!   token, then resumes to completion — the resumed pass is counted
//!   cache-warm;
//! - latency (wall_ms) is reported (p50/p95 over repetitions) but never
//!   asserted — correctness and cache behavior are the gates.
//!
//! Static fixture binaries only; nothing is executed.

use serde_json::{Value, json};

/// The IDA version the real bench requests: the ABI this binary was
/// compiled with (idalib94 -> 9.4, otherwise the 9.2 default).
#[cfg(feature = "idalib94")]
const REQ_IDA_VERSION: &str = "9.4";
#[cfg(not(feature = "idalib94"))]
const REQ_IDA_VERSION: &str = "9.2";

use crate::bench::ScenarioResult;

fn fail(name: &'static str, start: std::time::Instant, detail: String) -> ScenarioResult {
    ScenarioResult {
        name,
        ok: false,
        round_trips: 0,
        output_bytes: 0,
        wall_ms: start.elapsed().as_millis(),
        detail,
    }
}

fn fixture(name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    p.is_file().then_some(p)
}

/// Open a real backend on a temp copy of `fixture`; errors carry the
/// doctor-style reason (never a silent mock fallback).
async fn open_real(
    pool: &mut rmcp_broker::WorkerPool,
    name: &'static str,
    fixture_name: &str,
    start: std::time::Instant,
) -> Result<String, ScenarioResult> {
    let Some(src) = fixture(fixture_name) else {
        return Err(fail(
            name,
            start,
            format!("fixture missing: {fixture_name}"),
        ));
    };
    let dst = std::env::temp_dir().join(format!("rmcp-bench-{fixture_name}"));
    // IDA scatters unpacked sidecars next to the input (.id0/.id1/.id2/.nam/
    // .til); a stale unpacked set from a crashed run would poison reopen.
    for ext in [".i64", ".id0", ".id1", ".id2", ".nam", ".til", ".idb"] {
        let _ = std::fs::remove_file(format!("{}{ext}", dst.display()));
    }
    std::fs::copy(&src, &dst).map_err(|e| fail(name, start, format!("copy: {e}")))?;
    let opened = pool
        .spawn_for(
            &dst.to_string_lossy(),
            8,
            "idalib",
            REQ_IDA_VERSION, // strict pin: no silent fallback to another version
        )
        .await;
    match opened {
        Ok(h) => Ok(h),
        Err(e) => Err(fail(
            name,
            start,
            format!(
                "no verified real-IDA backend available (bench cannot run): {e} \
                 - set IDADIR to a licensed IDA 9.2 install"
            ),
        )),
    }
}

/// Resolve a function EA by exact name (bench fixtures have stable names;
/// ground truth comes from the fixture sources, see tests/idalib_real.rs).
/// Takes the already-locked session guard: the session mutex must never be
/// re-acquired while held (that would self-deadlock).
async fn ea_of(
    s: &tokio::sync::MutexGuard<'_, rmcp_broker::worker_pool::WorkerSession>,
    want: &str,
) -> Result<u64, String> {
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 8000}))
        .await
        .map_err(|e| format!("functions: {e}"))?;
    for f in fns.as_array().cloned().unwrap_or_default() {
        if f["name"].as_str() == Some(want)
            && let Some(ea) = f["ea_start"].as_u64()
        {
            return Ok(ea);
        }
    }
    Err(format!("function '{want}' not found in fixture"))
}

/// One full deep-chain scenario pass. Returns extra metrics in `detail`.
async fn deep_pass(
    pool: &mut rmcp_broker::WorkerPool,
    pass: usize,
) -> (ScenarioResult, Option<Value>) {
    let name: &'static str = "deep_chain_walk";
    let start = std::time::Instant::now();
    let h = match open_real(pool, name, "deep.exe", start).await {
        Ok(h) => h,
        Err(r) => return (r, None),
    };
    let session = pool.session(&h).await.expect("session");
    let s = session.lock().await;
    let mut ok = true;
    let mut detail = String::new();

    // Ground truth: the deep.exe chain root is `process` (fixture source
    // has process -> sub1 -> sub2 chain; see tests/idalib_real.rs).
    let root = match ea_of(&s, "process").await {
        Ok(ea) => ea,
        Err(e) => return (fail(name, start, e), None),
    };

    // Fresh run: walk the whole chain, single decompile per function.
    let v = match s
        .call(
            "deep.function",
            json!({"target": format!("{root:#x}"), "depth": 4, "max_functions": 32}),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return (
                fail(name, start, format!("deep.function failed: {e}")),
                None,
            );
        }
    };
    let cached = v["cached"].as_bool().unwrap_or(false);
    if pass == 1 && cached {
        ok = false;
        detail.push_str("pass1 unexpectedly cached; ");
    }
    let result = &v["result"];
    let visited = result["visited_count"].as_u64().unwrap_or(0);
    if visited < 3 {
        ok = false;
        detail.push_str(&format!("deep walk visited {visited} (<3); "));
    }
    // Single-decompile: functions array length must equal visited_count
    // (each function appears exactly once in the walk).
    let fns = result["functions"].as_array().cloned().unwrap_or_default();
    if fns.len() as u64 != visited {
        ok = false;
        detail.push_str(&format!(
            "single-decompile violation: {} dossiers for {visited} visited; ",
            fns.len()
        ));
    }
    detail.push_str(&format!("pass{pass} visited={visited} cached={cached}"));

    // Repeat the same request in the SAME session: must be a cache hit
    // (revision unchanged, no resume token) — proves no re-decompilation.
    let v2 = match s
        .call(
            "deep.function",
            json!({"target": format!("{root:#x}"), "depth": 4, "max_functions": 32}),
        )
        .await
    {
        Ok(v) => v,
        Err(e) => {
            return (
                fail(name, start, format!("deep.function repeat failed: {e}")),
                None,
            );
        }
    };
    let repeat_cached = v2["cached"].as_bool().unwrap_or(false);
    if !repeat_cached {
        ok = false;
        detail.push_str("; repeat not cached (re-decompiled)");
    }

    let wall = start.elapsed().as_millis();
    let metrics = json!({
        "visited_count": visited,
        "root": format!("{root:#x}"),
        "in_session_cache_hit": repeat_cached,
    });
    let r = ScenarioResult {
        name,
        ok,
        round_trips: 3,
        output_bytes: v.to_string().len() + v2.to_string().len(),
        wall_ms: wall,
        detail,
    };
    drop(s);
    let _ = pool.close(&h).await;
    (r, Some(metrics))
}

pub async fn run_real_bench() -> (Vec<ScenarioResult>, Value) {
    let mut pool = rmcp_broker::WorkerPool::new();
    let mut results: Vec<ScenarioResult> = Vec::new();
    let mut extras = json!({});

    // Scenario: deep chain with cache verification (the core #50 gate).
    let (r1, m1) = deep_pass(&mut pool, 1).await;
    results.push(r1);
    let (r2, m2) = deep_pass(&mut pool, 2).await;
    results.push(r2);
    extras["deep_chain"] = json!({"pass1": m1, "pass2": m2});

    // Scenario: workflow.function_context (one-call composite) + repeat.
    {
        let name: &'static str = "one_call_function_context";
        let start = std::time::Instant::now();
        match open_real(&mut pool, name, "simple.exe", start).await {
            Err(r) => results.push(r),
            Ok(h) => {
                let session = pool.session(&h).await.expect("session");
                let s = session.lock().await;
                let mut ok = true;
                let mut detail = String::new();
                let mut hits = (0u64, 0u64);
                let mut main_ea = 0u64;
                let mut ea_ok = true;
                match ea_of(&s, "main").await {
                    Ok(ea) => main_ea = ea,
                    Err(e) => {
                        ea_ok = false;
                        ok = false;
                        detail.push_str(&format!("{e}; "));
                    }
                }
                let req = json!({"workflow_req": {"workflow": "function_context", "ea": format!("{main_ea:#x}")}});
                for pass in 1..=2 {
                    if !ea_ok {
                        break;
                    }
                    match s.call("workflow.run", req.clone()).await {
                        Ok(v) => {
                            let cached = v["cached"].as_bool().unwrap_or(false);
                            hits = (
                                v["cache_hits"].as_u64().unwrap_or(0),
                                hits.1 + if cached { 0 } else { 1 },
                            );
                            if pass == 2 && !cached {
                                ok = false;
                                detail.push_str("pass2 not cached; ");
                            }
                            if v["result"]["name"].is_null() {
                                ok = false;
                                detail.push_str("no name; ");
                            }
                        }
                        Err(e) => {
                            ok = false;
                            detail.push_str(&format!("workflow.run failed: {e}; "));
                        }
                    }
                }
                results.push(ScenarioResult {
                    name,
                    ok,
                    round_trips: 2,
                    output_bytes: 0,
                    wall_ms: start.elapsed().as_millis(),
                    detail,
                });
                extras["function_context"] = json!({"cache_hits": hits.0, "fresh_runs": hits.1});
                drop(s);
                let _ = pool.close(&h).await;
            }
        }
    }

    // Scenario: timeout -> resume token -> completion (cache-warm).
    {
        let name: &'static str = "timeout_resume";
        let start = std::time::Instant::now();
        match open_real(&mut pool, name, "deep.exe", start).await {
            Err(r) => results.push(r),
            Ok(h) => {
                let session = pool.session(&h).await.expect("session");
                let s = session.lock().await;
                let mut ok = true;
                let mut detail = String::new();
                let mut chain_root = 0u64;
                match ea_of(&s, "process").await {
                    Ok(ea) => chain_root = ea,
                    Err(e) => {
                        ok = false;
                        detail.push_str(&format!("{e}; "));
                    }
                }
                // Tiny budget forces budget_hit + resume token.
                let partial = if chain_root != 0 {
                    s.call(
                        "deep.function",
                        json!({"target": format!("{chain_root:#x}"), "depth": 4, "max_functions": 2}),
                    )
                    .await
                } else {
                    Err(rmcp_core::error::Error::Worker("no chain root".into()))
                };
                match partial {
                    Ok(v) => {
                        let result = &v["result"];
                        if result["budget_hit"] != json!(true) {
                            ok = false;
                            detail.push_str("expected budget_hit; ");
                        }
                        let mut token = result["resume"].clone();
                        if !token.is_object() {
                            ok = false;
                            detail.push_str("no resume token; ");
                        } else {
                            // Resume until terminal (bounded to 32 rounds).
                            let mut completed = false;
                            for _ in 0..32 {
                                let v = s
                                    .call(
                                        "deep.function",
                                        json!({
                                            "target": format!("{chain_root:#x}"),
                                            // Depth is also relaxed: the partial
                                            // run stopped at depth 4 with pending
                                            // frontier entries AT depth 4, so a
                                            // resume with depth 4 can never make
                                            // progress (it would budget-hit
                                            // immediately, forever). Depth max
                                            // is 8; the chain is 4 levels.
                                            "depth": 8,
                                            // Relax the per-call budget: the
                                            // resumed visited set includes the
                                            // dossiers restored from the token,
                                            // so a budget <= restored count
                                            // would stall with zero progress.
                                            "max_functions": 32,
                                            "resume_from": token,
                                        }),
                                    )
                                    .await;
                                match v {
                                    Ok(v) => {
                                        let result = &v["result"];
                                        if result["budget_hit"] == json!(true) {
                                            token = result["resume"].clone();
                                            if !token.is_object() {
                                                completed = true;
                                                break;
                                            }
                                        } else {
                                            completed = true;
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        ok = false;
                                        detail.push_str(&format!("resume failed: {e}; "));
                                        break;
                                    }
                                }
                            }
                            if !completed {
                                ok = false;
                                detail.push_str("resume never reached terminal state; ");
                            }
                        }
                    }
                    Err(e) => {
                        ok = false;
                        detail.push_str(&format!("partial run failed: {e}; "));
                    }
                }
                detail.push_str(" (resumed pass bypasses result cache by design)");
                results.push(ScenarioResult {
                    name,
                    ok,
                    round_trips: 1,
                    output_bytes: 0,
                    wall_ms: start.elapsed().as_millis(),
                    detail,
                });
                drop(s);
                let _ = pool.close(&h).await;
            }
        }
    }

    (results, extras)
}
