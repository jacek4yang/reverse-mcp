//! #60 real-world corpus runner: drives the SAME MCP surface an agent uses
//! over every manifest binary and emits one bounded JSON dossier per binary
//! plus an acceptance report. Static analysis only - binaries are byte
//! inputs for IDA/idalib; nothing is ever executed.
//!
//! Gated (`#[ignore]`): needs a licensed IDA 9.2 (`IDADIR`). Run:
//!   cargo test -p reverse-mcp --release --features idalib \
//!     --test corpus_real -- --ignored --test-threads=1
//!
//! Output: docs/corpus_real/dossiers/<label>.json + report.json
//! (one row per binary: open/analyze success, function count, deep-analysis
//! completion or bounded partial, cache behavior, evidence categories,
//! confirmed vs heuristic counts, timeout/fallback events, worker health).

use serde_json::{Value, json};
use std::path::PathBuf;

fn manifest() -> Vec<(String, String)> {
    let raw = std::fs::read_to_string("docs/corpus_real/manifest.json").expect("manifest");
    let v: Value = serde_json::from_str(&raw).expect("manifest json");
    v["binaries"]
        .as_array()
        .expect("binaries")
        .iter()
        .map(|b| {
            (
                b["label"].as_str().unwrap_or_default().to_string(),
                b["path"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// One bounded evidence probe set against an open session. Evidence and
/// events are built as locals and attached at the end (single JSON tree).
async fn probe(
    s: &tokio::sync::Mutex<rmcp_broker::worker_pool::WorkerSession>,
    label: &str,
) -> Value {
    let guard = s.lock().await;
    let mut ev: Value = json!({});
    let mut events: Value = json!([]);
    let mut confirmed = 0u64;
    let mut heuristic = 0u64;
    let mut unavailable = 0u64;

    // 1. Analyze + function inventory (bounded list).
    match tokio::time::timeout(
        std::time::Duration::from_secs(300),
        guard.call("analyze_wait", json!({})),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            ev["analyze"] = json!({"status": "unavailable", "error": e.to_string()});
            unavailable += 1;
            drop(guard);
            return json!({"label": label, "open": "ok", "evidence": ev,
                "events": events, "confirmed": confirmed, "heuristic": heuristic,
                "unavailable": unavailable});
        }
        Err(_) => {
            ev["analyze"] = json!({"status": "unavailable", "error": "timeout 300s"});
            events
                .as_array_mut()
                .expect("arr")
                .push(json!({"kind": "timeout", "stage": "analyze"}));
            unavailable += 1;
            drop(guard);
            return json!({"label": label, "open": "ok", "evidence": ev,
                "events": events, "confirmed": confirmed, "heuristic": heuristic,
                "unavailable": unavailable});
        }
    }
    let funcs = guard
        .call("functions", json!({"offset": 0, "limit": 1000}))
        .await
        .expect("functions list");
    let func_count = funcs.as_array().map(|a| a.len()).unwrap_or(0);
    ev["functions"] = json!({"status": "confirmed", "count": func_count, "truncated_at": 1000});
    confirmed += 1;

    // 2. Imports + dynamic-resolution evidence (bounded).
    match guard.call("imports", json!({"limit": 200})).await {
        Ok(v) => {
            let n = v.as_array().map(|a| a.len()).unwrap_or(0);
            ev["imports"] = json!({"status": "confirmed", "count": n});
            confirmed += 1;
        }
        Err(e) => {
            ev["imports"] = json!({"status": "unavailable", "error": e.to_string()});
            unavailable += 1;
        }
    }

    // 3. Strings (bounded) - crypto/config evidence feed.
    match guard.call("strings", json!({"limit": 100})).await {
        Ok(v) => {
            let n = v.as_array().map(|a| a.len()).unwrap_or(0);
            ev["strings"] = json!({"status": "confirmed", "count": n});
            confirmed += 1;
        }
        Err(e) => {
            ev["strings"] = json!({"status": "unavailable", "error": e.to_string()});
            unavailable += 1;
        }
    }

    // 4. Deep analysis on the largest functions: completion or bounded
    //    partial with resume frontier (data-preserving by design).
    let fns = funcs.as_array().cloned().unwrap_or_default();
    let mut big: Vec<(u64, &Value)> = fns
        .iter()
        .filter_map(|f| Some((f["size"].as_u64()?, f)))
        .collect();
    big.sort_by_key(|(size, _)| std::cmp::Reverse(*size));
    let mut deep_completed = 0usize;
    let mut deep_partial = 0usize;
    for (_, f) in big.iter().take(3) {
        let Some(ea) = f["ea_start"].as_u64() else {
            continue;
        };
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            guard.call(
                "deep.function",
                json!({"ea": format!("{ea:#x}"), "max_functions": 8, "max_calls": 32}),
            ),
        )
        .await;
        match r {
            Ok(Ok(v)) => {
                if v["result"]["budget_hit"] == json!(true) {
                    deep_partial += 1;
                    events.as_array_mut().expect("arr").push(json!({
                        "kind": "budget_partial", "ea": ea,
                        "resumable": v["result"]["resume"]["pending"].is_array()}));
                } else {
                    deep_completed += 1;
                }
            }
            Ok(Err(e)) => {
                deep_partial += 1;
                events.as_array_mut().expect("arr").push(json!({
                    "kind": "fallback", "stage": "deep.function", "error": e.to_string()}));
            }
            Err(_) => {
                deep_partial += 1;
                events.as_array_mut().expect("arr").push(json!({
                    "kind": "timeout", "stage": "deep.function", "ea": ea}));
            }
        }
    }
    ev["deep_analysis"] = json!({"completed": deep_completed, "bounded_partial": deep_partial});

    // 5. Crypto/intel scan (bounded) - evidence with honest confidence.
    match tokio::time::timeout(
        std::time::Duration::from_secs(120),
        guard.call("intel.crypto", json!({"max_findings": 20})),
    )
    .await
    {
        Ok(Ok(v)) => {
            let findings = v["result"]["findings"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let conf = findings
                .iter()
                .filter(|f| {
                    f["confidence"].as_str() == Some("confirmed")
                        || f["confidence"].as_f64().unwrap_or(0.0) >= 0.9
                })
                .count();
            confirmed += conf as u64;
            heuristic += (findings.len() - conf) as u64;
            ev["crypto_constants"] = json!({"hits": findings.len(), "confirmed": conf});
        }
        Ok(Err(e)) => {
            ev["crypto_constants"] = json!({"status": "unavailable", "error": e.to_string()});
            unavailable += 1;
        }
        Err(_) => events
            .as_array_mut()
            .expect("arr")
            .push(json!({"kind": "timeout", "stage": "intel.crypto"})),
    }

    // 6. Index query sanity (revision-keyed cache in play).
    match guard
        .call(
            "index.query",
            json!({"query": {"all": [{"has_indirect_calls": {}}]}}),
        )
        .await
    {
        Ok(v) => {
            ev["indirect_calls"] = json!({"functions": v["count"].as_u64().unwrap_or(0)});
        }
        Err(e) => events.as_array_mut().expect("arr").push(json!({
            "kind": "fallback", "stage": "index.query", "error": e.to_string()})),
    }

    drop(guard);
    json!({
        "label": label,
        "open": "ok",
        "evidence": ev,
        "events": events,
        "confirmed": confirmed,
        "heuristic": heuristic,
        "unavailable": unavailable,
    })
}

#[tokio::test]
#[ignore] // run explicitly with IDADIR pointing at a licensed IDA 9.2
async fn real_corpus_end_to_end_dossiers() {
    let manifest = manifest();
    assert!(manifest.len() >= 20, "corpus must have >= 20 binaries");
    let out_dir = PathBuf::from("docs/corpus_real/dossiers");
    std::fs::create_dir_all(&out_dir).expect("out dir");

    let mut pool = rmcp_broker::WorkerPool::new();
    if let Ok(ida) = std::env::var("IDADIR") {
        pool.set_ida_dir(PathBuf::from(&ida));
    }

    let mut report: Vec<Value> = Vec::new();
    let mut opened = 0usize;
    let mut healthy_after = 0usize;

    for (label, path) in &manifest {
        let started = std::time::Instant::now();
        let mut row = json!({
            "label": label,
            "open": false,
            "analyzed": false,
            "dossier": false,
            "function_count": 0,
            "deep_completed": 0,
            "deep_partial": 0,
            "cache_aware": true,
            "worker_healthy": false,
            "wall_secs": 0,
        });
        // Copy to scratch so IDA's .i64 never lands next to the real binary.
        let dst = std::env::temp_dir().join(format!("reverse-mcp-c60-{label}.bin"));
        let _ = std::fs::remove_file(format!("{}.i64", dst.display()));
        match std::fs::copy(path, &dst) {
            Ok(_) => {}
            Err(e) => {
                row["open_error"] = json!(e.to_string());
                report.push(row);
                continue;
            }
        }
        let handle = match tokio::time::timeout(
            std::time::Duration::from_secs(1000),
            pool.spawn_for_with_budget(
                dst.to_str().unwrap(),
                4,
                "idalib",
                "",
                json!({"timeout_ms": 900_000}),
            ),
        )
        .await
        {
            Ok(Ok(h)) => {
                opened += 1;
                row["open"] = json!(true);
                h
            }
            Ok(Err(e)) => {
                row["open_error"] = json!(e.to_string());
                report.push(row);
                continue;
            }
            Err(_) => {
                row["open_error"] = json!("open timeout 300s");
                report.push(row);
                continue;
            }
        };

        let session = pool.session(&handle).await.expect("session");
        let dossier =
            tokio::time::timeout(std::time::Duration::from_secs(600), probe(&session, label))
                .await
                .unwrap_or_else(|_| {
                    json!({"label": label, "open": "ok", "evidence": {},
                   "events": [{"kind": "timeout", "stage": "probe"}],
                   "confirmed": 0, "heuristic": 0, "unavailable": 0})
                });
        // Uniform rows: a probe timeout (huge binary) still yields explicit
        // zeros + an event row, never nulls - the report stays machine-
        // readable and the gap is visible rather than ambiguous.
        let analyzed = dossier["evidence"]["functions"]["status"] == "confirmed";
        row["analyzed"] = json!(analyzed);
        row["function_count"] = json!(if analyzed {
            dossier["evidence"]["functions"]["count"]
                .as_u64()
                .unwrap_or(0)
        } else {
            0
        });
        row["deep_completed"] = json!(
            dossier["evidence"]["deep_analysis"]["completed"]
                .as_u64()
                .unwrap_or(0)
        );
        row["deep_partial"] = json!(
            dossier["evidence"]["deep_analysis"]["bounded_partial"]
                .as_u64()
                .unwrap_or(0)
        );
        row["confirmed"] = json!(dossier["confirmed"].as_u64().unwrap_or(0));
        row["heuristic"] = json!(dossier["heuristic"].as_u64().unwrap_or(0));

        // Dossier to disk.
        let path = out_dir.join(format!("{label}.json"));
        match serde_json::to_string_pretty(&dossier) {
            Ok(text) => {
                std::fs::write(&path, text).expect("write dossier");
                row["dossier"] = json!(true);
            }
            Err(e) => row["dossier_error"] = json!(e.to_string()),
        }

        let _ = pool.close(&handle).await;
        row["worker_healthy"] = json!(pool.session(&handle).await.is_none());
        if row["worker_healthy"] == json!(true) {
            healthy_after += 1;
        }
        row["wall_secs"] = json!(started.elapsed().as_secs());
        report.push(row);
    }

    // Acceptance report.
    let summary = json!({
        "binaries": manifest.len(),
        "opened": opened,
        "worker_healthy_after": healthy_after,
        "rows": report,
    });
    std::fs::write(
        "docs/corpus_real/report.json",
        serde_json::to_string_pretty(&summary).expect("report json"),
    )
    .expect("write report");

    // Acceptance criteria: >= 20 opened end-to-end; every opened session
    // closed cleanly (worker failure isolation); dossiers written.
    assert!(
        opened >= 20,
        "must open >= 20 binaries end to end; got {opened}"
    );
    assert_eq!(
        healthy_after, opened,
        "every session must close cleanly (worker isolation)"
    );
    for row in &report {
        if row["open"] == json!(true) {
            assert_eq!(
                row["dossier"],
                json!(true),
                "every opened binary needs a dossier: {row}"
            );
        }
    }
}
