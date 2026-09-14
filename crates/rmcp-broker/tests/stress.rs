//! Multi-agent stress tests (issue #15 acceptance): concurrent operations
//! across two DBs, same-DB serialization, stale mutation rejection under
//! load, crash-under-load recovery. Mock backend, repeatable, no timing
//! dependencies.

use std::sync::Arc;

use serde_json::json;

use rmcp_broker::WorkerPool;

fn pool() -> WorkerPool {
    WorkerPool::new()
}

/// A -> db1 decompile, B -> db2 search, C -> db1 xrefs, D -> db2 inspect:
/// different DBs make progress concurrently and every call succeeds.
#[tokio::test]
async fn concurrent_ops_on_two_dbs() {
    let mut pool = pool();
    let h1 = pool
        .spawn_for("stress-a.i64", 8, "mock", "")
        .await
        .expect("db1");
    let h2 = pool
        .spawn_for("stress-b.i64", 8, "mock", "")
        .await
        .expect("db2");

    let s1 = Arc::clone(&pool.session(&h1).await.expect("s1"));
    let s2 = Arc::clone(&pool.session(&h2).await.expect("s2"));

    let mut tasks = tokio::task::JoinSet::new();
    // A -> db1 decompile
    tasks.spawn({
        let s1 = Arc::clone(&s1);
        async move {
            let s = s1.lock().await;
            s.call("decompile", json!({"ea": "0x401000"})).await
        }
    });
    // B -> db2 search
    tasks.spawn({
        let s2 = Arc::clone(&s2);
        async move {
            let s = s2.lock().await;
            s.call("search_text", json!({"needle": "usage", "limit": 5}))
                .await
        }
    });
    // C -> db1 xrefs
    tasks.spawn({
        let s1 = Arc::clone(&s1);
        async move {
            let s = s1.lock().await;
            s.call("xrefs_to", json!({"ea": "0x401100"})).await
        }
    });
    // D -> db2 inspect
    tasks.spawn({
        let s2 = Arc::clone(&s2);
        async move {
            let s = s2.lock().await;
            s.call("function_at", json!({"ea": "0x401000"})).await
        }
    });

    let mut results = Vec::new();
    while let Some(r) = tasks.join_next().await {
        results.push(r.expect("task panicked"));
    }
    assert_eq!(results.len(), 4);
    for r in &results {
        assert!(r.is_ok(), "stress call failed: {r:?}");
    }

    pool.close(&h1).await.expect("close 1");
    pool.close(&h2).await.expect("close 2");
}

/// Same-DB calls serialize (per-DB mutex) but all complete: N concurrent
/// mutations on one DB produce N distinct revision increments.
#[tokio::test]
async fn same_db_serialized_mutations() {
    let mut pool = pool();
    let handle = pool
        .spawn_for("stress-serial.i64", 8, "mock", "")
        .await
        .expect("db");
    let s = Arc::clone(&pool.session(&handle).await.expect("s"));

    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..8u64 {
        let s = Arc::clone(&s);
        tasks.spawn(async move {
            let s = s.lock().await;
            s.call(
                "rename",
                json!({"ea": "0x401100", "name": format!("fn_{i}")}),
            )
            .await
        });
    }
    let mut revisions = Vec::new();
    while let Some(r) = tasks.join_next().await {
        let out = r.expect("task panicked").expect("mutation");
        revisions.push(out["revision_after"].as_u64().expect("revision"));
    }
    revisions.sort_unstable();
    // 8 mutations = 8 distinct increments: proves serialization (no lost
    // updates) and revision monotonicity.
    assert_eq!(revisions, vec![1, 2, 3, 4, 5, 6, 7, 8]);

    pool.close(&handle).await.expect("close");
}

/// Stale mutation under load: interleaved mutations on one DB, a caller
/// holding an old revision must get `revision_conflict`.
#[tokio::test]
async fn stale_mutation_rejected_under_load() {
    let mut pool = pool();
    let handle = pool
        .spawn_for("stress-stale.i64", 8, "mock", "")
        .await
        .expect("db");
    let s = Arc::clone(&pool.session(&handle).await.expect("s"));

    // First confirmed mutation -> revision 1.
    {
        let s = s.lock().await;
        let out = s
            .call("rename", json!({"ea": "0x401100", "name": "first"}))
            .await
            .expect("first rename");
        assert_eq!(out["revision_after"], 1);
    }

    // A competing mutation lands first (revision becomes 2).
    {
        let s = s.lock().await;
        let out = s
            .call("rename", json!({"ea": "0x401100", "name": "second"}))
            .await
            .expect("second rename");
        assert_eq!(out["revision_after"], 2);
    }

    // Then the caller sends its stale write with expected_revision=1.
    {
        let s = s.lock().await;
        let err = s
            .call(
                "rename",
                json!({"ea": "0x401100", "name": "stale", "expected_revision": 1}),
            )
            .await
            .expect_err("stale mutation must fail");
        assert_eq!(err.code(), "revision_conflict");
    }

    pool.close(&handle).await.expect("close");
}

/// Kill a worker mid-session and recover while another DB keeps serving:
/// recovery preserves the handle and later reads continue (issue #15 stress
/// scenario: "kill db1 worker; A -> db1 call after recovery").
#[tokio::test]
async fn crash_under_load_recovers() {
    let mut pool = pool();
    let h1 = pool
        .spawn_for("stress-crash-a.i64", 8, "mock", "")
        .await
        .expect("db1");
    let h2 = pool
        .spawn_for("stress-crash-b.i64", 8, "mock", "")
        .await
        .expect("db2");

    // Healthy check on db1.
    {
        let s = pool.session(&h1).await.expect("s1");
        let s = s.lock().await;
        s.call("db.info", json!({})).await.expect("info");
    }

    // Kill the db1 worker child (crash, not shutdown).
    {
        let s = pool.session(&h1).await.expect("s1");
        let pid = s.lock().await.hello().pid;
        let status = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output()
            .expect("taskkill");
        assert!(status.status.success(), "taskkill failed: {status:?}");
    }
    // Give the pump time to observe EOF and flip the state.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        pool.health(&h1).await.unwrap(),
        rmcp_broker::recovery::WorkerHealth::Crashed
    );

    // db2 keeps serving while db1 is down.
    {
        let s = pool.session(&h2).await.expect("s2");
        let s = s.lock().await;
        s.call("db.info", json!({})).await.expect("db2 still works");
    }

    // Recover db1 under the same handle.
    pool.recover(
        &h1,
        &rmcp_broker::recovery::RestartPolicy {
            max_restarts: 3,
            backoff: std::time::Duration::from_millis(50),
        },
    )
    .await
    .expect("recovery");
    assert_eq!(
        pool.health(&h1).await.unwrap(),
        rmcp_broker::recovery::WorkerHealth::Healthy
    );

    // A -> db1 call after recovery.
    {
        let s = pool.session(&h1).await.expect("s1 after recovery");
        let s = s.lock().await;
        let info = s
            .call("db.info", json!({}))
            .await
            .expect("info after recovery");
        assert!(info["function_count"].is_number());
    }

    // Both handles still registered.
    let listed = pool.list().await;
    assert!(listed.iter().any(|(h, _)| h == &h1));
    assert!(listed.iter().any(|(h, _)| h == &h2));

    pool.close(&h1).await.expect("close 1");
    pool.close(&h2).await.expect("close 2");
}

/// Max-worker enforcement: opening more than the cap fails cleanly without
/// killing existing sessions.
#[tokio::test]
async fn max_worker_enforcement() {
    let mut pool = pool();
    let h1 = pool
        .spawn_for("stress-max-a.i64", 1, "mock", "")
        .await
        .expect("db1");
    let err = pool
        .spawn_for("stress-max-b.i64", 1, "mock", "")
        .await
        .expect_err("second open must hit the cap");
    assert!(err.to_string().contains("max_workers"), "err: {err}");
    // db1 still healthy.
    {
        let s = pool.session(&h1).await.expect("s1");
        let s = s.lock().await;
        s.call("db.info", json!({})).await.expect("db1 works");
    }
    pool.close(&h1).await.expect("close");
}
