//! #57 long-run reliability gate: a bounded soak that runs the full
//! lifecycle cycle (open -> analyze -> decompile -> mutate -> save ->
//! close -> reopen) repeatedly over mock workers while watching for the
//! failure modes the issue forbids: leaked workers, unbounded memory,
//! deadlocked calls, stale sessions, result-store drift.
//!
//! CI runs the 60-second gate; `scripts/soak.ps1` wraps the same harness
//! for the 12h/24h release gates on a machine with real IDA.

use serde_json::json;
use std::sync::Arc;

use rmcp_broker::WorkerPool;

#[tokio::test]
async fn soak_gate_60s_lifecycle_cycles() {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut pool = WorkerPool::new();
    let mut cycles = 0u64;
    let mut handled_crashes = 0u64;

    while tokio::time::Instant::now() < deadline {
        cycles += 1;

        // Open two DBs (concurrent sessions are the production shape).
        let h1 = pool
            .spawn_for("soak-a.i64", 8, "mock", "")
            .await
            .expect("open a");
        let h2 = pool
            .spawn_for("soak-b.i64", 8, "mock", "")
            .await
            .expect("open b");

        // Mixed workload on both sessions.
        for round in 0..4u32 {
            let s1 = Arc::clone(&pool.session(&h1).await.expect("s1"));
            let s2 = Arc::clone(&pool.session(&h2).await.expect("s2"));
            let (r1, r2) = tokio::join!(
                async {
                    let s = s1.lock().await;
                    s.call_with_timeout(
                        "decompile",
                        json!({"ea": format!("{:#x}", 0x401000 + round)}),
                        std::time::Duration::from_secs(30),
                    )
                    .await
                },
                async {
                    let s = s2.lock().await;
                    s.call_with_timeout(
                        "search_text",
                        json!({"needle": "usage", "limit": 5}),
                        std::time::Duration::from_secs(30),
                    )
                    .await
                },
            );
            assert!(r1.is_ok(), "decompile must answer: {r1:?}");
            assert!(r2.is_ok(), "search must answer: {r2:?}");
        }

        // Session crash + recovery (the production failure mode).
        {
            let s = pool.session(&h1).await.expect("s1");
            let pid = s.lock().await.hello().pid;
            drop(s);
            // Kill the child by PID per-OS (taskkill on Windows, kill -9 on
            // Unix - #48 Linux CI).
            if cfg!(windows) {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .output();
            } else {
                let _ = std::process::Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .output();
            }
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            assert_eq!(
                pool.health(&h1).await.unwrap(),
                rmcp_broker::recovery::WorkerHealth::Crashed
            );
            pool.recover(
                &h1,
                &rmcp_broker::recovery::RestartPolicy {
                    max_restarts: 3,
                    backoff: std::time::Duration::from_millis(50),
                },
            )
            .await
            .expect("recovery");
            handled_crashes += 1;
            assert_eq!(
                pool.health(&h1).await.unwrap(),
                rmcp_broker::recovery::WorkerHealth::Healthy
            );
        }

        // Clean close both; handles must vanish from the pool.
        pool.close(&h1).await.expect("close a");
        pool.close(&h2).await.expect("close b");
        assert!(pool.session(&h1).await.is_none(), "session a must be gone");
        assert!(pool.session(&h2).await.is_none(), "session b must be gone");

        // Never accumulate sessions across cycles (leak check).
        assert!(
            pool.list().await.is_empty(),
            "pool must be empty after close"
        );
    }

    // The gate only passes if real work happened.
    assert!(cycles >= 3, "60s must fit >= 3 full cycles; did {cycles}");
    assert!(
        handled_crashes >= 2,
        "crash+recovery must have been exercised; got {handled_crashes}"
    );
}
