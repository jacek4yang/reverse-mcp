//! Real-IDA integration test (feature `idalib`): drives the REAL production
//! path — `reverse-mcp serve`'s WorkerPool spawning `<exe> worker` children —
//! against a real binary analyzed by IDA 9.2 idalib.
//!
//! Chain verified (docs/reverse-mcp-ffi.md item 7):
//! open -> analyze -> functions -> disassemble -> xrefs -> strings ->
//! Hex-Rays decompile -> rename/comment -> save -> reopen.
//!
//! Requires IDADIR to point at an IDA 9.x install with a valid license.
//! Run explicitly: cargo test -p reverse-mcp --features idalib
//!                 --test idalib_real -- --ignored

use std::path::PathBuf;
use std::sync::Arc;

use rmcp_broker::WorkerPool;
use serde_json::json;

/// The pool spawns the combined exe in `worker` mode; the child needs the
/// IDA dir on PATH to resolve ida.dll/idalib.dll.
fn pool_with_ida_on_path() -> WorkerPool {
    let mut pool = WorkerPool::new();
    if let Ok(ida_dir) = std::env::var("IDADIR") {
        pool.set_ida_dir(PathBuf::from(ida_dir));
    }
    pool
}

async fn open_idalib(pool: &mut WorkerPool, path: &str) -> String {
    pool.spawn_for(path, 4, "idalib", "")
        .await
        .expect("idalib open")
}

#[tokio::test]
#[ignore] // run explicitly with IDADIR pointing at a licensed IDA 9.2
async fn real_ida_full_chain() {
    // Copy fixture to a scratch path; IDA creates simple.i64 next to it.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-simple.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();

    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    // 1. open ran auto-analysis; function count reported at open.
    let info = s.call("db.info", json!({})).await.expect("db.info");
    let fn_count = info["function_count"].as_u64().expect("function count");
    assert!(
        fn_count >= 5,
        "expected at least 5 functions, got {fn_count}"
    );

    // 2. analyze wait
    let r = s.call("analyze_wait", json!({})).await.expect("analyze");
    assert_eq!(r["analyzed"], true);

    // 3. functions list contains our named functions
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let arr = fns.as_array().expect("functions array");
    assert!(!arr.is_empty());
    let names: Vec<&str> = arr.iter().filter_map(|f| f["name"].as_str()).collect();
    let has_helper = names.iter().any(|n| n.contains("helper"));
    let has_decrypt = names.iter().any(|n| n.contains("decrypt_packet"));
    assert!(has_helper || has_decrypt, "named funcs missing: {names:?}");

    // helper function address for later steps
    let helper_ea = arr
        .iter()
        .find(|f| f["name"].as_str().is_some_and(|n| n.contains("helper")))
        .expect("helper function")["ea_start"]
        .as_u64()
        .expect("helper ea");

    // 4. instruction decode at helper
    let insns = s
        .call("disassemble", json!({"ea": helper_ea, "max_insns": 8}))
        .await
        .expect("disassemble");
    let iarr = insns.as_array().expect("insns array");
    assert!(
        !iarr.is_empty(),
        "no instructions decoded at {helper_ea:#x}"
    );
    assert!(iarr[0]["text"].as_str().is_some_and(|t| !t.is_empty()));

    // 5. xrefs: main calls helper
    let xrefs_to = s
        .call("xrefs_to", json!({"ea": helper_ea}))
        .await
        .expect("xrefs_to");
    let xarr = xrefs_to.as_array().expect("xrefs array");
    assert!(!xarr.is_empty(), "expected call xrefs to helper");

    // 6. strings: the fixture has a "usage: simple" string
    let strings = s
        .call("strings", json!({"offset": 0, "limit": 5000}))
        .await
        .expect("strings");
    let sarr = strings.as_array().expect("strings array");
    let found_usage = sarr
        .iter()
        .any(|s| s["value"].as_str().is_some_and(|v| v.contains("usage")));
    assert!(
        found_usage,
        "usage string not found in {} strings",
        sarr.len()
    );

    // 7. Hex-Rays decompile of helper
    let dec = s
        .call("decompile", json!({"ea": helper_ea}))
        .await
        .expect("decompile");
    let pseudo = dec["pseudocode"].as_str().expect("pseudocode");
    assert!(
        pseudo.contains("helper") || pseudo.contains("a + b") || pseudo.contains("return"),
        "unexpected pseudocode: {pseudo}"
    );

    // 8. rename + comment
    let ren = s
        .call(
            "rename",
            json!({"ea": helper_ea, "name": "helper_renamed_it"}),
        )
        .await
        .expect("rename");
    assert_eq!(ren["changed"], true);
    let cmt = s
        .call(
            "set_comment",
            json!({"ea": helper_ea, "comment": "it-test comment", "repeatable": false}),
        )
        .await
        .expect("set_comment");
    assert_eq!(cmt["changed"], true);
    let got = s
        .call("get_comment", json!({"ea": helper_ea, "repeatable": false}))
        .await
        .expect("get_comment");
    assert_eq!(got["comment"], "it-test comment");

    // 9. save then close
    s.call("db.save", json!({})).await.expect("db.save");
    s.call("db.close", json!({})).await.expect("db.close");
    drop(s);
    pool.close(&handle).await.expect("close");

    // 10. reopen in a fresh worker and verify the rename survived
    let mut pool2 = pool_with_ida_on_path();
    let handle2 = open_idalib(&mut pool2, &dst).await;
    let session2 = pool2.session(&handle2).await.expect("session");
    let s2 = session2.lock().await;
    let fns2 = s2
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let names2: Vec<String> = fns2
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|f| f["name"].as_str().map(str::to_string))
        .collect();
    assert!(
        names2.iter().any(|n| n == "helper_renamed_it"),
        "rename not persisted after reopen: {names2:?}"
    );
    s2.call("db.close", json!({})).await.expect("db.close");
    drop(s2);
    pool2.close(&handle2).await.expect("close");
}

/// Two databases concurrently: separate worker processes must both make
/// progress and stay isolated (per-DB serialization is the pool's job).
#[tokio::test]
#[ignore] // run explicitly with IDADIR pointing at a licensed IDA 9.2
async fn real_ida_two_dbs_concurrent() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple.exe");
    let dst1 = std::env::temp_dir().join("reverse-mcp-it-two-a.exe");
    let dst2 = std::env::temp_dir().join("reverse-mcp-it-two-b.exe");
    std::fs::copy(&src, &dst1).expect("copy fixture a");
    std::fs::copy(&src, &dst2).expect("copy fixture b");
    let dst1 = dst1.to_string_lossy().into_owned();
    let dst2 = dst2.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let h1 = open_idalib(&mut pool, &dst1).await;
    let h2 = open_idalib(&mut pool, &dst2).await;

    let s1 = Arc::clone(&pool.session(&h1).await.expect("s1"));
    let s2 = Arc::clone(&pool.session(&h2).await.expect("s2"));

    // Interleave calls on both sessions concurrently.
    let a = tokio::spawn(async move {
        let s = s1.lock().await;
        let fns = s
            .call("functions", json!({"offset": 0, "limit": 50}))
            .await
            .expect("a: functions");
        let ren = s
            .call(
                "rename",
                json!({"ea": fns[0]["ea_start"], "name": "a_renamed"}),
            )
            .await
            .expect("a: rename");
        assert_eq!(ren["changed"], true);
        ren
    });
    let b = tokio::spawn(async move {
        let s = s2.lock().await;
        let fns = s
            .call("functions", json!({"offset": 0, "limit": 50}))
            .await
            .expect("b: functions");
        let info = s.call("db.info", json!({})).await.expect("b: info");
        assert!(info["function_count"].as_u64().unwrap_or(0) > 0);
        fns
    });
    let (ra, rb) = tokio::join!(a, b);
    assert_eq!(ra.expect("a task")["changed"], true);
    assert!(!rb.expect("b task").as_array().unwrap().is_empty());

    pool.close(&h1).await.expect("close 1");
    pool.close(&h2).await.expect("close 2");
}
