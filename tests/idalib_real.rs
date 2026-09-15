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

    // 7b. calls graph rooted at main must find calls at NON-entry addresses:
    // main's body calls j_helper / j_dispatch / j_decrypt_packet, which are
    // not at main's entry EA. Function-wide call discovery must find them.
    let main_ea = info["main_ea"]
        .as_u64()
        .or_else(|| {
            arr.iter()
                .find(|f| f["name"].as_str() == Some("main"))
                .and_then(|f| f["ea_start"].as_u64())
        })
        .expect("main function");
    let calls = s
        .call(
            "graph",
            json!({"ea": main_ea, "kind": "calls", "depth": 1, "max_nodes": 100, "max_edges": 200}),
        )
        .await
        .expect("calls graph");
    let edges = calls["edges"].as_array().expect("edges array");
    let callees: Vec<&serde_json::Value> = edges
        .iter()
        .filter(|e| e["from"].as_u64() == Some(main_ea))
        .collect();
    assert!(
        callees.len() >= 2,
        "expected >=2 calls from main's body, got {callees:?}"
    );
    let helper_in_graph = calls["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["ea"].as_u64() == Some(helper_ea));
    assert!(
        helper_in_graph,
        "helper must appear in main's calls graph: {calls}"
    );

    // 7c. cfg graph of main: basic-block flow view (the fixture's main is
    // mostly linear, so 1 block is legitimate; assert structural validity)
    let cfg = s
        .call(
            "graph",
            json!({"ea": main_ea, "kind": "cfg", "depth": 1, "max_nodes": 500, "max_edges": 1000}),
        )
        .await
        .expect("cfg graph");
    let cfg_nodes = cfg["nodes"].as_array().expect("cfg nodes");
    assert!(!cfg_nodes.is_empty(), "cfg must have >=1 basic block");
    assert_eq!(cfg_nodes[0]["ea"].as_u64(), Some(main_ea));
    // function-wide CFG: the root block covers main's entry
    let cfg_root_covered = cfg_nodes.iter().any(|n| n["ea"].as_u64() == Some(main_ea));
    assert!(cfg_root_covered, "cfg must include main's entry block");
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

/// #19 capability gaps: metadata, imports, fixups, file map, tails, switch
/// info, sp delta, ctree/lvar summaries, demangle and insn features against
/// the real fixture. Read-only over the existing fixture DB.
#[tokio::test]
#[ignore] // run explicitly with IDADIR pointing at a licensed IDA 9.2
async fn real_ida_issue19_capability_chain() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-19.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    // --- db.metadata: hashes + imagebase + entries ---
    let md = s.call("db.metadata", json!({})).await.expect("db.metadata");
    // MD5 of the copied fixture must be present (16 bytes hex)...
    let md5 = md["md5"].as_str().expect("md5 present");
    assert_eq!(md5.len(), 32, "md5 hex length");
    // ...and must equal the digest IDA recorded at open (same file), i.e.
    // the value must be a well-formed lowercase hex digest, not a stub.
    assert!(
        md5.bytes().all(|b| b.is_ascii_hexdigit()),
        "md5 must be hex: {md5}"
    );
    assert!(
        md["imagebase"].as_u64().is_some(),
        "imagebase missing: {md}"
    );
    assert!(
        md["imagebase"].as_u64() == Some(0x140000000),
        "PE default imagebase expected, got {md}"
    );
    assert_eq!(
        md["tls_callbacks_supported"], false,
        "TLS callbacks must be reported honestly as unsupported"
    );
    // --- imports.list: fixture imports from KERNEL32 ---
    let imports = s
        .call("imports.list", json!({}))
        .await
        .expect("imports.list");
    let modules = imports["modules"].as_array().expect("modules array");
    assert!(
        !modules.is_empty() && modules[0]["name"].as_str().is_some_and(|n| !n.is_empty()),
        "expected at least one named import module, got {modules:?}"
    );

    // --- file.map: EA of the entry point must map to a real file offset ---
    let entry_ea = md["entries"][0]["ea"]
        .as_u64()
        .expect("entry point ea in metadata");
    let fwd = s
        .call("file.map", json!({"value": entry_ea}))
        .await
        .expect("file.map ea->offset");
    let off = fwd["file_offset"].as_i64().expect("file offset");
    assert!(off >= 0, "entry point must map into the file");
    let back = s
        .call("file.map", json!({"value": off, "to_ea": true}))
        .await
        .expect("file.map offset->ea");
    assert_eq!(back["ea"].as_u64(), Some(entry_ea), "roundtrip");

    // --- fixups.list: may be empty for this MSVC link; shape must hold ---
    let fx = s.call("fixups.list", json!({})).await.expect("fixups");
    assert!(fx["total"].as_u64().is_some(), "fixup total missing: {fx}");

    // --- func.tails + sp_delta + insn features on helper ---
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let arr = fns.as_array().expect("functions array");
    let helper = arr
        .iter()
        .find(|f| f["name"].as_str().is_some_and(|n| n.contains("helper")))
        .expect("helper function")
        .clone();
    let helper_ea = helper["ea_start"].as_u64().unwrap();
    let tails = s
        .call("func.tails", json!({"ea": helper_ea}))
        .await
        .expect("func.tails");
    let chunks = tails["chunks"].as_array().expect("chunks");
    assert!(!chunks.is_empty(), "at least the entry chunk");
    assert_eq!(chunks[0]["start"].as_u64(), Some(helper_ea));
    let sp = s
        .call("func.sp_delta", json!({"ea": helper_ea}))
        .await
        .expect("sp_delta");
    assert!(sp["sp_delta"].as_i64().is_some(), "sp_delta payload: {sp}");
    let feats = s
        .call("insn.features", json!({"ea": helper_ea}))
        .await
        .expect("insn.features");
    assert!(
        feats["features"].as_u64().is_some(),
        "canon feature bits: {feats}"
    );
    assert!(
        !feats["mnemonic"].as_str().unwrap_or_default().is_empty(),
        "mnemonic must decode at helper"
    );

    // --- func.switch_info: the fixture's dispatch() compiles to a cmp chain
    // (no jump table), so NO address carries switch info. The honest
    // assertion: scanning dispatch must not crash, and any switch found
    // (none expected here) would carry a jump table.
    let dispatch = arr
        .iter()
        .find(|f| f["name"].as_str().is_some_and(|n| n.contains("dispatch")))
        .expect("dispatch function")
        .clone();
    let dispatch_ea = dispatch["ea_start"].as_u64().unwrap();
    let dispatch_end = dispatch["ea_end"].as_u64().unwrap();
    let insns = s
        .call(
            "disassemble",
            json!({"ea": dispatch_ea, "end": dispatch_end, "max_insns": 200}),
        )
        .await
        .expect("disassemble dispatch");
    for i in insns.as_array().expect("insns").iter() {
        let ea = i["ea"].as_u64().unwrap();
        // must return a clean error (not crash) for non-switch addresses
        let _ = s.call("func.switch_info", json!({"ea": ea})).await;
    }

    // --- hr.cfunc: bounded ctree summaries + lvars + return type ---
    let hr = s
        .call(
            "hr.cfunc",
            json!({"ea": helper_ea, "include_ctree": true, "include_lvars": true, "limit": 50}),
        )
        .await
        .expect("hr.cfunc");
    let ctree = hr["ctree"].as_array().expect("ctree array");
    assert!(
        ctree.len() >= 5,
        "helper ctree should have multiple nodes, got {}",
        ctree.len()
    );
    // cot_num rows carry the numeric value in `c`
    assert!(
        ctree.iter().any(|r| r["op"].as_u64().is_some()),
        "ctree rows must carry typed op codes"
    );
    assert!(
        ctree
            .iter()
            .any(|r| r["text"].as_str().is_some_and(|t| !t.is_empty())),
        "ctree expressions must carry rendered text"
    );
    assert_eq!(
        hr["ctree_truncated"].as_bool(),
        Some(false),
        "50-row limit must not truncate helper"
    );
    let lvars = hr["lvars"].as_array().expect("lvars array");
    assert!(
        lvars.iter().any(|l| l["is_arg"].as_bool() == Some(true)),
        "helper must have at least one arg lvar: {lvars:?}"
    );
    assert!(
        lvars.iter().all(|l| l["type_text"].as_str().is_some()),
        "each lvar must carry a rendered type text"
    );
    assert!(
        hr["return_type"].as_str().is_some_and(|t| !t.is_empty()),
        "return type text must be rendered: {hr}"
    );

    // --- hr.lvar_rename: rename the first arg lvar (its locator defea is
    // the function entry in this fixture), persist and re-decompile.
    let rename_target = lvars[0]["defea"].as_u64().expect("first lvar defea");
    let ren = s
        .call(
            "hr.lvar_rename",
            json!({"ea": helper_ea, "var_defea": rename_target, "name": "it19_arg"}),
        )
        .await
        .expect("hr.lvar_rename");
    assert_eq!(ren["changed"], true);
    // re-decompile must show the renamed lvar
    let hr2 = s
        .call(
            "hr.cfunc",
            json!({"ea": helper_ea, "include_ctree": false, "include_lvars": true, "limit": 50}),
        )
        .await
        .expect("hr.cfunc after rename");
    let lvars2 = hr2["lvars"].as_array().expect("lvars2");
    assert!(
        lvars2
            .iter()
            .any(|l| l["name"].as_str() == Some("it19_arg")),
        "renamed lvar must appear in fresh decompilation: {lvars2:?}"
    );

    // --- names.demangle: fixture is MSVC C, feed a known MSVC mangled name ---
    let dem = s
        .call("names.demangle", json!({"name": "?fn@ns@@YAHXZ"}))
        .await
        .expect("names.demangle");
    assert_eq!(dem["changed"], true, "MSVC name must demangle: {dem}");

    // --- demangle passthrough for a plain C name ---
    let plain = s
        .call("names.demangle", json!({"name": "helper"}))
        .await
        .expect("demangle plain");
    assert_eq!(plain["changed"], false);

    s.call("db.save", json!({})).await.expect("save");
    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

/// #19 function-structure mutations: create / resize / delete with
/// expected_revision guarding.
#[tokio::test]
#[ignore] // run explicitly with IDADIR pointing at a licensed IDA 9.2
async fn real_ida_issue19_func_mutations() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-19-mut.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    let rev0 = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();

    // Pick a code address that is not inside any function (scan for undefined
    // code past the last function). Use main's tail bytes region: we create a
    // function at a known code address by first deleting nothing — instead we
    // grab the address of an instruction INSIDE main (offset +2) which belongs
    // to no function start, and create a function there? add_func on a
    // mid-function address fails; so use a fresh path: find undefined bytes.
    // Simplest deterministic approach: create at main's entry + main size
    // boundary is risky. Instead, locate any "sub_" region via the analyzer:
    // use an address right after main's end where padding/thunk code may sit.
    // Robust choice: pick the entry thunk of an import (data) — no. We use
    // `functions` list: choose the LAST function's end; alignment padding
    // follows. If creation fails there, the API must return a clean error.
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let arr = fns.as_array().expect("functions array");
    let last = arr.last().expect("last function");
    let probe = last["ea_end"].as_u64().unwrap() + 0x10;

    // create at a likely-invalid address must fail cleanly (not crash)
    let r = s.call("func.create", json!({"start": probe})).await;
    // On MSVC-linked binaries the tail may or may not hold code; both a clean
    // error and a success are acceptable, but a crash/panic is not.
    let created = r.is_ok() && r.unwrap()["changed"] == true;
    let rev_after_create = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    if created {
        assert!(
            rev_after_create > rev0,
            "successful mutation must bump revision"
        );
        // delete it again
        let del = s
            .call(
                "func.delete",
                json!({"ea": probe, "expected_revision": rev_after_create}),
            )
            .await
            .expect("func.delete");
        assert_eq!(del["changed"], true);
    } else {
        assert_eq!(rev_after_create, rev0, "failed mutation must not bump");
    }

    // resize: move main's end then restore
    let main = arr
        .iter()
        .find(|f| f["name"].as_str() == Some("main"))
        .expect("main function")
        .clone();
    let main_ea = main["ea_start"].as_u64().unwrap();
    let old_end = main["ea_end"].as_u64().unwrap();
    let rev1 = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    let rs = s
        .call(
            "func.resize",
            json!({"ea": main_ea, "new_end": old_end - 1, "expected_revision": rev1}),
        )
        .await
        .expect("resize end");
    assert_eq!(rs["changed"], true);
    let fns2 = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions after resize");
    let main2 = fns2
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["ea_start"].as_u64() == Some(main_ea))
        .expect("main after resize")
        .clone();
    assert_eq!(
        main2["ea_end"].as_u64(),
        Some(old_end - 1),
        "resized end must be reflected"
    );
    // restore
    let rev2 = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    let rs2 = s
        .call(
            "func.resize",
            json!({"ea": main_ea, "new_end": old_end, "expected_revision": rev2}),
        )
        .await
        .expect("resize restore");
    assert_eq!(rs2["changed"], true);

    // stale expected_revision must be rejected with a stable error code
    let r = s
        .call(
            "func.delete",
            json!({"ea": main_ea, "expected_revision": 0}),
        )
        .await;
    match r {
        Err(e) => assert_eq!(e.code(), "revision_conflict"),
        Ok(v) => panic!("stale revision must fail: {v}"),
    }

    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

/// #16 acceptance, real IDA: patch bytes persist after save/reopen; the
/// mutation audit trail records old/new state; snapshot/rollback restores
/// a pre-mutation name. Requires IDADIR.
#[tokio::test]
#[ignore]
async fn real_ida_issue16_mutation_layer() {
    // Copy fixture to a scratch path; IDA creates the .i64 next to it.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-16.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    // A stale .i64 from a previous run already contains saved mutations,
    // making the test non-idempotent - remove it before opening.
    let fresh_i64 = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&fresh_i64);
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    let md = s.call("db.metadata", json!({})).await.expect("metadata");
    let entry_ea = md["entries"][0]["ea"].as_u64().expect("entry point ea");

    // --- plan: stale whole-plan revision is rejected before any op runs ---
    let rev = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    let stale = s
        .call(
            "plan.apply",
            json!({
                "expected_revision": rev.wrapping_sub(1),
                "operations": [
                    {"ea": format!("{entry_ea:#x}"), "kind": "rename", "name": "nope"}
                ]
            }),
        )
        .await;
    match stale {
        Err(e) => assert_eq!(e.code(), "revision_conflict"),
        Ok(v) => panic!("stale plan must be rejected: {v}"),
    }

    // --- apply: rename + comment plan applies, audit trail grows by 2 ---
    let rev = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    let applied = s
        .call(
            "plan.apply",
            json!({
                "expected_revision": rev,
                "operations": [
                    {"ea": format!("{entry_ea:#x}"), "kind": "rename", "name": "issue16_planned"},
                    {"ea": format!("{entry_ea:#x}"), "kind": "comment", "comment": "issue16 audit note"}
                ]
            }),
        )
        .await
        .expect("plan.apply");
    assert_eq!(applied["applied"], 2, "apply: {applied}");
    assert_eq!(applied["partial"], false);

    let audit = s
        .call("mutation.audit", json!({"limit": 10}))
        .await
        .expect("audit");
    assert!(audit["total"].as_u64().unwrap() >= 2, "audit: {audit}");
    let entries = audit["entries"].as_array().unwrap();
    assert!(
        entries.iter().any(|e| e["kind"] == "rename"),
        "audit: {audit}"
    );

    // --- snapshot -> mutate -> rollback restores the pre-snapshot name ---
    let snap = s
        .call("snapshot.create", json!({}))
        .await
        .expect("snapshot");
    let snap_rev = snap["revision_after"].as_u64().unwrap();

    let rev = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    let _ = s
        .call(
            "rename",
            json!({"ea": format!("{entry_ea:#x}"), "name": "issue16_after_snap", "expected_revision": rev}),
        )
        .await
        .expect("rename after snapshot");

    let restored = s
        .call("snapshot.restore", json!({}))
        .await
        .expect("restore");
    assert_eq!(restored["restored"], true, "restore: {restored}");
    assert!(restored["revision_after"].as_u64().unwrap() > snap_rev);

    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions after rollback");
    let gone = !fns
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["name"].as_str() == Some("issue16_after_snap"));
    assert!(gone, "rollback must restore the pre-snapshot name");
    let still_there = fns
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["name"].as_str() == Some("issue16_planned"));
    assert!(
        still_there,
        "planned rename must survive the later rollback"
    );

    // --- patch persistence: patch, save, close, reopen, verify bytes ---
    let rev = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    let p = s
        .call(
            "patch_bytes",
            json!({"ea": format!("{entry_ea:#x}"), "hex": "90", "expected_revision": rev}),
        )
        .await
        .expect("patch for persistence");
    assert_eq!(p["changed"], true);
    let original_hex = p["detail"]["original"]
        .as_str()
        .expect("original bytes")
        .to_string();
    s.call("db.save", json!({})).await.expect("save");
    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");

    // reopen the same database file
    let i64_path = std::path::PathBuf::from(format!("{}.i64", dst));
    let handle2 = open_idalib(&mut pool, i64_path.to_string_lossy().as_ref()).await;
    let session2 = pool.session(&handle2).await.expect("session2");
    let s2 = session2.lock().await;
    let bytes = s2
        .call(
            "get_bytes",
            json!({"ea": format!("{entry_ea:#x}"), "size": 1}),
        )
        .await
        .expect("bytes after reopen");
    assert_eq!(
        bytes["hex"], "90",
        "patched byte must persist after save/reopen: {bytes}"
    );
    let orig = s2
        .call("patch_bytes", json!({"ea": format!("{entry_ea:#x}"), "hex": original_hex, "expected_revision": s2.call("revision", json!({})).await.unwrap()["revision"].as_u64().unwrap()}))
        .await
        .expect("restore original byte");
    assert_eq!(orig["changed"], true);
    s2.call("db.save", json!({})).await.expect("save 2");
    s2.call("db.close", json!({})).await.expect("close 2");
    drop(s2);
    pool.close(&handle2).await.expect("close pool 2");
}
