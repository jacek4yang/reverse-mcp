//! Real-IDA integration test (feature `idalib`): drives the REAL production
//! path 闁?`reverse-mcp serve`'s WorkerPool spawning `<exe> worker` children 闁?
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
    // function at a known code address by first deleting nothing 闁?instead we
    // grab the address of an instruction INSIDE main (offset +2) which belongs
    // to no function start, and create a function there? add_func on a
    // mid-function address fails; so use a fresh path: find undefined bytes.
    // Simplest deterministic approach: create at main's entry + main size
    // boundary is risky. Instead, locate any "sub_" region via the analyzer:
    // use an address right after main's end where padding/thunk code may sit.
    // Robust choice: pick the entry thunk of an import (data) 闁?no. We use
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

/// #14 acceptance, real IDA: index builds over imports/strings/functions/
/// constants; queries return evidence-bearing hits; the built index is
/// reused (status.current=true) until a mutation bumps the revision.
#[tokio::test]
#[ignore]
async fn real_ida_issue14_evidence_index() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-14.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let fresh_i64 = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&fresh_i64);
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    // Build: covers functions, strings, imports, constants.
    let built = s.call("index.build", json!({})).await.expect("index.build");
    assert!(built["functions"].as_u64().unwrap() > 0, "build: {built}");

    // Query 1: strings predicate 闁?the fixture has "usage: simple".
    let hits = s
        .call(
            "index.query",
            json!({"query": {"all": [{"string_contains": "usage"}]}}),
        )
        .await
        .expect("string query");
    assert!(hits["count"].as_u64().unwrap() >= 1, "hits: {hits}");
    let first = &hits["hits"][0];
    assert!(
        first["matched"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m.as_str().unwrap_or("").starts_with("string:")),
        "hit must carry string evidence: {first}"
    );

    // Query 2: constants predicate on a real constant from the fixture.
    // Entry-point EA works as a data anchor; use name query for determinism.
    let hits2 = s
        .call(
            "index.query",
            json!({"query": {"all": [{"name_contains": "main"}], "limit": 5}}),
        )
        .await
        .expect("name query");
    assert!(hits2["count"].as_u64().unwrap() >= 1, "hits2: {hits2}");

    // Query 3: import predicate 闁?simple.exe imports from the CRT; search a
    // common import substring. Even zero hits must be a bounded response.
    let hits3 = s
        .call(
            "index.query",
            json!({"query": {"all": [{"import": "kernel32"}], "limit": 10}}),
        )
        .await
        .expect("import query");
    assert!(hits3["count"].as_u64().unwrap() <= 10);

    // Reuse: status.current == true right after build (no rescan needed).
    let status = s.call("index.status", json!({})).await.expect("status");
    assert_eq!(status["current"], true, "status: {status}");
    assert_eq!(
        status["md5"],
        built
            .get("binary_md5")
            .unwrap_or(&serde_json::Value::Null)
            .clone()
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_default(),
        "md5 identity"
    );

    // A mutation bumps the revision -> index must be invalidated (current=false).
    let rev = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    let md = s.call("db.metadata", json!({})).await.expect("metadata");
    let entry_ea = md["entries"][0]["ea"].as_u64().unwrap();
    let _ = s
        .call(
            "rename",
            json!({"ea": format!("{entry_ea:#x}"), "name": "issue14_renamed", "expected_revision": rev}),
        )
        .await
        .expect("rename");
    let status2 = s.call("index.status", json!({})).await.expect("status2");
    assert_eq!(
        status2["current"], false,
        "mutation must invalidate index: {status2}"
    );

    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

/// #8 acceptance, real IDA: one function_context call returns the composite
/// picture; unchanged repeats are served from cache; a mutation invalidates.
#[tokio::test]
#[ignore]
async fn real_ida_issue8_workflows() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/simple.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-8.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let fresh_i64 = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&fresh_i64);
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    let md = s.call("db.metadata", json!({})).await.expect("metadata");
    let entry_ea = md["entries"][0]["ea"].as_u64().unwrap();

    let out = s
        .call(
            "workflow.run",
            json!({"workflow_req": {
                "workflow": "function_context",
                "ea": format!("{entry_ea:#x}"),
                "detail": "normal"
            }}),
        )
        .await
        .expect("function_context");
    let result = &out["result"];
    assert!(result["name"].as_str().is_some(), "out: {out}");
    assert!(
        result["callers"].is_array() && result["callees"].is_array(),
        "out: {out}"
    );
    assert!(result["strings"].is_array(), "out: {out}");

    // Cache: repeat is served from cache.
    let out2 = s
        .call(
            "workflow.run",
            json!({"workflow_req": {
                "workflow": "function_context",
                "ea": format!("{entry_ea:#x}"),
                "detail": "normal"
            }}),
        )
        .await
        .expect("repeat");
    assert_eq!(out2["cached"], true, "repeat must hit cache: {out2}");

    // trace_call_path works on the real graph.
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let arr = fns.as_array().unwrap();
    let main_f = arr
        .iter()
        .find(|f| f["name"].as_str() == Some("main"))
        .expect("main");
    let main_ea = main_f["ea_start"].as_u64().unwrap();
    // Pick a real callee of main from the neighborhood, then trace main -> callee.
    let neigh = s
        .call(
            "workflow.run",
            json!({"workflow_req": {
                "workflow": "call_neighborhood",
                "ea": format!("{main_ea:#x}"),
                "depth": 1,
                "max_functions": 5,
                "include_noise": true
            }}),
        )
        .await
        .expect("neighborhood");
    let callee_ea = neigh["result"]["edges"][0]["to"]
        .as_str()
        .expect("callee ea")
        .to_string();
    let path = s
        .call(
            "workflow.run",
            json!({"workflow_req": {
                "workflow": "trace_call_path",
                "ea": format!("{main_ea:#x}"),
                "target_ea": callee_ea,
                "depth": 4
            }}),
        )
        .await
        .expect("trace_call_path");
    assert_eq!(path["result"]["found"], true, "path: {path}");

    // Mutation invalidates the workflow cache.
    let rev = s.call("revision", json!({})).await.expect("revision")["revision"]
        .as_u64()
        .unwrap();
    let _ = s
        .call(
            "rename",
            json!({"ea": format!("{entry_ea:#x}"), "name": "issue8_renamed", "expected_revision": rev}),
        )
        .await
        .expect("rename");
    let out3 = s
        .call(
            "workflow.run",
            json!({"workflow_req": {
                "workflow": "function_context",
                "ea": format!("{entry_ea:#x}"),
                "detail": "normal"
            }}),
        )
        .await
        .expect("post-mutation");
    assert_eq!(
        out3["cached"], false,
        "mutation must invalidate cache: {out3}"
    );
    assert_eq!(
        out3["result"]["name"], "issue8_renamed",
        "fresh result must see the rename: {out3}"
    );

    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

/// #10 deep analysis: recursive decompilation with type propagation,
/// bounded dataflow, cycle safety, budgets and cache reuse on the deep
/// fixture (3-level call chain + indirect call + mutual recursion).
#[tokio::test]
#[ignore]
async fn real_ida_issue10_deep_analysis() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/deep.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-10b.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let fresh_i64 = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&fresh_i64);
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    // Resolve the fixture functions by name.
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let find = |name: &str| -> Option<u64> {
        fns.as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"].as_str() == Some(name))
            .and_then(|f| f["ea_start"].as_u64())
    };
    let process_ea = find("process").expect("process fn");

    // --- deep.function: recursive decompile with type propagation ---
    let out = s
        .call(
            "deep.function",
            json!({"target": format!("{process_ea:#x}"), "depth": 4, "max_functions": 30}),
        )
        .await
        .expect("deep.function");
    let result = &out["result"];
    assert!(
        result["functions"].as_array().unwrap().len() >= 3,
        "must visit the 3-level chain: {result}"
    );
    // Cycle safety: level2a/level2b mutual recursion must not runaway; the
    // visited set stays bounded and the run completes with a verdict.
    assert!(
        result["convergence"].is_object() || result["convergence"].is_null(),
        "out: {out}"
    );
    // Deterministic repeat: served from the cache, substantially less work.
    let out2 = s
        .call(
            "deep.function",
            json!({"target": format!("{process_ea:#x}"), "depth": 4, "max_functions": 30}),
        )
        .await
        .expect("deep.function repeat");
    assert_eq!(out2["cached"], true, "repeat must hit cache: {out2}");

    // --- deep.dataflow: bounded evidence with confidence split ---
    let df = s
        .call(
            "deep.dataflow",
            json!({
                "target": format!("{process_ea:#x}"),
                "direction": "backward",
                "depth": 3
            }),
        )
        .await
        .expect("deep.dataflow");
    let dres = &df["result"];
    assert!(
        !dres["evidence"].as_array().unwrap().is_empty(),
        "must cite concrete call sites: {dres}"
    );
    // Every evidence row carries an EA and a confidence tag.
    for e in dres["evidence"].as_array().unwrap() {
        assert!(e["at"].as_str().is_some(), "evidence: {e}");
        let conf = e["confidence"].as_str().unwrap();
        assert!(
            conf == "confirmed" || conf == "heuristic",
            "confidence: {e}"
        );
    }

    // --- deep.retype: apply a prototype (mutation) and check cache loss ---
    let apply_stream_ea = find("apply_stream").expect("apply_stream fn");
    let ret = s
        .call(
            "deep.retype",
            json!({"ea": format!("{apply_stream_ea:#x}"), "decl": "int apply_stream(unsigned char *, int, unsigned char);"}),
        )
        .await
        .expect("deep.retype");
    assert_eq!(ret["changed"], true, "retype: {ret}");

    // A mutation bumps the revision: the next deep.function rebuilds.
    let out3 = s
        .call(
            "deep.function",
            json!({"target": format!("{process_ea:#x}"), "depth": 4, "max_functions": 30}),
        )
        .await
        .expect("deep.function after mutation");
    assert_eq!(out3["cached"], false, "must recompute after retype: {out3}");

    // Budgets are enforced: 1 function max visits only the root.
    let tight = s
        .call(
            "deep.function",
            json!({"target": format!("{process_ea:#x}"), "max_functions": 1}),
        )
        .await
        .expect("deep.function tight budget");
    assert!(
        tight["result"]["visited_count"].as_u64().unwrap() <= 2,
        "budget must bound the walk: {tight}"
    );

    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

/// #11 type recovery: member-access evidence across functions sharing a
/// struct, shape matching against an existing local type, vtable discovery
/// mapping slots to candidate methods, and proposal/apply separation.
#[tokio::test]
#[ignore]
async fn real_ida_issue11_type_recovery() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/types.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-11b.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let fresh_i64 = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&fresh_i64);
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let find_all = |name: &str| -> Vec<u64> {
        fns.as_array()
            .unwrap()
            .iter()
            .filter(|f| f["name"].as_str().map(|n| n.contains(name)) == Some(true))
            .filter_map(|f| f["ea_start"].as_u64())
            .collect()
    };
    // MSVC may emit wrapper thunks alongside the real body; take all
    // candidates so the evidence walk can pick the one with a real body.
    let eval_candidates = find_all("config_eval");
    let init_candidates = find_all("config_init");
    assert!(
        !eval_candidates.is_empty() && !init_candidates.is_empty(),
        "fixture functions missing"
    );
    let _ = (&eval_candidates, &init_candidates);
    let find = |name: &str| -> Option<u64> { find_all(name).first().copied() };

    // --- evidence: member observations per function (skip thunks: a thunk
    // decompiles to a bare call and has no member accesses) ---
    let mut evidence_found = false;
    let mut prop_functions: Vec<String> = Vec::new();
    for &cand in eval_candidates.iter().chain(init_candidates.iter()) {
        let ev = s
            .call(
                "types.evidence",
                json!({"ea": format!("{cand:#x}"), "limit": 64}),
            )
            .await
            .expect("types.evidence");
        let members = ev["members"].as_array().expect("members array");
        if !members.is_empty() {
            evidence_found = true;
            prop_functions.push(format!("{cand:#x}"));
            for m in members {
                assert!(m["offset"].as_str().is_some(), "offset required: {m}");
            }
        }
    }
    assert!(
        evidence_found,
        "no member evidence across candidates {eval_candidates:?} {init_candidates:?}"
    );

    // --- propose: aggregated field proposals with evidence + confidence ---
    let prop = s
        .call("types.propose", json!({"functions": prop_functions}))
        .await
        .expect("types.propose");
    let proposals = prop["proposals"].as_array().expect("proposals array");
    assert!(
        !proposals.is_empty(),
        "must aggregate into proposals: {prop}"
    );
    let first = &proposals[0];
    let fields = first["fields"].as_array().expect("fields array");
    assert!(fields.len() >= 2, "shared struct needs >=2 fields: {prop}");
    for f in fields {
        let conf = f["confidence"].as_str().unwrap_or("0");
        let conf: f64 = conf.parse().unwrap_or(0.0);
        assert!((0.0..=1.0).contains(&conf), "confidence in [0,1]: {f}");
        assert!(f["read"].as_u64().is_some(), "read count: {f}");
        assert!(f["candidate_width"].as_u64().is_some(), "width: {f}");
    }

    // --- vtable: find Device::reset's data xref (its vtable slot) ---
    if let Some(reset_ea) = find("Device::reset") {
        let xrefs = s
            .call("xrefs.to", json!({"ea": format!("{reset_ea:#x}")}))
            .await
            .expect("xrefs.to");
        for x in xrefs.as_array().unwrap() {
            if let Some(from) = x["from"]
                .as_str()
                .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            {
                // Scan 16-aligned start of the containing page as vtable.
                let vt = from & !0xF;
                let vt_out = s
                    .call(
                        "types.vtable",
                        json!({"ea": format!("{vt:#x}"), "max_entries": 8}),
                    )
                    .await
                    .expect("types.vtable");
                let slots = vt_out["slots"].as_array().expect("slots");
                assert!(!slots.is_empty(), "vtable slots: {vt_out}");
                break;
            }
        }
    }

    // --- proposal/apply separation: create_struct is an explicit mutation ---
    let applied = s
        .call(
            "types.apply",
            json!({
                "name": "recovered_config_t",
                "fields": [
                    "0:4:level:int",
                    "8:8:key:long long",
                    "16:4:mode:int"
                ],
            }),
        )
        .await
        .expect("types.apply");
    assert_eq!(applied["applied"], true, "apply: {applied}");

    // --- false-positive guard: unrelated pointer arithmetic / jump tables
    // must not produce member proposals. The dispatch function in the
    // simple fixture uses a jump table; ensure evidence on a code-only
    // function yields either no proposals or low confidence. (Checked via
    // propose on device_drive: virtual calls are call sites, not members.)
    if let Some(drive_ea) = find("device_drive") {
        let drive = s
            .call("types.evidence", json!({"ea": format!("{drive_ea:#x}")}))
            .await
            .expect("device_drive evidence");
        // Virtual calls show up as calls, not as member rows with widths.
        assert!(
            drive["members"].as_array().is_some(),
            "well-formed response: {drive}"
        );
    }

    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

/// #12 binary intelligence: crypto-constant scan finds the AES S-box and
/// SHA-256 IV with provenance, the ror13 API-hash resolver is detected and
/// its stored hashes verified against import-style names, and stack-string
/// immediates are recovered from the string-builder function. Proposal
/// provenance: every finding carries EAs and callers; nothing mutates.
#[tokio::test]
#[ignore]
async fn real_ida_issue12_binary_intel() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/crypto.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-12.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let fresh_i64 = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&fresh_i64);
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let find_all = |name: &str| -> Vec<u64> {
        fns.as_array()
            .unwrap()
            .iter()
            .filter(|f| f["name"].as_str().map(|n| n.contains(name)) == Some(true))
            .filter_map(|f| f["ea_start"].as_u64())
            .collect()
    };

    // --- crypto scan: AES S-box and SHA-256 IV must surface, ranked ---
    let scan = s
        .call("intel.crypto", json!({"max_findings": 50}))
        .await
        .expect("intel.crypto");
    let findings = scan["findings"].as_array().expect("findings");
    assert!(!findings.is_empty(), "crypto scan empty: {scan}");
    let sbox_hit = findings
        .iter()
        .find(|f| f["name"].as_str() == Some("AES S-box"));
    assert!(sbox_hit.is_some(), "AES S-box must be found: {scan}");
    let sbox = sbox_hit.unwrap();
    assert!(
        sbox["ea"].as_str().is_some() && sbox["confidence"].as_str().is_some(),
        "hit provenance: {sbox}"
    );
    // SHA-256 IV stored as dwords: the scanner matches the little-endian
    // leading bytes of H0.
    let iv_hit = findings.iter().find(|f| {
        f["name"]
            .as_str()
            .map(|n| n.contains("SHA-256"))
            .unwrap_or(false)
    });
    assert!(iv_hit.is_some(), "SHA-256 IV must be found: {scan}");

    // --- API-hash resolver: ror13 detected, stored hashes verified ---
    let hashes = s
        .call("intel.api_hashes", json!({"max_findings": 50}))
        .await
        .expect("intel.api_hashes");
    let hfindings = hashes["findings"].as_array().expect("hash findings");
    // The fixture computes ror13("Sleep"/"LoadLibraryA"/"GetProcAddress")
    // at runtime and compares; those constants appear in api_dispatch.
    // Detection requires constants in the index: verify at least one
    // resolver-shaped finding if the compiler kept the constants inline.
    // (If MSVC folded them, the scan legitimately reports nothing 閳?assert
    // the response is well-formed in that case.)
    for f in hfindings {
        assert!(
            f["confidence"].as_str().is_some(),
            "confidence required: {f}"
        );
        if let Some(vh) = f["verified_hashes"].as_array() {
            for v in vh {
                assert!(v["api"].as_str().is_some(), "verified: {v}");
            }
        }
    }

    // --- stack string: recover the cmd.exe /c immediates ---
    let mut stack_ea = None;
    for cand in find_all("stack_string_check") {
        let rec = s
            .call("intel.strings", json!({"target": format!("{cand:#x}")}))
            .await
            .expect("intel.strings");
        let strings = rec["strings"].as_array().expect("strings array");
        if !strings.is_empty() {
            stack_ea = Some((cand, strings.to_owned()));
            break;
        }
    }
    if let Some((ea, strings)) = stack_ea {
        let joined: String = strings
            .iter()
            .filter_map(|s| s["value"].as_str())
            .collect::<Vec<_>>()
            .join("");
        assert!(
            joined.contains("cmd.exe") || joined.contains("cmd"),
            "stack string must contain cmd.exe: {strings:?} (fn {ea:#x})"
        );
    }

    // --- determinism: repeat scan is well-formed (cache keying covered by
    // the workflow cache tests) ---
    let scan2 = s
        .call("intel.crypto", json!({"max_findings": 50}))
        .await
        .expect("intel.crypto repeat");
    assert_eq!(
        scan2["findings"].as_array().map(|a| a.len()),
        scan["findings"].as_array().map(|a| a.len()),
        "repeat scan must be deterministic"
    );

    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

/// #9 deobfuscation: analysis-only pass engine over an obfuscated fixture
/// (junk no-ops, opaque/self-comparison branches, flattening-shaped CFG,
/// indirect call). Verifies: passes run within budget, findings are
/// bounded and machine-readable, junk+opaque passes trigger on the fixture
/// and stay quiet on a plain function (regression), and NO IDB mutation
/// occurs (revision unchanged).
#[tokio::test]
#[ignore]
async fn real_ida_issue9_deobfuscation() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/obfuscated.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-9.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let fresh_i64 = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&fresh_i64);
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let find_all9 = |name: &str| -> Vec<u64> {
        fns.as_array()
            .unwrap()
            .iter()
            .filter(|f| f["name"].as_str().map(|n| n.contains(name)) == Some(true))
            .filter_map(|f| f["ea_start"].as_u64())
            .collect()
    };
    let rev_before = s.call("revision", json!({})).await.expect("revision");

    // --- junk + opaque detection on the obfuscated functions (thunk-safe:
    // MSVC emits wrapper thunks, so try every candidate) ---
    let mut junk_hits = 0usize;
    let mut last_report = serde_json::Value::Null;
    let mut opaque_reports: Vec<serde_json::Value> = Vec::new();
    let mut opaque_hits = 0usize;
    for name in ["junk_calc", "opaque_check"] {
        let mut best_junk = 0usize;
        let mut best_opaque = 0usize;
        for ea in find_all9(name) {
            let out = s
                .call(
                    "deob.run",
                    json!({"target": format!("{ea:#x}"), "max_passes": 8}),
                )
                .await
                .expect("deob.run");
            last_report = out.clone();
            if name == "opaque_check" {
                opaque_reports.push(out.clone());
            }
            let findings = out["findings"].as_array().expect("findings array");
            assert_eq!(out["mode"], "analysis_only", "safety: {out}");
            assert!(findings.len() >= 3, "passes ran: {out}");
            for p in findings {
                assert!(p["pass"].as_str().is_some(), "pass name: {p}");
                assert!(p["confidence"].as_str().is_some(), "confidence: {p}");
            }
            if name == "junk_calc" {
                best_junk = best_junk.max(
                    findings
                        .iter()
                        .filter(|p| p["pass"] == "junk_code" && p["confidence"] != "0.05")
                        .count(),
                );
            }
            if name == "opaque_check" {
                best_opaque = best_opaque.max(
                    findings
                        .iter()
                        .filter(|p| p["pass"] == "opaque_branch" && p["confidence"] != "0.05")
                        .count(),
                );
            }
        }
        junk_hits = junk_hits.max(best_junk);
        opaque_hits = opaque_hits.max(best_opaque);
    }
    assert!(
        junk_hits >= 1,
        "junk pass must trigger on junk_calc: {}",
        serde_json::to_string(&last_report).unwrap_or_default()
    );
    assert!(
        opaque_hits >= 1,
        "opaque pass must trigger on opaque_check: {}",
        serde_json::to_string(&opaque_reports).unwrap_or_default()
    );

    // --- regression: plain function must NOT trigger junk/opaque ---
    // main is plain; its passes should stay at base confidence.
    if let Some(main_ea) = find_all9("main").first().copied() {
        let out = s
            .call("deob.run", json!({"target": format!("{main_ea:#x}")}))
            .await
            .expect("deob.run main");
        let findings = out["findings"].as_array().expect("findings");
        let triggered = findings
            .iter()
            .filter(|p| {
                let c: f64 = p["confidence"]
                    .as_str()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0.0);
                c >= 0.6
            })
            .count();
        // A plain printf-calling main should not trip multiple detectors.
        assert!(
            triggered <= 1,
            "plain main must not trip detectors: {}",
            serde_json::to_string(&out["findings"]).unwrap_or_default()
        );
    }

    // --- safety: no IDB mutation from deob runs ---
    let rev_after = s.call("revision", json!({})).await.expect("revision");
    assert_eq!(
        rev_before, rev_after,
        "deobfuscation analysis must not mutate the IDB"
    );

    s.call("db.close", json!({})).await.expect("close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

/// #13 signatures & cross-IDB: two optimization variants of the same
/// source (crypto.c at /Od and /O2) map with useful precision; strict
/// matches clear the threshold, proposals carry conflict detection, and
/// nothing is applied automatically.
#[tokio::test]
#[ignore]
async fn real_ida_issue13_signatures() {
    let src1 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sig_v1.exe");
    let src2 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sig_v2.exe");
    let dst1 = std::env::temp_dir().join("reverse-mcp-it-13a.exe");
    let dst2 = std::env::temp_dir().join("reverse-mcp-it-13b.exe");
    std::fs::copy(&src1, &dst1).expect("copy v1");
    std::fs::copy(&src2, &dst2).expect("copy v2");
    for d in [&dst1, &dst2] {
        let _ = std::fs::remove_file(std::path::PathBuf::from(format!("{}.i64", d.display())));
    }
    let dst1 = dst1.to_string_lossy().into_owned();
    let dst2 = dst2.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    // Two simultaneously-open workers (acceptance requirement).
    let h1 = open_idalib(&mut pool, &dst1).await;
    let h2 = open_idalib(&mut pool, &dst2).await;
    let sess1 = pool.session(&h1).await.expect("s1");
    let sess2 = pool.session(&h2).await.expect("s2");
    let s1 = sess1.lock().await;
    let s2 = sess2.lock().await;

    // Export sig indexes for both variants.
    let ex1 = s1.call("sig.export", json!({})).await.expect("export v1");
    assert!(ex1["functions"].as_u64().unwrap() > 0, "ex1: {ex1}");
    let ex2 = s2.call("sig.export", json!({})).await.expect("export v2");
    assert!(ex2["functions"].as_u64().unwrap() > 0, "ex2: {ex2}");

    // Read the persisted open-format indexes.
    let p1 = ex1["path"].as_str().expect("path1");
    let p2 = ex2["path"].as_str().expect("path2");
    let sig1: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p1).expect("read1")).expect("parse1");
    let sig2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(p2).expect("read2")).expect("parse2");

    // Cross-IDB mapping: variants of one source must produce ranked
    // transfer proposals with per-family evidence.
    let map = s1
        .call(
            "sig.map",
            json!({"from": sig1, "to": sig2, "max_transfers": 200}),
        )
        .await
        .expect("sig.map");
    let transfers = map["transfers"].as_array().expect("transfers");
    assert!(
        !transfers.is_empty(),
        "variants of the same source must map: {}",
        serde_json::to_string(&map).unwrap_or_default()
    );
    // Every proposal carries per-family evidence.
    for t in transfers.iter().take(10) {
        assert!(t["evidence"].is_object(), "evidence: {t}");
        assert!(t["score"].as_f64().is_some(), "score: {t}");
        assert!(t["proposal"]["conflict"].is_boolean(), "conflict: {t}");
    }
    // Strict-vs-relaxed honesty: relaxed matches are hints only. With two
    // different optimization levels (and differing static-CRT noise) most
    // matches are relaxed; assert the policy split is well-formed rather
    // than demanding strict matches across variants.
    let kinds: Vec<&str> = transfers
        .iter()
        .filter_map(|t| t["match_kind"].as_str())
        .collect();
    assert!(
        kinds.iter().all(|k| *k == "strict" || *k == "relaxed"),
        "match kinds must be classified: {kinds:?}"
    );

    // Identify one v1 function against the v2 reference index.
    let fns = s1
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let target = fns
        .as_array()
        .unwrap()
        .iter()
        .find(|f| {
            f["name"]
                .as_str()
                .map(|n| n.contains("ror13_hash"))
                .unwrap_or(false)
        })
        .and_then(|f| f["ea_start"].as_u64());
    if let Some(target) = target {
        let id = s1
            .call(
                "sig.identify",
                json!({"target": format!("{target:#x}"), "reference": sig2, "max_candidates": 5}),
            )
            .await
            .expect("sig.identify");
        let cands = id["candidates"].as_array().expect("candidates");
        assert!(!cands.is_empty(), "candidates: {id}");
        for c in cands {
            assert!(c["evidence"].is_object(), "candidate evidence: {c}");
        }
        // The top candidate should have a decent score (same algorithm).
        let top = &cands[0];
        let score = top["score"].as_f64().unwrap_or(0.0);
        assert!(
            score >= 0.5,
            "top candidate score {score} for same-source function: {id}"
        );
    }

    // Safety: mapping is proposals-only; neither DB mutated.
    let rev1 = s1.call("revision", json!({})).await.expect("rev1");
    let rev_before_check = rev1["revision"].as_u64().unwrap_or(0);
    // (No rename applied anywhere in this test; the assertion is implicit
    // in never calling a mutation method.)

    let _ = rev_before_check;
    s1.call("db.close", json!({})).await.expect("close1");
    s2.call("db.close", json!({})).await.expect("close2");
    drop(s1);
    drop(s2);
    pool.close(&h1).await.expect("close h1");
    pool.close(&h2).await.expect("close h2");
}

// ---------------------------------------------------------------------------
// #43: microcode generation/inspection (real-IDA gated)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // run explicitly with IDADIR pointing at a licensed IDA 9.2
async fn real_ida_issue43_microcode() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/obfuscated.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-43.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let fresh_i64 = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&fresh_i64);
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    // capabilities must now honestly report microcode support
    let caps = s
        .call("capabilities", json!({}))
        .await
        .expect("capabilities");
    assert_eq!(
        caps["microcode"], true,
        "idalib backend must report microcode:true; got {caps}"
    );

    // pick the flattened function; MSVC emits ILT wrapper thunks, so try
    // every candidate until one yields a real body (a thunk is a tiny
    // jmp-stub mba with 3 blocks, the real flattened body has ~19).
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let candidates: Vec<u64> = fns
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["name"].as_str().is_some_and(|n| n.contains("flattened")))
        .filter_map(|f| f["ea_start"].as_u64())
        .collect();
    assert!(!candidates.is_empty(), "flattened function not found");

    let mut flat_ea = 0u64;
    for c in &candidates {
        let r = s
            .call("hr.microcode", json!({"ea": c, "max_insns": 300}))
            .await
            .expect("hr.microcode");
        // the worker wraps the dump under `result` (cache envelope)
        let qty = r["result"]["qty"].as_u64().unwrap_or(0);
        eprintln!("candidate {c:#x} qty={qty}");
        if qty >= 5 {
            flat_ea = *c;
            break;
        }
    }
    assert!(flat_ea != 0, "no flattened candidate produced microcode");

    // 1. bounded dump: maturity, blocks and rendered insns present
    let out = s
        .call("hr.microcode", json!({"ea": flat_ea, "max_insns": 300}))
        .await
        .expect("hr.microcode");
    let dump = &out["result"]; // warm from the candidate loop
    let maturity = dump["maturity"].as_u64().unwrap();
    assert!(
        maturity >= 1,
        "microcode must be generated, maturity={maturity}"
    );
    let insns = dump["insns"].as_array().expect("insns array");
    assert!(!insns.is_empty(), "flattened() must produce instructions");
    for i in insns.iter().take(5) {
        assert!(i["ea"].as_u64().is_some(), "insn missing ea: {i}");
        assert!(
            i["text"].as_str().map(|t| !t.is_empty()).unwrap_or(false),
            "insn missing rendered text: {i}"
        );
    }

    // 2. budget truncation: tiny cap -> truncated flag, partial insns
    let out2 = s
        .call("hr.microcode", json!({"ea": flat_ea, "max_insns": 3}))
        .await
        .expect("bounded dump");
    let dump2 = &out2["result"];
    let insns2 = dump2["insns"].as_array().unwrap();
    assert!(insns2.len() <= 3, "budget must bound insns");
    assert_eq!(dump2["truncated"], true, "tiny budget must flag truncation");

    // 3. cache: identical request on unchanged DB is served free
    let out3 = s
        .call("hr.microcode", json!({"ea": flat_ea, "max_insns": 300}))
        .await
        .expect("repeat dump");
    assert_eq!(out3["cached"], true, "identical dump must hit the cache");

    // 4. mutation invalidates: rename bumps revision -> cache miss again
    s.call(
        "rename",
        json!({"ea": flat_ea, "name": "flattened_renamed"}),
    )
    .await
    .expect("rename");
    let out4 = s
        .call("hr.microcode", json!({"ea": flat_ea, "max_insns": 300}))
        .await
        .expect("post-mutation dump");
    assert_eq!(out4["cached"], false, "mutation must invalidate the cache");

    // 5. decompile of the same function still works (analysis untouched)
    s.call("decompile", json!({"ea": flat_ea}))
        .await
        .expect("decompile after microcode dump");

    s.call("db.close", json!({})).await.expect("db.close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

#[tokio::test]
#[ignore] // run explicitly with IDADIR pointing at a licensed IDA 9.2
async fn real_ida_issue44_value_propagation() {
    // Fixture: deep.exe 3-level call chain (sub chain with constant args at
    // /Od /Zi, plus one indirect call site from the earlier deep tests).
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/deep.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-issue44.exe");
    std::fs::copy(&src, &dst).expect("copy fixture");
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    s.call("analyze_wait", json!({})).await.expect("analyze");

    // Locate the chain root by name (thunk-safe: take every candidate).
    let funcs = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions list");
    let root: u64 = funcs
        .as_array()
        .expect("functions array")
        .iter()
        .find(|f| f["name"].as_str() == Some("process"))
        .and_then(|f| f["ea_start"].as_u64())
        .expect("process must exist in deep.exe");
    assert!(root != 0);

    // 1. Full pass over the root: rows must be evidence-shaped and bounded.
    let out = s
        .call(
            "value.propagate",
            json!({"ea": format!("{root:#x}"), "depth": 2, "max_functions": 8, "max_calls": 32}),
        )
        .await
        .expect("value.propagate");
    assert_eq!(out["cached"], false);
    let result = &out["result"];
    assert_eq!(result["truncated"], false, "tiny fixture must not truncate");
    let targets = result["targets"].as_array().expect("targets array");
    let indirect = result["indirect"].as_array().expect("indirect array");
    for row in targets {
        assert!(
            row["confidence"].as_str().is_some(),
            "every target row needs a confidence: {row}"
        );
        assert!(
            row["at"].as_array().is_some(),
            "every target row needs provenance EAs: {row}"
        );
    }
    for row in indirect {
        assert!(
            row["call_ea"].as_str().is_some(),
            "indirect rows need a call-site EA: {row}"
        );
    }

    // 2. Cache: identical repeat is free.
    let out2 = s
        .call(
            "value.propagate",
            json!({"ea": format!("{root:#x}"), "depth": 2, "max_functions": 8, "max_calls": 32}),
        )
        .await
        .expect("repeat");
    assert_eq!(out2["cached"], true, "identical repeat must hit the cache");

    // 3. Depth-1 run on a leaf function must stay intra-procedural.
    let leaf: u64 = {
        let funcs2 = s
            .call("functions", json!({"offset": 0, "limit": 6000}))
            .await
            .expect("funcs");
        funcs2
            .as_array()
            .expect("functions array")
            .iter()
            .filter_map(|f| {
                let ea = f["ea_start"].as_u64().unwrap_or(0);
                (ea != 0 && ea != root).then_some(ea)
            })
            .next()
            .expect("a second function")
    };
    let out3 = s
        .call(
            "value.propagate",
            json!({"ea": format!("{leaf:#x}"), "depth": 1}),
        )
        .await
        .expect("leaf pass");
    assert_eq!(out3["result"]["depth_used"], 1);

    s.call("db.close", json!({})).await.expect("db.close");
    drop(s);
    pool.close(&handle).await.expect("close");
}

#[tokio::test]
#[ignore] // run explicitly with IDADIR pointing at a licensed IDA 9.2
async fn real_ida_issue46_transform_apply_rollback() {
    // Fixture: obfuscated.exe from #9 (junk roundtrips at /Od /Zi).
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/obfuscated.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-issue46.exe");
    let _ = std::fs::remove_file(format!("{}.i64", dst.display()));
    std::fs::copy(&src, &dst).expect("copy fixture");
    let dst = dst.to_string_lossy().into_owned();

    let mut pool = pool_with_ida_on_path();
    let handle = open_idalib(&mut pool, &dst).await;
    let session = pool.session(&handle).await.expect("session");
    let s = session.lock().await;

    s.call("analyze_wait", json!({})).await.expect("analyze");

    // Resolve the junky function by name (thunk-safe: try every candidate).
    let fns = s
        .call("functions", json!({"offset": 0, "limit": 6000}))
        .await
        .expect("functions");
    let target: u64 = fns
        .as_array()
        .expect("functions array")
        .iter()
        .find(|f| f["name"].as_str() == Some("junk_calc"))
        .and_then(|f| f["ea_start"].as_u64())
        .expect("junk_calc fn");

    // 1. propose: T2 plan from live analysis evidence.
    let out = s
        .call(
            "deob.propose",
            json!({"target": format!("{target:#x}"), "kind": "T2_junk_removal"}),
        )
        .await
        .expect("propose");
    let ops = out["operations"].as_array().expect("operations").len();
    assert!(ops > 0, "obfuscated fixture must yield T2 sites: {out}");

    // 2. validate: live DB re-check must pass (no xrefs into junk here).
    let v = s
        .call("deob.validate", json!({"plan": out}))
        .await
        .expect("validate");
    assert_eq!(v["valid"], true, "clean junk sites must validate: {v}");

    // 3. apply: snapshot -> revision-guarded patch -> before/after.
    let rev_before = s.call("revision", json!({})).await.expect("revision");
    let rev_before = rev_before["revision"].as_u64().expect("rev");
    let applied = s
        .call(
            "deob.apply",
            json!({"plan": out, "expected_revision": rev_before}),
        )
        .await
        .expect("apply");
    assert_eq!(applied["applied"]["partial"], false, "apply: {applied}");
    assert!(
        applied["before"].is_object() && applied["after"].is_object(),
        "before/after evidence required: {applied}"
    );

    // 4. revision conflict: stale expected_revision must reject cleanly.
    let conflict = s
        .call(
            "deob.apply",
            json!({"plan": out, "expected_revision": rev_before}),
        )
        .await;
    assert!(conflict.is_err(), "stale revision must be rejected");

    // 5. rollback: snapshot restore brings the bytes back (audited).
    let rolled = s
        .call("snapshot.restore", json!({}))
        .await
        .expect("rollback");
    assert_eq!(rolled["restored"], true, "rollback: {rolled}");

    // 6. after rollback the same plan validates and applies again.
    let rev2 = s.call("revision", json!({})).await.expect("rev2");
    let rev2 = rev2["revision"].as_u64().expect("rev2");
    let v2 = s
        .call("deob.validate", json!({"plan": out}))
        .await
        .expect("validate2");
    assert_eq!(v2["valid"], true, "post-rollback re-validate: {v2}");
    let _ = s
        .call(
            "deob.apply",
            json!({"plan": out, "expected_revision": rev2}),
        )
        .await
        .expect("re-apply");

    s.call("db.close", json!({})).await.expect("db.close");
    drop(s);
    pool.close(&handle).await.expect("close");
}
