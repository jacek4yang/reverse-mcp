//! Real-IDA integration test (feature `idalib`): drives reverse-mcp-worker
//! over its stdio protocol against a real binary analyzed by IDA 9.2 idalib.
//!
//! Chain verified (reverse-mcp-ffi.md item 7):
//! open -> analyze -> functions -> instruction -> xrefs -> strings ->
//! Hex-Rays decompile -> rename/comment -> save -> reopen.
//!
//! Requires IDADIR to point at an IDA 9.x install with a valid license.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};

use serde_json::{Value, json};

struct WorkerProc {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl WorkerProc {
    fn spawn() -> Self {
        let exe = env!("CARGO_BIN_EXE_reverse-mcp-worker");
        let mut cmd = Command::new(exe);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // The worker exe links ida.dll/idalib.dll; make sure they resolve.
        if let Ok(ida_dir) = std::env::var("IDADIR") {
            let path = std::env::var("PATH").unwrap_or_default();
            cmd.env("PATH", format!("{ida_dir};{path}"));
        }
        let mut child = cmd
            .spawn()
            .expect("spawn worker");
        let stdout = child.stdout.take().expect("worker stdout");
        let mut w = WorkerProc {
            child,
            reader: BufReader::new(stdout),
            next_id: 1,
        };
        // hello line
        let mut hello = String::new();
        w.reader.read_line(&mut hello).expect("hello");
        let v: Value = serde_json::from_str(&hello).expect("hello json");
        assert_eq!(v["protocol"], 1, "protocol version");
        w
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"id": id, "method": method, "params": params});
        let mut stdin = self.child.stdin.as_ref().expect("stdin");
        let line = format!("{req}\n");
        stdin.write_all(line.as_bytes()).expect("write req");
        stdin.flush().expect("flush req");
        let mut resp = String::new();
        self.reader.read_line(&mut resp).expect("read resp");
        let v: Value = serde_json::from_str(&resp).expect("resp json");
        assert_eq!(v["id"].as_u64(), Some(id), "response id mismatch");
        if let Some(err) = v.get("error") {
            panic!("{method} failed: {err}");
        }
        v["result"].clone()
    }
}

impl Drop for WorkerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn fixture_path() -> String {
    // CARGO_MANIFEST_DIR is crates/rmcp-worker; the fixture lives in the
    // workspace root's tests/fixtures directory.
    let dir = env!("CARGO_MANIFEST_DIR");
    let p = std::path::Path::new(dir)
        .join("../../tests/fixtures/simple.exe")
        .canonicalize()
        .expect("fixture exists");
    p.to_string_lossy().into_owned()
}

fn scratch_path() -> String {
    std::env::temp_dir()
        .join("reverse-mcp-it-simple.exe")
        .to_string_lossy()
        .into_owned()
}

#[test]
#[ignore] // run explicitly: cargo test -p rmcp-worker --features idalib -- --ignored
fn real_ida_full_chain() {
    // Copy fixture to a scratch path; IDA will create simple.i64 next to it.
    let src = fixture_path();
    let dst = scratch_path();
    std::fs::copy(&src, &dst).expect("copy fixture");

    let mut w = WorkerProc::spawn();

    // backend.select idalib (initializes the IDA library on the main thread)
    let r = w.call("backend.select", json!({"kind": "idalib"}));
    assert_eq!(r["backend"], "idalib");

    // 1. open (creates a new IDB for the binary, runs auto-analysis)
    let r = w.call(
        "db.open",
        json!({"path": dst}),
    );
    assert!(r.get("function_count").is_some() || r.get("path").is_some(), "open info: {r}");

    // 2. analyze wait
    let r = w.call("analyze_wait", json!({}));
    assert_eq!(r["analyzed"], true);
    let fn_count = r["functions"].as_u64().expect("function count");
    assert!(fn_count >= 5, "expected at least 5 functions, got {fn_count}");

    // 3. functions list contains our named functions
    let fns = w.call("functions", json!({"offset": 0, "limit": 500}));
    let arr = fns.as_array().expect("functions array");
    assert!(!arr.is_empty());
    let names: Vec<&str> = arr.iter().filter_map(|f| f["name"].as_str()).collect();
    let has_helper = names.iter().any(|n| n.contains("helper"));
    let has_decrypt = names.iter().any(|n| n.contains("decrypt_packet"));
    assert!(has_helper || has_decrypt, "named funcs missing: {names:?}");

    // helper function address for later steps
    let helper = arr
        .iter()
        .find(|f| f["name"].as_str().is_some_and(|n| n.contains("helper")))
        .expect("helper function")
        .clone();
    let helper_ea = helper["ea_start"].as_u64().expect("helper ea");

    // 4. instruction decode at helper
    let insns = w.call(
        "disassemble",
        json!({"ea": helper_ea, "max_insns": 8}),
    );
    let iarr = insns.as_array().expect("insns array");
    assert!(!iarr.is_empty(), "no instructions decoded at {helper_ea:#x}");
    assert!(iarr[0]["text"].as_str().is_some_and(|t| !t.is_empty()));

    // 5. xrefs: main calls helper
    let xrefs_to = w.call("xrefs_to", json!({"ea": helper_ea}));
    let xarr = xrefs_to.as_array().expect("xrefs array");
    assert!(!xarr.is_empty(), "expected call xrefs to helper");

    // 6. strings: the fixture has a "usage: simple" string (MSVC's own
    // runtime strings come first in .rdata, so search a large window)
    let strings = w.call("strings", json!({"offset": 0, "limit": 5000}));
    let sarr = strings.as_array().expect("strings array");
    let found_usage = sarr
        .iter()
        .any(|s| s["value"].as_str().is_some_and(|v| v.contains("usage")));
    assert!(found_usage, "usage string not found in {} strings", sarr.len());

    // 7. Hex-Rays decompile of helper
    let dec = w.call("decompile", json!({"ea": helper_ea}));
    let pseudo = dec["pseudocode"].as_str().expect("pseudocode");
    assert!(pseudo.contains("helper") || pseudo.contains("a + b") || pseudo.contains("return"),
        "unexpected pseudocode: {pseudo}");

    // 8. rename + comment
    let ren = w.call("rename", json!({"ea": helper_ea, "name": "helper_renamed_it"}));
    assert_eq!(ren["changed"], true);
    let cmt = w.call(
        "set_comment",
        json!({"ea": helper_ea, "comment": "it-test comment", "repeatable": false}),
    );
    assert_eq!(cmt["changed"], true);
    let got = w.call("get_comment", json!({"ea": helper_ea, "repeatable": false}));
    assert_eq!(got["comment"], "it-test comment");

    // 9. save (db.save) then close
    w.call("db.save", json!({}));
    w.call("db.close", json!({}));

    // 10. reopen and verify the rename survived
    let mut w2 = WorkerProc::spawn();
    w2.call("backend.select", json!({"kind": "idalib"}));
    w2.call("db.open", json!({"path": dst}));
    let fns2 = w2.call("functions", json!({"offset": 0, "limit": 500}));
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
    w2.call("db.close", json!({}));
}
