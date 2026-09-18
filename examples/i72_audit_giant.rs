//! #72 audit: open the giant-switch fixture in real IDA 9.2 and document
//! exactly what whole-function Hex-Rays does, plus the IDA-native facts the
//! preflight can use. One report, one worker, bounded steps.

#![cfg(feature = "idalib")]

use rmcp_broker::WorkerPool;
use serde_json::json;

#[tokio::main]
async fn main() {
    let mut pool = WorkerPool::new();
    if let Ok(ida) = std::env::var("IDADIR") {
        pool.set_ida_dir(std::path::PathBuf::from(ida));
    }
    let db = "tests/fixtures/largefn/giant_switch_3000.dll";
    let h = pool
        .spawn_for(db, 8, "idalib", "9.2")
        .await
        .expect("open fixture");
    println!("opened: {h}");
    let session = pool.session(&h).await.expect("session");
    let s = session.lock().await;

    let fns = s
        .call("functions", json!({"offset": 0, "limit": 50}))
        .await
        .expect("functions");
    let arr = fns.as_array().cloned().unwrap_or_default();
    println!("functions: {}", arr.len());
    let mut target = None;
    for f in &arr {
        println!(
            "  {:#x}-{:#x} {} ({} bytes)",
            f["ea_start"].as_u64().unwrap_or(0),
            f["ea_end"].as_u64().unwrap_or(0),
            f["name"].as_str().unwrap_or("?"),
            f["size"].as_u64().unwrap_or(0)
        );
        if f["size"].as_u64().unwrap_or(0) > 10_000 {
            target = Some(f.clone());
        }
    }
    let Some(big) = target else {
        println!("AUDIT: no giant function found");
        return;
    };
    let ea = big["ea_start"].as_u64().unwrap();
    let size = big["size"].as_u64().unwrap();
    println!("giant fn at {ea:#x} size {size}");

    // IDA-native CFG facts (this is what the preflight will use).
    let graph = s
        .call("graph", json!({"ea": format!("{ea:#x}"), "kind": "cfg", "max_nodes": 10_000, "max_edges": 20_000}))
        .await;
    match graph {
        Ok(v) => {
            let nodes = v["graph"]["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
            let edges = v["graph"]["edges"].as_array().map(|a| a.len()).unwrap_or(0);
            println!("cfg: {nodes} nodes, {edges} edges (bounded query)");
        }
        Err(e) => println!("graph cfg ERR: {e}"),
    }

    // Whole-function Hex-Rays: the exact operation that fails/hangs today.
    let t0 = std::time::Instant::now();
    let dec = s
        .call_with_timeout(
            "decompile",
            json!({"ea": format!("{ea:#x}")}),
            std::time::Duration::from_secs(240),
        )
        .await;
    match dec {
        Ok(v) => {
            let text = v["pseudocode"].as_str().unwrap_or("");
            println!(
                "decompile OK in {:?}: {} bytes of pseudocode",
                t0.elapsed(),
                text.len()
            );
        }
        Err(e) => {
            println!("decompile FAILED after {:?}: {e}", t0.elapsed());
        }
    }

    // hr.cfunc for the same function (the tool the user hit in the UI).
    let t0 = std::time::Instant::now();
    let hr = s
        .call_with_timeout(
            "hr.cfunc",
            json!({"ea": format!("{ea:#x}"), "include_ctree": false, "include_lvars": false}),
            std::time::Duration::from_secs(240),
        )
        .await;
    match hr {
        Ok(v) => println!("hr.cfunc OK in {:?}", t0.elapsed()),
        Err(e) => println!("hr.cfunc FAILED after {:?}: {e}", t0.elapsed()),
    }

    drop(s);
    pool.close(&h).await.expect("close");
    println!("AUDIT DONE");
}
