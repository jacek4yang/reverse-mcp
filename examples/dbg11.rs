use rmcp_broker::WorkerPool;
use std::path::PathBuf;
#[tokio::main]
async fn main() {
    let src = PathBuf::from("tests/fixtures/types.exe");
    let dst = std::env::temp_dir().join("reverse-mcp-it-11.exe");
    std::fs::copy(&src, &dst).unwrap();
    let i64p = std::path::PathBuf::from(format!("{}.i64", dst.display()));
    let _ = std::fs::remove_file(&i64p);
    let mut pool = WorkerPool::new();
    pool.set_ida_dir(PathBuf::from("D:\\Applications\\IDA_Professional"));
    let h = pool
        .spawn_for(dst.to_str().unwrap(), 4, "idalib", "")
        .await
        .unwrap();
    let sess = pool.session(&h).await.unwrap();
    let s = sess.lock().await;
    let fns = s
        .call("functions", serde_json::json!({"offset": 0, "limit": 6000}))
        .await
        .unwrap();
    let arr = fns.as_array().unwrap();
    for f in arr {
        println!(
            "FN {} {}",
            f["ea_start"],
            f["name"].as_str().unwrap_or_default()
        );
    }
    eprintln!("DONE listing, closing");
    drop(s);
    pool.close(&h).await.unwrap();
    eprintln!("CLOSED");
}
