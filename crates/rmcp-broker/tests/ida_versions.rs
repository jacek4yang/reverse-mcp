//! Multi-version selection integration test (feature `idalib`, requires a
//! real IDA on this machine): verifies the broker's `ida_db open` honors
//! `ida_version` requirements — exact match, ranges, and refusal to
//! silently fall back when no installed version satisfies the requirement.

use rmcp_core::discovery::{IdaRequirement, discover_all, resolve};

#[test]
#[ignore] // run explicitly: cargo test -p rmcp-broker --features idalib -- --ignored
fn version_selection_flow() {
    // 0. There must be at least one discovered install (IDADIR or scan).
    let all = discover_all(None);
    assert!(
        !all.is_empty(),
        "no IDA installs discovered on this machine"
    );

    // 1. "latest" resolves to the highest-version, backend-ready install.
    let latest = resolve(&IdaRequirement::parse("latest").unwrap())
        .expect("latest must resolve when installs exist");
    let max_version = all
        .iter()
        .filter(|i| i.backend_ready())
        .map(|i| i.version)
        .max()
        .expect("at least one backend-ready install");
    assert_eq!(
        latest.version, max_version,
        "latest must pick highest ready"
    );

    // 2. Exact version of the ready install resolves to it.
    let key = latest.version.to_string();
    let exact = resolve(&IdaRequirement::parse(&key).unwrap()).expect("exact version resolves");
    assert_eq!(exact.version, latest.version);
    assert!(exact.backend_ready());

    // 3. A range excluding the installed version must fail listing candidates
    //    — never silently fall back.
    let (major, minor) = (latest.version.major, latest.version.minor);
    let lower = format!(">={major}.{minor},<{major}.{minor}");
    let err = resolve(&IdaRequirement::parse(&lower).unwrap()).unwrap_err();
    assert_eq!(err.code(), "ida_version_mismatch", "err: {err}");
    let msg = err.to_string();
    assert!(msg.contains("IDA"), "error must list candidates: {msg}");

    // 4. Open-ended range including the install resolves.
    let open_ended = format!(">={major}.{minor}");
    let ok = resolve(&IdaRequirement::parse(&open_ended).unwrap())
        .expect("open-ended range including install resolves");
    assert!(ok.version >= latest.version);

    // 5. Backend status is surfaced per-install: every install whose
    //    version key isn't 9_2 must be marked unavailable.
    for inst in &all {
        if inst.version.backend_key() != "9_2" {
            assert!(
                !inst.backend_ready(),
                "unverified version {} must not be backend-ready",
                inst.version
            );
        }
    }
}

#[tokio::test]
#[ignore] // run explicitly: cargo test -p rmcp-broker --features idalib -- --ignored
async fn broker_open_with_version_params() {
    // Single-exe architecture: the pool spawns this exe in `worker` mode; no
    // worker binary to locate. The "auto" backend path tolerates mock-only
    // builds, so both outcomes are valid — the assertion is that resolution +
    // spawn + handshake all succeed.
    let mut pool = rmcp_broker::WorkerPool::new();

    // empty version = auto-select; "auto" falls back to mock when the
    // nearest worker binary is mock-only, so both outcomes are valid here —
    // the assertion is that resolution + spawn + handshake all succeed.
    // idalib strictly requires the input file to exist; create a tiny
    // scratch file so this test exercises resolution+spawn+handshake
    // regardless of which backend "auto" selects.
    let probe_path = std::env::temp_dir().join("selftest-idaver");
    std::fs::write(&probe_path, b"selftest").expect("write probe file");

    let handle = pool
        .spawn_for(&probe_path.to_string_lossy(), 4, "auto", "")
        .await
        .expect("auto-select open");
    let session = pool.session(&handle).await.expect("session");
    {
        let s = session.lock().await;
        let info = s
            .call("db.info", serde_json::json!({}))
            .await
            .expect("db.info");
        assert!(info.get("function_count").is_some(), "info: {info}");
    }
    pool.close(&handle).await.expect("close");
}
