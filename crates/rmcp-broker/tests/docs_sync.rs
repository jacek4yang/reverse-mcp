//! #49 anti-drift guard: docs must match the code exactly.
//!
//! Fails CI when the tool count claimed in README/docs diverges from the
//! registry, or when MCP_TOOLS.md tool sections drift from the registered
//! tool names.

use std::path::Path;

fn repo_root() -> &'static Path {
    // CARGO_MANIFEST_DIR is crates/rmcp-broker; docs live at the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

fn read(rel: &str) -> String {
    let p = repo_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

#[test]
fn tool_count_matches_registry() {
    let mut names = rmcp_broker::registry::tool_names();
    names.sort_unstable();
    let count = names.len();

    // e2e test pins the exact count; keep this in sync with it.
    assert_eq!(
        count, 35,
        "registry tool count changed; update docs + e2e_stdio.rs"
    );
    // README must not claim a wrong count.
    let readme = read("README.md");
    assert!(
        readme.contains(&format!("{count} tools")),
        "README must state '{count} tools'"
    );
    assert!(
        !readme.contains("17 tools"),
        "README still claims '17 tools'"
    );

    // ARCHITECTURE testing table must reference the real count.
    let arch = read("docs/ARCHITECTURE.md");
    assert!(
        arch.contains(&format!("({count} tools)")),
        "docs/ARCHITECTURE.md e2e row must say '({count} tools)'"
    );
}

#[test]
fn mcp_tools_reference_covers_all_tools() {
    let mut registered = rmcp_broker::registry::tool_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    registered.sort();

    let doc = read("docs/MCP_TOOLS.md");
    let mut documented: Vec<String> = doc
        .lines()
        .filter_map(|l| l.strip_prefix("### ").map(|s| s.trim().to_string()))
        .filter(|s| s.starts_with("ida_"))
        .collect();
    documented.sort();

    assert_eq!(
        registered, documented,
        "docs/MCP_TOOLS.md sections must exactly match registered tools"
    );
}

#[test]
fn limitations_has_no_known_false_claims() {
    let doc = read("docs/LIMITATIONS.md");
    for stale in [
        "stdio only: no Streamable HTTP transport yet",
        "No worker crash recovery yet",
    ] {
        assert!(
            !doc.contains(stale),
            "docs/LIMITATIONS.md still claims: {stale}"
        );
    }
    // Status line must be present and pinned to the current year marker.
    assert!(
        doc.contains("Status: accurate as of"),
        "docs/LIMITATIONS.md is missing its 'Status: accurate as of' line"
    );
}
