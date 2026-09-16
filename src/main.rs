//! reverse-mcp — one binary: broker (MCP server) + self-spawned workers.
//!
//! Subcommands: serve | worker (internal) | doctor | open | sessions |
//! inspect | decompile | selftest | ida list | version.
//!
//! The broker spawns itself via `std::env::current_exe()` with the internal
//! `worker` subcommand, so the distributed artifact is a single exe.
//!
//! Windows note: with the `idalib` feature this binary links ida.dll /
//! idalib.dll. Those imports are delay-loaded (build.rs) so the broker and
//! mock-worker modes start without IDA on PATH; the real backend only needs
//! it once idalib is actually initialized.

mod bench;
mod cli;

use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("serve") => cmd_serve(args.get(1).map(String::as_str), &args).await,
        // Internal subcommand: the broker spawns `<exe> worker` per open DB.
        Some("worker") => {
            // Hidden helper: `--probe-backend <kind>` prints the kind and
            // exits 0 if this build supports it, used by the broker to detect
            // the real idalib backend without spawning a session.
            if args.get(1).map(String::as_str) == Some("--probe-backend") {
                let kind = args.get(2).map(String::as_str).unwrap_or("");
                if rmcp_worker::probe_backend(kind) {
                    println!("{kind}");
                    std::process::exit(0);
                }
                std::process::exit(1);
            }
            rmcp_worker::worker_main()
        }
        Some("doctor") => cmd_doctor(args.get(1).map(String::as_str)),
        Some("open") => cli::cmd_open(args.get(1).map(String::as_str).unwrap_or("")).await,
        Some("sessions") => cli::cmd_sessions().await,
        Some("inspect") => {
            cli::cmd_inspect(
                args.get(1).map(String::as_str),
                args.get(2).map(String::as_str),
            )
            .await
        }
        Some("decompile") => {
            cli::cmd_decompile(
                args.get(1).map(String::as_str),
                args.get(2).map(String::as_str),
            )
            .await
        }
        Some("selftest") => cli::cmd_selftest().await,
        Some("bench") => {
            let results = bench::run_mock_bench().await;
            let report = bench::report(&results);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            );
            if report["all_ok"] == true { 0 } else { 1 }
        }
        Some("ida") => match args.get(1).map(String::as_str) {
            Some("list") => cli::cmd_ida_list(args.get(2).map(String::as_str)),
            _ => {
                eprintln!("usage: reverse-mcp ida list");
                2
            }
        },
        Some("version") | Some("--version") | Some("-V") => {
            println!("reverse-mcp {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some(other) => {
            eprintln!(
                "unknown subcommand '{other}' (serve|doctor|ida list|open|sessions|inspect|decompile|selftest|version)"
            );
            2
        }
        None => {
            eprintln!(
                "usage: reverse-mcp <serve|doctor|ida list|open|sessions|inspect|decompile|selftest|version>"
            );
            2
        }
    };
    std::process::exit(code);
}

async fn cmd_serve(transport: Option<&str>, args: &[String]) -> i32 {
    let config = match rmcp_core::config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return 1;
        }
    };
    let broker = rmcp_broker::Broker::new(config);

    match transport {
        // `serve --http 127.0.0.1:8750` or `serve http <addr>`; defaults to
        // loopback so the server is never exposed on other interfaces.
        Some("http") | Some("--http") => {
            let arg = args.get(2).cloned().unwrap_or_default();
            let parsed: Result<std::net::SocketAddr, String> = if arg.is_empty() {
                "127.0.0.1:8750"
                    .parse()
                    .map_err(|e| format!("bad default addr: {e}"))
            } else if let Some(port) = arg.strip_prefix(':') {
                format!("127.0.0.1:{port}")
                    .parse()
                    .map_err(|e| format!("bad port '{arg}': {e}"))
            } else {
                arg.parse()
                    .map_err(|e| format!("bad bind address '{arg}': {e}"))
            };
            let addr = match parsed {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            };
            match broker.serve_http(addr).await {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("serve http failed: {e}");
                    1
                }
            }
        }
        Some(t) if t.starts_with("--") => {
            eprintln!("unknown flag '{t}'");
            2
        }
        _ => match broker.serve_stdio().await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("serve failed: {e}");
                1
            }
        },
    }
}

fn cmd_doctor(ida_dir_override: Option<&str>) -> i32 {
    let mut ok = true;

    println!("reverse-mcp doctor");
    println!("==================");

    // Config
    match rmcp_core::config::Config::load() {
        Ok(cfg) => {
            match &cfg.config_path {
                Some(p) => println!("config: {} loaded", p.display()),
                None => println!("config: none, using defaults"),
            }
            println!("required ida version: {}", cfg.required_ida_version);
            println!("max workers: {}", cfg.max_workers);
        }
        Err(e) => {
            println!("config: ERROR {e}");
            ok = false;
        }
    }

    // Portable layout
    let exe_dir = rmcp_core::layout::exe_dir();
    println!("exe dir: {}", exe_dir.display());
    let plugins = rmcp_core::layout::plugins_dir();
    let plugin_count = std::fs::read_dir(&plugins)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
                .count()
        })
        .unwrap_or(0);
    println!(
        "plugin source: {} (reverse-mcp managed, {plugin_count} plugin files; IDA install dir and %APPDATA%\\.idapro are never used)",
        plugins.display()
    );

    // Single-exe worker: this binary serves as its own worker (`worker`
    // subcommand); no separate reverse-mcp-worker.exe is needed.
    let worker_probe = std::process::Command::new(std::env::current_exe().unwrap_or_default())
        .args(["worker", "--probe-backend", "mock"])
        .output();
    match worker_probe {
        Ok(out) if out.status.success() => {
            println!("worker mode: OK (single exe, `worker` subcommand)");
        }
        _ => {
            println!("worker mode: BROKEN (`<exe> worker --probe-backend mock` failed)");
            ok = false;
        }
    }

    // IDA discovery (multi-version)
    let explicit: Option<PathBuf> = ida_dir_override.map(PathBuf::from);
    let installs = rmcp_core::discovery::discover_all(explicit.as_deref());
    if installs.is_empty() {
        println!("ida: NOT FOUND");
        ok = false;
    }
    for inst in &installs {
        let backend = match inst.backend {
            rmcp_core::discovery::BackendStatus::Ready => "backend ready",
            rmcp_core::discovery::BackendStatus::Unavailable => "backend unavailable",
        };
        let decos = if inst.decompilers.is_empty() {
            "no hexrays decompilers detected".to_string()
        } else {
            inst.decompilers
                .iter()
                .map(|d| d.name.clone())
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "ida {}: {} (source: {}, {}, {})",
            inst.version,
            inst.root.display(),
            inst.source.as_str(),
            decos,
            backend
        );
    }

    // Toolchain note: the discovered version is a best-effort file/name hint;
    // the worker re-verifies at startup via get_library_version().
    println!("ida version check: re-verified by worker at startup (get_library_version)");

    // Backend manifests: pinned SDK/FFI/generator facts per verified backend.
    for m in rmcp_core::backend_registry::VERIFIED_BACKENDS {
        println!(
            "backend-{}: SDK {} ({}) | ffi: {} | gen: {} | arch: {} | verified: {}",
            m.key,
            m.sdk_version,
            m.sdk_commit,
            m.ffi_source,
            m.generator,
            m.verified_arch.join(","),
            m.verified
        );
    }

    // Rust toolchain pinning.
    match std::fs::read_to_string("rust-toolchain.toml").or_else(|_| {
        std::fs::read_to_string(rmcp_core::layout::exe_dir().join("rust-toolchain.toml"))
    }) {
        Ok(raw) => {
            let channel = raw
                .lines()
                .find_map(|l| l.trim().strip_prefix("channel = "))
                .map(|s| s.trim_matches('"').to_string())
                .unwrap_or_else(|| "unknown".into());
            println!("rust toolchain: pinned {} (rust-toolchain.toml)", channel);
        }
        Err(_) => println!("rust toolchain: rust-toolchain.toml not found (unpinned!)"),
    }

    // ABI probe: status only (the probe itself needs SDK headers + clang).
    let abi_facts = "backends/abi/expected-9_2.json";
    if std::path::Path::new(abi_facts).is_file() {
        println!(
            "abi probe: expected-9_2.json present ({}); run scripts/run-abi-probe.ps1 against the SDK headers to verify",
            abi_facts
        );
    } else {
        println!(
            "abi probe: no expected fact file found in exe dir (probe runs from the repo checkout)"
        );
    }

    // A backend-ready install must exist for real work.
    if !installs.iter().any(|i| i.backend_ready()) {
        println!("no backend-ready IDA install (v0.1 verifies 9.2.x only)");
        ok = false;
    }

    if ok {
        println!("doctor: OK");
        0
    } else {
        println!("doctor: PROBLEMS FOUND");
        1
    }
}
