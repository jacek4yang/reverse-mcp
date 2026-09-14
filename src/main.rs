//! reverse-mcp — one binary: broker (MCP server) + self-spawned workers.
//!
//! Subcommands: serve | worker | doctor | open | sessions | inspect |
//! decompile | selftest | version.

use std::path::PathBuf;

mod cli;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("serve") => cmd_serve(args.get(1).map(String::as_str)).await,
        Some("doctor") => cmd_doctor(args.get(1).map(String::as_str)),
        Some("open") => cli::cmd_open(args.get(1).map(String::as_str).unwrap_or("")).await,
        Some("sessions") => cli::cmd_sessions().await,
        Some("inspect") => {
            cli::cmd_inspect(args.get(1).map(String::as_str), args.get(2).map(String::as_str))
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

async fn cmd_serve(transport: Option<&str>) -> i32 {
    let config = match rmcp_core::config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return 1;
        }
    };
    let broker = rmcp_broker::Broker::new(config);

    match transport {
        Some("http") | Some("--http") => {
            eprintln!("HTTP transport lands with the hardening commit; use stdio for now");
            2
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

    // Worker binary
    let worker = exe_dir.join(if cfg!(windows) {
        "reverse-mcp-worker.exe"
    } else {
        "reverse-mcp-worker"
    });
    if worker.is_file() {
        println!("worker binary: {} OK", worker.display());
    } else {
        println!("worker binary: {} MISSING", worker.display());
        ok = false;
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
