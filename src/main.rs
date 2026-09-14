//! reverse-mcp — one binary: broker (MCP server) + self-spawned workers.
//!
//! Subcommands: serve | worker | doctor | open | sessions | inspect |
//! decompile | selftest | version. Only doctor/version are functional in this
//! commit; the rest land with broker/worker implementation.

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("doctor") => cmd_doctor(args.get(1).map(String::as_str)),
        Some("version") | Some("--version") | Some("-V") => {
            println!("reverse-mcp {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some(other) => {
            eprintln!(
                "unknown subcommand '{other}' (serve|worker|doctor|version available in this build)"
            );
            2
        }
        None => {
            eprintln!("usage: reverse-mcp <serve|worker|doctor|version>");
            2
        }
    };
    std::process::exit(code);
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
        "plugin source: {} (reverse-mcp managed, {} plugin files; IDA install dir and %APPDATA%\\.idapro are never used)",
        plugins.display(),
        plugin_count
    );

    // IDA discovery
    let explicit: Option<PathBuf> = ida_dir_override.map(PathBuf::from);
    match rmcp_core::discovery::discover(explicit.as_deref()) {
        Ok(install) => println!(
            "ida: found {} (source: {})",
            install.dir.display(),
            install.source
        ),
        Err(e) => {
            println!("ida: NOT FOUND — {e}");
            ok = false;
        }
    }

    // Toolchain note: IDA version is verified at worker startup via
    // get_library_version() because ida.dll has no usable version resource.
    println!("ida version check: performed by worker at startup (get_library_version)");

    if ok {
        println!("doctor: OK");
        0
    } else {
        println!("doctor: PROBLEMS FOUND");
        1
    }
}
