//! CLI tests: run the built `reverse-mcp` binary with different subcommands
//! and assert exit codes plus key output (no IDA required; the mock chain
//! covers the worker binary + handshake + protocol).

use std::process::Command;

fn cli() -> Command {
    let exe = env!("CARGO_BIN_EXE_reverse-mcp");
    Command::new(exe)
}

#[test]
fn version_prints_and_exits_zero() {
    let out = cli().args(["version"]).output().expect("run version");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout: {stdout}"
    );
}

#[test]
fn unknown_subcommand_errors() {
    let out = cli().args(["nope"]).output().expect("run nope");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unknown subcommand"), "stderr: {stderr}");
}

#[test]
fn no_args_prints_usage() {
    let out = cli().output().expect("run with no args");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage:"), "stderr: {stderr}");
}

#[test]
fn open_rejects_missing_file() {
    let out = cli()
        .args(["open", "Z:/definitely/not/here.bin"])
        .output()
        .expect("run open");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a file"), "stderr: {stderr}");
}

#[test]
fn decompile_requires_args() {
    let out = cli().args(["decompile"]).output().expect("run decompile");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage:"), "stderr: {stderr}");
}
