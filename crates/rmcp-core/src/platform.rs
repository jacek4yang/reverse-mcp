//! Platform adapter (issue #48): every OS-specific constant and string
//! operation used by the broker/worker lives here so no other module needs
//! `#[cfg]` branches. Unit-tested with per-OS expectations.
//!
//! Scope note (#48): this isolates OS specifics; it does not add target
//! support by itself — a platform is supported only after the real-IDA
//! acceptance suite passes there (tested facts, per ENGINEERING_PRINCIPLES).

/// Name of the PATH-like environment variable on this OS.
pub fn path_env() -> &'static str {
    // All supported OSes use PATH; kept as a function so a future
    // platform with a different name changes one place only.
    "PATH"
}

/// Separator between entries in the PATH-like variable.
pub fn path_separator() -> char {
    if cfg!(windows) { ';' } else { ':' }
}

/// Prepend `dir` to a PATH-style value: `dir <sep> existing`.
/// The existing part may be empty; the result never starts with the
/// separator.
pub fn prepend_path(dir: &std::path::Path, existing: &str) -> String {
    if existing.is_empty() {
        dir.display().to_string()
    } else {
        format!("{}{}{}", dir.display(), path_separator(), existing)
    }
}

/// Runtime library filenames for this OS (loader-imported IDA runtime).
pub fn runtime_libraries() -> &'static [&'static str] {
    if cfg!(windows) {
        &["ida.dll", "idalib.dll"]
    } else if cfg!(target_os = "macos") {
        &["libida.dylib", "libidalib.dylib"]
    } else {
        &["libida.so", "libidalib.so"]
    }
}

/// Subdirectory (inside the IDA install) that holds the embedded Python
/// home, if the layout ships one. Checked by the caller with `is_dir`.
pub fn python_home_dirname() -> &'static str {
    if cfg!(windows) {
        "Python311"
    } else {
        // Linux/macOS installs ship python under "python" (IDA 9.x).
        "python"
    }
}

/// Name of the worker executable for this OS (single-exe architecture:
/// the worker is `<exe> worker`).
pub fn worker_exe_name() -> &'static str {
    if cfg!(windows) {
        "reverse-mcp.exe"
    } else {
        "reverse-mcp"
    }
}

/// Extension for shared libraries (diagnostics).
pub fn shared_lib_ext() -> &'static str {
    if cfg!(windows) {
        "dll"
    } else if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_building_uses_os_separator() {
        let dir = std::path::Path::new("/opt/ida");
        let sep = path_separator();
        assert_eq!(
            prepend_path(dir, "/usr/bin"),
            format!("/opt/ida{sep}/usr/bin")
        );
        // Empty existing value: no leading separator.
        assert_eq!(prepend_path(dir, ""), "/opt/ida");
    }

    #[test]
    fn runtime_libraries_match_runtime_paths() {
        // Cross-check against discovery's runtime_paths so the two tables
        // can never drift apart (both must describe the same runtime files).
        let libs = runtime_libraries();
        assert_eq!(libs.len(), 2, "ida + idalib runtime expected");
        let ext = shared_lib_ext();
        for lib in libs {
            assert!(
                lib.ends_with(&format!(".{ext}")),
                "{lib} must end with .{ext}"
            );
        }
    }

    #[test]
    fn worker_name_has_no_exe_suffix_off_windows() {
        let name = worker_exe_name();
        if cfg!(windows) {
            assert!(name.ends_with(".exe"));
        } else {
            assert!(!name.contains('.'));
        }
    }
}
