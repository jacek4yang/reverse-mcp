//! Portable layout: everything lives next to the exe (plugins, cache, config),
//! cline-proxy-bin style. No writes to system directories or the user profile.

use std::path::PathBuf;

/// Directory containing the running executable (resolves symlinks).
pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `<exe dir>/plugins` — reverse-mcp-managed IDA plugins. The worker points
/// `IDAUSR` here so plugins are fully isolated from the IDA install dir and
/// `%APPDATA%\.idapro`. Created on demand.
pub fn plugins_dir() -> PathBuf {
    let d = exe_dir().join("plugins");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// `<exe dir>/cache` — discovery cache and other ephemeral data.
pub fn cache_dir() -> PathBuf {
    let d = exe_dir().join("cache");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// `<exe dir>/logs` — file logs (stdout stays reserved for MCP framing).
pub fn logs_dir() -> PathBuf {
    let d = exe_dir().join("logs");
    let _ = std::fs::create_dir_all(&d);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs_are_exe_relative() {
        // Just verify they resolve and are creatable without touching the profile.
        assert!(plugins_dir().ends_with("plugins"));
        assert!(cache_dir().ends_with("cache"));
        assert!(logs_dir().ends_with("logs"));
    }
}
