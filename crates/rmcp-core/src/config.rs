//! Configuration: `reverse-mcp.toml` next to the exe (portable layout), with
//! optional CLI overrides applied on top.

use std::path::PathBuf;
use std::time::Duration;

/// Full runtime configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Explicit IDA directory (wins over discovery). None = auto-discover.
    pub ida_dir: Option<PathBuf>,
    /// Require IDA version prefix, e.g. "9.2".
    pub required_ida_version: String,
    /// Max concurrent worker processes.
    pub max_workers: usize,
    /// Result-store spill threshold in bytes.
    pub result_threshold: usize,
    /// Result-store TTL.
    pub result_ttl: Duration,
    /// Result-store hard cap (entries). Oldest entries are evicted first;
    /// 0 = unlimited. Default bounds worst-case broker memory for soak runs.
    pub result_max_entries: usize,
    /// Path to config file that was loaded, if any.
    pub config_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ida_dir: None,
            required_ida_version: "9.2".into(),
            max_workers: 8,
            result_threshold: 24 * 1024,
            result_ttl: Duration::from_secs(3600),
            result_max_entries: 256,
            config_path: None,
        }
    }
}

/// On-disk TOML shape. Every field optional.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    ida_dir: Option<PathBuf>,
    required_ida_version: Option<String>,
    max_workers: Option<usize>,
    /// KiB
    result_threshold_kib: Option<usize>,
    /// Seconds
    result_ttl_secs: Option<u64>,
    /// Hard entry cap for the result store (0 = unlimited).
    result_max_entries: Option<usize>,
}

impl Config {
    /// Load `<exe dir>/reverse-mcp.toml` if present, else defaults.
    pub fn load() -> crate::error::Result<Self> {
        let path = crate::layout::exe_dir().join("reverse-mcp.toml");
        if !path.is_file() {
            return Ok(Self {
                config_path: None,
                ..Self::default()
            });
        }
        let raw = std::fs::read_to_string(&path)?;
        let file: FileConfig =
            toml::from_str(&raw).map_err(|e| crate::error::Error::Config(e.to_string()))?;
        Ok(Self {
            ida_dir: file.ida_dir,
            required_ida_version: file.required_ida_version.unwrap_or_else(|| "9.2".into()),
            max_workers: file.max_workers.unwrap_or(8).max(1),
            result_threshold: file.result_threshold_kib.unwrap_or(24) * 1024,
            result_ttl: Duration::from_secs(file.result_ttl_secs.unwrap_or(3600)),
            result_max_entries: file.result_max_entries.unwrap_or(256),
            config_path: Some(path),
        })
    }

    /// CLI overrides applied after file load.
    pub fn with_ida_dir_override(mut self, dir: Option<PathBuf>) -> Self {
        if let Some(d) = dir {
            self.ida_dir = Some(d);
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.max_workers, 8);
        assert_eq!(c.result_threshold, 24 * 1024);
        assert_eq!(c.required_ida_version, "9.2");
    }
}
