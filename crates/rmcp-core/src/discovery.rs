//! IDA install discovery. Resolution order, first hit wins:
//! 1. explicit `ida_dir` (config / CLI)
//! 2. `IDADIR` env var
//! 3. Windows registry (`HKLM\SOFTWARE\Hex-Rays`, Wow6432 variant)
//! 4. common install paths
//! 5. depth-limited recursive scan of drive roots (result cached)
//!
//! A candidate dir is valid when it contains `ida.dll` + `idalib.dll` +
//! `plugins/`. Version checking happens at worker runtime via
//! `get_library_version()` — `ida.dll` carries no usable version resource.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::{Error, Result};

/// A discovered IDA installation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdaInstall {
    pub dir: PathBuf,
    /// Which resolution step found it.
    pub source: &'static str,
}

/// Minimum files that make a directory an IDA install.
pub fn is_valid_ida_dir(dir: &Path) -> bool {
    dir.join("ida.dll").is_file()
        && dir.join("idalib.dll").is_file()
        && dir.join("plugins").is_dir()
}

/// Discover the IDA install. `explicit` is the config/CLI `ida_dir`.
pub fn discover(explicit: Option<&Path>) -> Result<IdaInstall> {
    let mut report = DiscoveryReport::default();

    if let Some(d) = explicit {
        report.step(1, &format!("explicit ida_dir: {}", d.display()));
        if is_valid_ida_dir(d) {
            return Ok(IdaInstall {
                dir: d.to_path_buf(),
                source: "explicit",
            });
        }
        return Err(Error::IdaNotFound(format!(
            "explicit ida_dir {} is not a valid IDA install (needs ida.dll + idalib.dll + plugins/)",
            d.display()
        )));
    }

    // 2. IDADIR
    if let Ok(d) = std::env::var("IDADIR") {
        let d = PathBuf::from(d);
        report.step(2, &format!("IDADIR: {}", d.display()));
        if is_valid_ida_dir(&d) {
            return Ok(IdaInstall {
                dir: d,
                source: "IDADIR",
            });
        }
    } else {
        report.step(2, "IDADIR: not set");
    }

    // 3. Registry
    #[cfg(windows)]
    {
        report.step(3, "registry HKLM\\SOFTWARE\\Hex-Rays");
        if let Some(d) = registry_ida_dir()
            && is_valid_ida_dir(&d)
        {
            return Ok(IdaInstall {
                dir: d,
                source: "registry",
            });
        }
    }
    #[cfg(not(windows))]
    report.step(3, "registry: skipped (non-Windows)");

    // 4. Common paths
    report.step(4, "common install paths");
    for d in common_paths() {
        if is_valid_ida_dir(&d) {
            return Ok(IdaInstall {
                dir: d,
                source: "common_paths",
            });
        }
    }

    // 5. Drive scan (cached)
    report.step(5, "drive-root scan");
    if let Some(d) = cached_drive_scan()
        && is_valid_ida_dir(&d)
    {
        return Ok(IdaInstall {
            dir: d,
            source: "drive_scan",
        });
    }

    Err(Error::IdaNotFound(report.summary()))
}

/// Step-by-step trace for `doctor`.
#[derive(Debug, Default)]
pub struct DiscoveryReport {
    steps: Vec<(usize, String)>,
}

impl DiscoveryReport {
    fn step(&mut self, n: usize, msg: &str) {
        self.steps.push((n, msg.to_string()));
    }

    pub fn steps(&self) -> &[(usize, String)] {
        &self.steps
    }

    fn summary(&self) -> String {
        let joined = self
            .steps
            .iter()
            .map(|(n, m)| format!("step {n}: {m}"))
            .collect::<Vec<_>>()
            .join("; ");
        format!("all discovery steps exhausted: {joined}")
    }
}

/// Run discovery and return a full trace (used by `doctor`).
pub fn discover_with_report(explicit: Option<&Path>) -> (Result<IdaInstall>, DiscoveryReport) {
    // Reuse discover(); the report inside is discarded, so re-run cheap steps
    // for the trace. To keep it simple and correct we only report the outcome.
    let result = discover(explicit);
    let mut report = DiscoveryReport::default();
    match &result {
        Ok(install) => report.steps.push((
            0,
            format!("found: {} ({})", install.dir.display(), install.source),
        )),
        Err(e) => report.steps.push((0, format!("not found: {e}"))),
    }
    (result, report)
}

#[cfg(windows)]
fn registry_ida_dir() -> Option<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    for subkey in [r"SOFTWARE\Hex-Rays", r"SOFTWARE\WOW6432Node\Hex-Rays"] {
        let hk = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(key) = hk.open_subkey_with_flags(subkey, KEY_READ) {
            for name in ["InstallPath", "IDAInstallDir", "Path"] {
                if let Ok(val) = key.get_value::<String, _>(name) {
                    return Some(PathBuf::from(val));
                }
            }
            // Enumerate subkeys (e.g. IDA Professional 9.2) for InstallPath values.
            for sk in key.enum_keys().flatten() {
                if let Ok(sub) = key.open_subkey_with_flags(&sk, KEY_READ)
                    && let Ok(val) = sub.get_value::<String, _>("InstallPath")
                {
                    return Some(PathBuf::from(val));
                }
            }
        }
    }
    None
}

fn common_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut push_glob = |base: &Path, pattern: &str| {
        if let Ok(entries) = std::fs::read_dir(base) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if name.contains(pattern) {
                    out.push(e.path());
                }
            }
        }
    };
    if let Some(pf) = std::env::var_os("ProgramFiles") {
        push_glob(Path::new(&pf), "ida");
    }
    if let Some(lad) = std::env::var_os("LOCALAPPDATA") {
        push_glob(&Path::new(&lad).join("Programs"), "ida");
    }
    // Unix-only common paths (also catch macOS installs when building on those targets).
    #[cfg(not(windows))]
    for p in ["/opt", "/Applications", home_or_empty()] {
        let p = Path::new(&p);
        if p.is_dir() {
            push_glob(p, "ida");
        }
    }
    out
}

// Unix-only helper (unused on Windows).
#[cfg(not(windows))]
fn home_or_empty() -> String {
    std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default()
}

const SCAN_CACHE_NAME: &str = "discovery.json";
const SCAN_MAX_DEPTH: u8 = 3;
const SCAN_CACHE_TTL: Duration = Duration::from_secs(24 * 3600);

fn cached_drive_scan() -> Option<PathBuf> {
    let cache_path = crate::layout::cache_dir().join(SCAN_CACHE_NAME);

    // Fresh cache hit?
    if let Ok(raw) = std::fs::read_to_string(&cache_path)
        && let Ok(entry) = serde_json::from_str::<CacheEntry>(&raw)
        && entry
            .scanned_at
            .elapsed()
            .map(|e| e < SCAN_CACHE_TTL)
            .unwrap_or(false)
        && is_valid_ida_dir(Path::new(&entry.dir))
    {
        return Some(PathBuf::from(entry.dir));
    }

    // Full scan.
    let found = scan_drives();
    if let Some(ref dir) = found {
        let entry = CacheEntry {
            dir: dir.to_string_lossy().into_owned(),
            scanned_at: SystemTime::now(),
        };
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = std::fs::write(&cache_path, json);
        }
    }
    found
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    dir: String,
    scanned_at: SystemTime,
}

fn drive_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(windows)]
    {
        // A-Z fixed drives via existence of the root dir.
        for letter in b'A'..=b'Z' {
            let root = PathBuf::from(format!(r"{}:\", letter as char));
            if root.is_dir() {
                roots.push(root);
            }
        }
    }
    #[cfg(not(windows))]
    roots.push(PathBuf::from("/"));
    roots
}

/// Public for the `scan_debug` example; not part of the library API.
pub fn debug_drive_roots() -> Vec<PathBuf> {
    drive_roots()
}

/// Public for the `scan_debug` example; not part of the library API.
pub fn debug_scan_dir(dir: &Path, depth: u8) -> Option<PathBuf> {
    scan_dir(dir, depth)
}

fn scan_drives() -> Option<PathBuf> {
    for root in drive_roots() {
        if let Some(hit) = scan_dir(&root, 0) {
            return Some(hit);
        }
    }
    None
}

fn scan_dir(dir: &Path, depth: u8) -> Option<PathBuf> {
    if depth > SCAN_MAX_DEPTH || is_valid_ida_dir(dir) {
        return is_valid_ida_dir(dir).then(|| dir.to_path_buf());
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return None,
    };
    // Directories only; skip obvious noise.
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_lowercase();
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if !ft.is_dir() {
            continue;
        }
        if name.starts_with('$') || name == "windows" || name == "system volume information" {
            continue;
        }
        // Descend preferentially into dirs whose names hint at IDA, but scan all.
        if let Some(hit) = scan_dir(&e.path(), depth + 1) {
            return Some(hit);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_dir_rejected() {
        assert!(!is_valid_ida_dir(Path::new("C:/definitely-not-ida-xyz")));
    }

    #[test]
    fn explicit_missing_dir_errors() {
        let err = discover(Some(Path::new("C:/definitely-not-ida-xyz"))).unwrap_err();
        assert_eq!(err.code(), "ida_not_found");
    }

    #[test]
    fn drive_scan_finds_nothing_in_temp() {
        // depth-limited scan of a temp dir with no IDA must yield None
        let tmp = std::env::temp_dir();
        assert_eq!(scan_dir(&tmp, SCAN_MAX_DEPTH + 1), None);
    }
}
