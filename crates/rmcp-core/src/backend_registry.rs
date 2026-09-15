//! Backend registry: one manifest per verified IDA-version backend.
//!
//! A backend is the combination of generated/hand-written FFI plus the
//! safe layer, pinned to one exact IDA SDK revision. A backend must never
//! be driven against a runtime of a different version: `Capabilities` and
//! the worker's startup version check both read the pinned facts from
//! `VERIFIED_BACKENDS` here, and `discovery::backend_status` is derived
//! from this table (single source of truth).
//!
//! Adding a backend (e.g. `backend-9_3`):
//! 1. vendor/point the FFI at the new SDK revision (never mix SDK ABIs);
//! 2. add a `BackendManifest` entry here with the exact SDK tag/commit,
//!    FFI source revision and generator versions used;
//! 3. add an `expected-<key>.json` fact file plus (if layouts changed)
//!    updated static asserts in `reverse-ida-sys`;
//! 4. run `scripts/run-abi-probe.ps1` against the new SDK headers;
//! 5. flip the entry to verified only after the real-IDA integration
//!    suite passes on that runtime (`tests/idalib_real.rs`).
//!
//! MCP/session APIs are version-agnostic: agents select via
//! `ida_version` on `ida_db.open`, and the resolver picks only installs
//! covered by a verified entry here.

/// One verified backend, pinned to one IDA SDK revision.
#[derive(Debug, Clone, Copy)]
pub struct BackendManifest {
    /// Stable backend key, e.g. `"9_2"`.
    pub key: &'static str,
    /// Exact IDA SDK version the FFI was generated against.
    pub sdk_version: &'static str,
    /// SDK build/commit identifier (ida-sdk tag or SDK build stamp).
    pub sdk_commit: &'static str,
    /// Vendored FFI source revision (`idalib-sys` crate version).
    pub ffi_source: &'static str,
    /// Binding generator (autocxx) version used to generate the bindings.
    pub generator: &'static str,
    /// Runtime architectures this backend was verified on.
    pub verified_arch: &'static [&'static str],
    /// Whether the real-IDA integration suite has passed for this backend.
    pub verified: bool,
}

/// The backend table. `backend-9_2` is the only entry verified so far.
pub const VERIFIED_BACKENDS: &[BackendManifest] = &[BackendManifest {
    key: "9_2",
    sdk_version: "9.2",
    sdk_commit: "9.2.250908",
    ffi_source: "idalib-sys 0.7.2+9.2.250908 (vendored)",
    generator: "autocxx 0.27 + autocxx-bindgen 0.71",
    verified_arch: &["x86_64"],
    verified: true,
}];

/// Look up a backend manifest by version key (`"9_2"`).
pub fn manifest_for(key: &str) -> Option<&'static BackendManifest> {
    VERIFIED_BACKENDS.iter().find(|m| m.key == key)
}

/// Whether a verified backend exists for this key.
pub fn is_verified(key: &str) -> bool {
    manifest_for(key).is_some()
}

/// Keys of all verified backends (used by discovery gating).
pub fn verified_keys() -> Vec<&'static str> {
    VERIFIED_BACKENDS.iter().map(|m| m.key).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_9_2_is_verified_with_pinned_facts() {
        let m = manifest_for("9_2").expect("9_2 manifest");
        assert!(m.verified);
        assert_eq!(m.sdk_version, "9.2");
        assert!(!m.sdk_commit.is_empty());
        assert!(!m.ffi_source.is_empty());
        assert!(m.verified_arch.contains(&"x86_64"));
    }

    #[test]
    fn unknown_backends_are_not_verified() {
        assert!(!is_verified("9_3"));
        assert!(manifest_for("9_3").is_none());
    }

    #[test]
    fn keys_are_unique_and_wellformed() {
        let keys = verified_keys();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(keys.len(), sorted.len(), "duplicate backend keys");
        for k in keys {
            assert!(k.contains('_'), "key '{k}' should look like '9_2'");
        }
    }
}
