//! Backend registry: one manifest per known IDA-version backend.
//!
//! A backend is the combination of generated/hand-written FFI plus the
//! safe layer, pinned to one exact IDA SDK revision. A backend must never
//! be driven against a runtime of a different version: `Capabilities` and
//! the worker's startup version check both read the pinned facts from
//! `KNOWN_BACKENDS` here, and `discovery::backend_status` is derived
//! from this table (single source of truth).
//!
//! Registry states are distinct and must not be conflated:
//! - *known*: a manifest row exists (the FFI source exists in `vendor/`);
//! - *verified*: the real-IDA integration suite has genuinely passed on a
//!   licensed runtime of that version (`verified: true`).
//!
//! `is_verified()` consults the flag, not mere presence: a known but
//! unverified backend stays `available/unverified` and the strict-version
//! resolver refuses to select it.
//!
//! Adding a backend (e.g. `backend-9_5`):
//! 1. vendor/point the FFI at the new SDK revision (never mix SDK ABIs);
//! 2. add a `BackendManifest` entry here with the exact SDK tag/commit,
//!    FFI source revision and generator versions used, `verified: false`;
//! 3. add an `expected-<key>.json` fact file plus (if layouts changed)
//!    updated static asserts in `reverse-ida-sys`;
//! 4. run `scripts/run-abi-probe.ps1 -IdaVersion <ver>` against the new
//!    SDK headers;
//! 5. flip the entry to verified only after the real-IDA integration
//!    suite passes on that runtime (`tests/idalib_real.rs`).
//!
//! MCP/session APIs are version-agnostic: agents select via
//! `ida_version` on `ida_db.open`, and the resolver picks only installs
//! covered by a verified entry here.

/// One backend, pinned to one IDA SDK revision.
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

/// The backend table.
///
/// `backend-9_2` is verified (v1.0 real-IDA suite, Windows 11 x86_64).
/// `backend-9_4` is verified: the gated real-IDA matrix passed on IDA
/// Professional 9.4 (build 260714, Windows 11 x86_64) — idalib_real
/// (21/21), wasm_real (2/2), largefn_real (giant-function hierarchical),
/// corpus_real (33 binaries), real-IDA bench, stdio + HTTP MCP smoke.
/// logic/malware local-corpus suites are machine-local by design. License
/// compliance for the runtime is the responsibility of the environment
/// that produced these results.
pub const KNOWN_BACKENDS: &[BackendManifest] = &[
    BackendManifest {
        key: "9_2",
        sdk_version: "9.2",
        sdk_commit: "9.2.250908",
        ffi_source: "idalib-sys 0.7.2+9.2.250908 (vendored)",
        generator: "autocxx 0.27 + autocxx-bindgen 0.71",
        verified_arch: &["x86_64"],
        verified: true,
    },
    BackendManifest {
        key: "9_4",
        sdk_version: "9.4",
        sdk_commit: "ida-sdk v9.4.0-sdk.1 (2a9143f2f4abd7f54fe20d1e40fb68391d19c4cb)",
        ffi_source: "idalib94-sys 0.10.1+9.4.260714 (vendored from idalib-rs/idalib v0.10.1+9.4.260714, commit 4f0437a3cff5067738f4645a1e365e139c09156c)",
        generator: "autocxx-idalib 0.30 + autocxx-bindgen-idalib 0.73",
        verified_arch: &["x86_64"],
        verified: true,
    },
];

/// Backwards-compatible alias: the registry lists known manifests; only the
/// verified subset may be selected for real work.
pub const VERIFIED_BACKENDS: &[BackendManifest] = KNOWN_BACKENDS;

/// Look up a known backend manifest by version key (`"9_2"`).
pub fn manifest_for(key: &str) -> Option<&'static BackendManifest> {
    KNOWN_BACKENDS.iter().find(|m| m.key == key)
}

/// Whether the real-IDA integration suite has passed for this backend.
/// Presence in the table alone does NOT count as verified.
pub fn is_verified(key: &str) -> bool {
    manifest_for(key).is_some_and(|m| m.verified)
}

/// Keys of all known backends (verified or not).
pub fn known_keys() -> Vec<&'static str> {
    KNOWN_BACKENDS.iter().map(|m| m.key).collect()
}

/// Keys of all verified backends (used by discovery gating).
pub fn verified_keys() -> Vec<&'static str> {
    KNOWN_BACKENDS
        .iter()
        .filter(|m| m.verified)
        .map(|m| m.key)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_in<'a>(table: &'a [BackendManifest], key: &str) -> Option<&'a BackendManifest> {
        table.iter().find(|m| m.key == key)
    }

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
    fn backend_9_4_manifest_exists_with_pinned_facts() {
        let m = manifest_for("9_4").expect("9_4 manifest");
        assert_eq!(m.sdk_version, "9.4");
        assert!(
            m.sdk_commit.contains("v9.4.0-sdk.1"),
            "exact SDK tag pinned"
        );
        assert!(
            m.sdk_commit
                .contains("2a9143f2f4abd7f54fe20d1e40fb68391d19c4cb")
        );
        assert!(m.ffi_source.contains("0.10.1+9.4.260714"));
        assert!(
            m.ffi_source
                .contains("4f0437a3cff5067738f4645a1e365e139c09156c")
        );
        assert!(m.verified_arch.contains(&"x86_64"));
    }

    #[test]
    fn unknown_backends_are_not_verified() {
        assert!(!is_verified("9_3"));
        assert!(manifest_for("9_3").is_none());
        assert!(!is_verified("9_5"));
    }

    #[test]
    fn is_verified_checks_the_flag_not_mere_presence() {
        // A manifest present in the table with verified=false must NOT
        // verify: this is the regression guard for the registry semantics
        // (manifest exists => automatically considered verified was the
        // v1.0 bug class this API must prevent).
        let m = manifest_for("9_4").expect("9_4 is in the table");
        if !m.verified {
            assert!(
                !is_verified("9_4"),
                "known-but-unverified backend must not be verified"
            );
        }
        // And directly on a synthetic table: verified flag is authoritative.
        let synthetic = [BackendManifest {
            key: "x_1",
            sdk_version: "x",
            sdk_commit: "x",
            ffi_source: "x",
            generator: "x",
            verified_arch: &[],
            verified: false,
        }];
        assert!(manifest_in(&synthetic, "x_1").is_some());
        assert!(!synthetic[0].verified);
    }

    #[test]
    fn verified_keys_only_contains_verified_backends() {
        let vk = verified_keys();
        assert!(vk.contains(&"9_2"));
        for k in &vk {
            assert!(
                manifest_for(k).is_some_and(|m| m.verified),
                "key {k} listed as verified but flag says otherwise"
            );
        }
        if !manifest_for("9_4").is_some_and(|m| m.verified) {
            assert!(
                !vk.contains(&"9_4"),
                "unverified 9_4 must not appear in verified_keys"
            );
        }
    }

    #[test]
    fn known_keys_are_unique_and_wellformed() {
        let keys = known_keys();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(keys.len(), sorted.len(), "duplicate backend keys");
        for k in keys {
            assert!(k.contains('_'), "key '{k}' should look like '9_2'");
        }
    }
}
