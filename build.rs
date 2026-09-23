//! Build script for the combined broker/worker binary.
//!
//! With an `idalib92`/`idalib94` feature the exe statically imports
//! ida.dll/idalib.dll, so the IDA install directory must be on PATH for every
//! invocation. This matches the previous separate-worker layout (the worker
//! binary always needed the IDA DLLs); mock-only builds (features off) have no
//! IDA imports and run anywhere. Delay-loading was evaluated and rejected:
//! IDA's library initialization terminates the process when its DLLs are
//! loaded mid-process, which breaks every db operation.
//!
//! Exactly one native IDA ABI may be linked per binary: the vendored 9.2 and
//! 9.4 idalib trees mirror different SDK layouts. The guard below fails the
//! build when both are requested.

#[cfg(all(feature = "idalib92", feature = "idalib94"))]
compile_error!(
    "features `idalib92` and `idalib94` are mutually exclusive: pick exactly one IDA ABI per build"
);

fn main() {
    #[cfg(feature = "idalib92")]
    {
        // Pull the import libraries through the vendored idalib-build helper
        // (SDK stubs when the real install is absent, as on CI).
        idalib_build::configure_idasdk_linkage();
    }
    #[cfg(feature = "idalib94")]
    {
        // Same linkage path, driven by the 9.4 vendored tree (SDK layout
        // lib/x64_win_64 instead of 9.2's lib/x64_win_vc_64).
        idalib94_build::configure_idasdk_linkage();
    }
    println!("cargo::rerun-if-changed=build.rs");
}
