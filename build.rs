//! Build script for the combined broker/worker binary.
//!
//! With the `idalib` feature the exe statically imports ida.dll/idalib.dll,
//! so the IDA install directory must be on PATH for every invocation. This
//! matches the previous separate-worker layout (the worker binary always
//! needed the IDA DLLs); mock-only builds (feature off) have no IDA imports
//! and run anywhere. Delay-loading was evaluated and rejected: IDA's
//! library initialization terminates the process when its DLLs are loaded
//! mid-process, which breaks every db operation.

fn main() {
    #[cfg(feature = "idalib")]
    {
        // Pull the import libraries through the vendored idalib-build helper
        // (SDK stubs when the real install is absent, as on CI).
        idalib_build::configure_idasdk_linkage();
    }
    println!("cargo::rerun-if-changed=build.rs");
}
