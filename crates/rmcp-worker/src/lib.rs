//! rmcp-worker: one process = one loaded IDB = one IDA-owning thread.
//!
//! Built as a library so the distributed `reverse-mcp.exe` can run the worker
//! loop in-process via `reverse-mcp worker` (the broker spawns itself through
//! `std::env::current_exe()`). Serves newline-delimited JSON-RPC over
//! stdin/stdout; can also be driven by hand for debugging.

use std::io::{self, BufReader, BufWriter, Write};

use rmcp_core::protocol::{FrameReader, PROTOCOL_VERSION, WorkerHello, WorkerRequest, write_frame};

pub mod dispatch;
pub mod plan;
pub mod state;

/// Capability probe: does this build support backend `kind`? The broker runs
/// `<exe> --probe-backend <kind>` to detect the real idalib backend without
/// spawning a session.
pub fn probe_backend(kind: &str) -> bool {
    match kind {
        "mock" => true,
        "idalib" => cfg!(feature = "idalib"),
        _ => false,
    }
}

/// On Windows, IDA's library initialization (delay-loaded mid-process, inside
/// `db.open`) reconfigures the CRT stdio and closes both fd 0 and fd 1. To
/// keep the protocol channel alive, duplicate the stdin and stdout handles up
/// front and serve the protocol through the duplicates; IDA is then free to
/// close the original fds. `dup_stdout` must be called AFTER at least one
/// real stdout write so std has materialized the underlying handle.
#[cfg(windows)]
fn dup_handle(
    which: windows_sys::Win32::System::Console::STD_HANDLE,
) -> std::io::Result<std::fs::File> {
    use std::os::windows::io::{FromRawHandle, RawHandle};

    use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
    use windows_sys::Win32::System::Console::GetStdHandle;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: GetStdHandle with a valid constant; returns the current std
    // handle or null.
    let raw = unsafe { GetStdHandle(which) } as HANDLE;
    if raw.is_null() || raw == -1isize as HANDLE {
        return Err(io::Error::other("std handle unavailable"));
    }
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicating a handle from our own process; `dup` is a fresh
    // handle we own and wrap in a File below.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` is a valid, exclusively-owned handle from DuplicateHandle.
    Ok(unsafe { std::fs::File::from_raw_handle(dup as RawHandle) })
}

#[cfg(windows)]
fn dup_stdin() -> std::io::Result<BufReader<std::fs::File>> {
    Ok(BufReader::new(dup_handle(
        windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
    )?))
}

#[cfg(windows)]
fn dup_stdout() -> std::io::Result<Box<dyn Write + Send>> {
    Ok(Box::new(dup_handle(
        windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
    )?))
}

/// Preload ida.dll and idalib.dll before `main` (via a `.CRT$XCU` startup
/// constructor). When the parent process exports REVERSE_MCP_IDA_DIR, the
/// worker's IDA dependencies are delay-loaded; binding them here — instead of
/// mid-run when the delay-load helper first fires inside `db.open` — runs
/// IDA's DllMain-time initialization during loader startup, the same timing
/// as static imports, which IDA requires. A no-op when the variable is unset,
/// so the broker process (same binary) never touches IDA at startup.
///
/// Pure Win32 by design: no Rust runtime facilities are guaranteed before
/// `main`, so this must not allocate through paths that assume std init or
/// panic (a panic here aborts before any handler exists).
#[cfg(windows)]
#[used]
#[unsafe(link_section = ".CRT$XCU")]
static IDA_DLL_PRELOAD: unsafe extern "C" fn() = preload_ida_dlls;

#[cfg(windows)]
unsafe extern "C" fn preload_ida_dlls() {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, GetFileAttributesW,
    };
    use windows_sys::Win32::System::Environment::{
        GetEnvironmentVariableW, SetEnvironmentVariableW,
    };
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryW, SetDllDirectoryW};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let var = wide("REVERSE_MCP_IDA_DIR");
    let mut dir = [0u16; 1024];
    // SAFETY: dir is a writable buffer of dir.len() chars; var is
    // NUL-terminated.
    let n = unsafe { GetEnvironmentVariableW(var.as_ptr(), dir.as_mut_ptr(), dir.len() as u32) };
    // 0 = not set; n >= dir.len() = path too long for our buffer. Both are
    // non-fatal: leave resolution to the delay-load helper and later probes.
    if n == 0 || n as usize >= dir.len() {
        return;
    }

    // The delay-load helper resolves ida.dll's own dependencies only from the
    // SetDllDirectory entry (PATH mutation is not honored there).
    // SAFETY: dir is a NUL-terminated wide path from the environment.
    let dir = &dir[..n as usize];
    unsafe {
        SetDllDirectoryW(dir.as_ptr());
    }

    // IDA's own runtime (plugins, loaders, embedded python) resolves files
    // relative to PATH during open_database; SetDllDirectoryW alone does not
    // cover those lookups. Prepend the IDA dir to PATH before any IDA code
    // runs so the worker does not depend on the broker mutating PATH.
    let path_var = wide("PATH");
    let mut old_path = [0u16; 32768];
    // SAFETY: old_path is a writable buffer; path_var is NUL-terminated.
    let np = unsafe { GetEnvironmentVariableW(path_var.as_ptr(), old_path.as_mut_ptr(), 32768) };
    if (np as usize) < old_path.len() {
        let mut new_path: Vec<u16> = dir.to_vec();
        new_path.push(u16::from(b';'));
        new_path.extend_from_slice(&old_path[..np as usize]);
        new_path.push(0);
        // SAFETY: new_path is NUL-terminated.
        unsafe {
            SetEnvironmentVariableW(path_var.as_ptr(), new_path.as_ptr());
        }
    }

    // IDA's embedded Python needs a home or its init fails and the worker
    // dies; mirror the broker's PYTHONHOME default here so a worker spawned
    // without the broker's full env still initializes.
    let pyhome_var = wide("PYTHONHOME");
    let mut probe = [0u16; 1];
    // SAFETY: probe is a valid (too-small) buffer; we only need the
    // set/unset answer.
    let pyhome_set = unsafe { GetEnvironmentVariableW(pyhome_var.as_ptr(), probe.as_mut_ptr(), 1) };
    if pyhome_set == 0 {
        let mut pyhome: Vec<u16> = dir.to_vec();
        pyhome.extend(wide("\\Python311"));
        // SAFETY: pyhome is NUL-terminated.
        let attrs = unsafe { GetFileAttributesW(pyhome.as_ptr()) };
        if attrs != FILE_ATTRIBUTE_NORMAL && attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            // SAFETY: pyhome is NUL-terminated.
            unsafe {
                SetEnvironmentVariableW(pyhome_var.as_ptr(), pyhome.as_ptr());
            }
        }
    }

    let mut h1: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut h2: *mut core::ffi::c_void = std::ptr::null_mut();
    for (dll, slot) in [("ida.dll", &mut h1), ("idalib.dll", &mut h2)] {
        let name = wide(dll);
        // SAFETY: name is a NUL-terminated wide string. Failures are
        // intentionally silent here; the worker and ida_health report
        // missing-runtime diagnostics later.
        *slot = unsafe { LoadLibraryW(name.as_ptr()) };
    }
}

#[cfg(not(windows))]
fn dup_stdin() -> std::io::Result<io::Stdin> {
    // Non-Windows has no delay-load stdio hazard; use plain stdin.
    Ok(io::stdin())
}

#[cfg(not(windows))]
fn dup_stdout() -> std::io::Result<Box<dyn Write + Send>> {
    // Non-Windows has no delay-load stdio hazard; use plain stdout.
    Ok(Box::new(io::stdout()))
}

/// Run the worker loop until stdin closes; returns the process exit code.
pub fn worker_main() -> i32 {
    // IDA DLL preloading happens in the .CRT$XCU constructor above, before
    // main runs, whenever the parent exported REVERSE_MCP_IDA_DIR.

    // Log anything fatal to stderr; stdout is protocol-only.
    let ida_dir = std::env::var("REVERSE_MCP_IDA_DIR").unwrap_or_default();
    let idausr = std::env::var("IDAUSR").unwrap_or_default();
    let ida_version =
        std::env::var("REVERSE_MCP_IDA_VERSION").unwrap_or_else(|_| "9.2-mock".into());

    let hello = WorkerHello {
        protocol: PROTOCOL_VERSION,
        ida_version,
        pid: std::process::id(),
        ida_dir,
        idausr,
    };

    let mut out = if write_frame(&mut io::stdout(), &hello).is_err() {
        return 3;
    } else {
        match dup_stdout() {
            Ok(w) => BufWriter::new(w),
            Err(_) => {
                return 3;
            }
        }
    };

    let mut input = match dup_stdin() {
        Ok(r) => r,
        Err(_) => {
            return 3;
        }
    };

    let mut reader = FrameReader::new(&mut input);
    let mut state = state::WorkerState::new();
    while let Ok(Some(req)) = reader.read::<WorkerRequest>() {
        let resp = dispatch::handle(&mut state, req);
        if write_frame(&mut out, &resp).is_err() {
            return 3;
        }
        // Exit cleanly after close so the broker observes EOF and reaps.
        if state.closed {
            let _ = out.flush();
            return 0;
        }
    }
    let _ = out.flush();
    0
}
