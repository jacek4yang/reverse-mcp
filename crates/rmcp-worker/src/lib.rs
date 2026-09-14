//! rmcp-worker: one process = one loaded IDB = one IDA-owning thread.
//!
//! Built as a library so the distributed `reverse-mcp.exe` can run the worker
//! loop in-process via `reverse-mcp worker` (the broker spawns itself through
//! `std::env::current_exe()`). Serves newline-delimited JSON-RPC over
//! stdin/stdout; can also be driven by hand for debugging.

use std::io::{self, BufReader, BufWriter, Write};

use rmcp_core::protocol::{FrameReader, PROTOCOL_VERSION, WorkerHello, WorkerRequest, write_frame};

pub mod dispatch;
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

/// Preload ida.dll and idalib.dll so their initialization (including IDA's
/// embedded Python) happens at worker startup with pristine stdio instead of
/// mid-process during the first idalib call.
#[cfg(windows)]
fn preload_ida_dlls() {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
    for dll in ["ida.dll", "idalib.dll"] {
        let wide: Vec<u16> = dll.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: wide is a valid NUL-terminated wide string.
        unsafe {
            LoadLibraryW(wide.as_ptr());
        }
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
    // The IDA library is delay-loaded; when its DLLs (and IDA's embedded
    // Python) initialize mid-process — e.g. during the first db.open — IDA's
    // init terminates the worker. Preload the IDA DLLs before the protocol
    // loop so all initialization happens at startup, mirroring the timing of
    // a statically-linked worker. The broker sets REVERSE_MCP_IDA_DIR only
    // for idalib workers; mock workers (and --probe-backend) skip this.
    #[cfg(windows)]
    if std::env::var("REVERSE_MCP_IDA_DIR").is_ok() {
        preload_ida_dlls();
    }

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
