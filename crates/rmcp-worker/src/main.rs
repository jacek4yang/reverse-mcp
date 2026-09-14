//! reverse-mcp-worker: one process = one loaded IDB = one IDA-owning thread.
//! Serves newline-delimited JSON-RPC over stdin/stdout. Spawned by the broker;
//! can also be driven by hand for debugging.

use std::io::{self, BufWriter, Write};

use rmcp_core::protocol::{FrameReader, PROTOCOL_VERSION, WorkerHello, WorkerRequest, write_frame};

mod dispatch;
mod state;

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
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
    {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        if write_frame(&mut lock, &hello).is_err() {
            return 3;
        }
    }

    let stdin = io::stdin();
    let mut reader = FrameReader::new(stdin.lock());
    let mut writer = BufWriter::new(io::stdout());
    let mut state = state::WorkerState::new();

    while let Ok(Some(req)) = reader.read::<WorkerRequest>() {
        let resp = dispatch::handle(&mut state, req);
        if write_frame(&mut writer, &resp).is_err() {
            return 3;
        }
        // Exit cleanly after close so the broker observes EOF and reaps.
        if state.closed {
            let _ = writer.flush();
            return 0;
        }
    }
    let _ = io::stdout().flush();
    0
}
