# Architecture

Status: accurate as of commit `b8fe1cd` (2026-09-15), main branch.

## Overview

```
agent ←→ broker (reverse-mcp.exe serve, MCP stdio)
              └→ spawns itself in `worker` mode per open DB
                    └→ idalib (IDA 9.2 native FFI, one IDB per process)
                          └→ Hex-Rays decompiler
```

One distributed binary: `reverse-mcp.exe`. Subcommands:

| subcommand | purpose |
|---|---|
| `serve` | MCP server over stdio; `serve --http 127.0.0.1:8750` enables Streamable HTTP on loopback (multi-agent stress-tested) |
| `worker` | internal: one process = one loaded IDB = one IDA-owning thread. Also `worker --probe-backend <kind>` for capability detection |
| `doctor` | config, portable layout, worker probe, IDA discovery report |
| `ida list` | every discovered IDA install: version, source, decompilers, backend readiness |
| `open`, `inspect`, `decompile`, `sessions`, `selftest` | CLI conveniences |
| `version` | version string |

## Workspace

```
src/                  combined binary: broker (serve) + worker + CLI
crates/rmcp-core/     domain model: backend trait, config, discovery, errors,
                      handles, protocol frames, result store
crates/rmcp-ida/      backends: MockBackend (default) + IdaLibBackend (feature idalib)
crates/rmcp-worker/   worker library (dispatch + state); no separate binary
crates/rmcp-broker/   MCP ServerHandler, tool registry, WorkerPool
crates/reverse-ida-sys/  hand-written #[repr(C)] IDA SDK layouts + static
                      layout assertions (op_t, func_t, segment_t, ...)
vendor/               gitignored-SDK-dependent: idalib 0.7.2, idalib-sys, idalib-build
vendor/idalib-sys/sdk/  IDA 9.2 SDK headers/libs — PROPRIETARY, gitignored, never committed
tests/                cli.rs (mock), idalib_real.rs (real IDA, --ignored, gated)
scripts/check-distribution.ps1  proprietary-file scan
.github/workflows/ci.yml        windows-latest: fmt, clippy -D warnings, mock tests
```

## Discovery

Multi-version discovery resolves an install before any worker starts:

1. explicit dir / config `ida_dir`
2. `IDADIR`
3. `ida-config.json` (`%APPDATA%\Hex-Rays\IDA Pro`, `~/.idapro`)
4. OS-native: Windows uninstall registry, App Paths (`ida.exe`)
5. common default paths
6. `ida.reg` hints
7. cached drive-root scan

Version is read from the PE version resource of `idalib.dll` (ida.dll carries no
version resource), falling back to directory-name hints. The backend claims one
verified version key: `9_2`. Every other discovered version reports
`backend unavailable` and `ida_db open` refuses it with `ida_version_mismatch` —
never a silent fallback. The worker re-verifies at startup via
`get_library_version()`.

### Versioned backend registry

`crates/rmcp-core/src/backend_registry.rs` is the single source of truth: one
`BackendManifest` per verified backend pinning the exact SDK version/commit,
FFI source revision, binding-generator versions and verified architectures.
`discovery::backend_status` derives its verdict from this table, so adding a
new backend (new manifest entry + its crate + a real-IDA test pass) requires
no MCP/session API redesign.

### ABI probe

`backends/abi/abi_probe.cpp` + `expected-9_2.json` + `scripts/run-abi-probe.ps1`:
the probe is compiled against the exact vendored SDK headers and
static_asserts each recorded sizeof/alignof/offsetof; the same JSON is
asserted against the Rust mirrors in `crates/reverse-ida-sys` tests. A layout
mismatch (SDK bump, compiler change, platform flag change) fails the compile.
No SDK library is linked and nothing proprietary is emitted.

## Broker / worker protocol

- IPC: newline-delimited JSON over worker stdin/stdout. First frame
  `WorkerHello{protocol:1, ida_version, pid, ida_dir, idausr}`.
- `backend.select` picks `mock` or `idalib`; `ida_db open backend=auto` uses the
  real backend when the install is backend-ready and the exe has the `idalib`
  feature, otherwise mock.
- One request at a time per session (idalib is single-threaded per DB); `max_workers`
  caps concurrent DB processes.
- The broker probes worker capability by running `<exe> worker --probe-backend
  <kind>` and checks the exit code — never stdout matching (IDA prints banner
  noise). Probes are guarded against re-entrancy (`REVERSE_MCP_PROBING=1`
  short-circuits `ensure_worker_exe` inside the probe child, so a hung binary
  can never fork-bomb via recursive probing) and run with the IDA dir on PATH
  when known, because an idalib-feature exe imports `ida.dll` at load time and
  dies with STATUS_DLL_NOT_FOUND before `main` otherwise.
- When running inside a test binary, `current_exe` is the test itself, so
  `ensure_worker_exe` falls back to a `reverse-mcp(.exe)` sibling in the exe or
  parent directory.
- Worker calls are bounded: `WorkerSession::call_with_timeout` honors an
  agent-supplied `timeout_ms` clamped to 5s..30min (default per tool). A worker
  that dies before the protocol handshake produces a stable
  `capability_unavailable` diagnostic (`diagnose_dead_worker` checks the IDA
  dir for the runtime DLLs first); unexpected worker death afterwards is
  handled by the recovery state machine in `crates/rmcp-broker/src/recovery.rs`
  (Healthy → Crashed → Recovering → Healthy/Dead with bounded respawn and
  backoff).

## stdio survival (Windows-specific)

IDA's library initialization reconfigures the CRT stdio (closing fd 0/1) and
IDA's `callui` UI-dispatcher is a **data export** of `ida.dll` — data imports
cannot be delay-loaded (LNK1194). Two compensations exist:

1. `vendor/idalib-sys` resolves `callui` at runtime via `GetProcAddress`
   (hexrays_extras.h) and bypasses the SDK's `INTERR` macro in
   `processor_t::get_proc_index` (ph_extras.h) — the only two data-import users.
2. `rmcp-worker` duplicates its stdin/stdout handles at startup and serves the
   protocol through the duplicates, so IDA's stdio reconfiguration cannot kill
   the protocol channel. It also preloads `ida.dll`/`idalib.dll` when
   `REVERSE_MCP_IDA_DIR` is set, and the broker wires `PYTHONHOME` to IDA's
   bundled interpreter (IDA 9.2 bundles `Python311`).

## Revision guard

The backend keeps a monotonic revision counter. `rename`, `set_comment`,
`set_type`, `patch_bytes` accept `expected_revision`; a present-and-stale value
is rejected with the stable `revision_conflict` error before any mutation, and
the revision increments only after a confirmed successful mutation. Omitted
`expected_revision` stays allowed.

## Result store

Responses larger than `result_threshold` (default ~24 KiB) spill to an in-memory
store: the caller gets `result_ref: rN`, a preview, and a hint; `ida_result`
(read/metadata/find/release) retrieves them. TTL configurable; truncation always
flagged.

## Testing

| layer | where | IDA needed |
|---|---|---|
| mock backend unit tests | `crates/rmcp-ida` | no |
| core (discovery, protocol, store, handles) | `crates/rmcp-core` | no |
| worker dispatch incl. revision guard | `crates/rmcp-worker` | no |
| MCP e2e over stdio + HTTP (34 tools) | `crates/rmcp-broker/tests/e2e_stdio.rs` | no |
| CLI exit-code tests | `tests/cli.rs` | no |
| real IDA full chain + two concurrent DBs | `tests/idalib_real.rs` (`--ignored`) | yes, local |

CI (windows-latest) runs fmt, clippy `-D warnings`, and the mock suite —
independent of proprietary IDA content. Real-IDA tests run locally before a
release.
