# reverse-mcp

[![ci](https://github.com/jacek4yang/reverse-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/jacek4yang/reverse-mcp/actions/workflows/ci.yml)

MCP server that gives AI agents headless, programmatic control over **IDA Pro 9.2** - a single `reverse-mcp.exe` (broker + self-spawned workers in the same binary) driving IDA through its native idalib API (no `idat`, no Python).

- Architecture details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Tool reference: [`docs/MCP_TOOLS.md`](docs/MCP_TOOLS.md)
- Honest limitations & roadmap: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md)

## What it does

An agent connects over MCP and gets **34 tools** (full reference with schemas
in [`docs/MCP_TOOLS.md`](docs/MCP_TOOLS.md)). Highlights:

| tool | purpose |
|---|---|
| `ida_capabilities` | what this backend/decompiler can do |
| `ida_installations` | all IDA installs on the machine: version, source, decompilers, backend readiness |
| `ida_db` | open / info / save / close / list databases |
| `ida_functions` | paginated function list |
| `ida_inspect` | everything known about one address |
| `ida_decompile` | Hex-Rays pseudocode |
| `ida_disassemble` | bounded disassembly ranges |
| `ida_xrefs` | cross references (to/from) |
| `ida_graph` | `kind=calls` (function-wide call discovery) or `kind=cfg` (basic-block flow), bounded |
| `ida_search` | text & immediate search |
| `ida_bytes` | read bytes |
| `ida_types` | local type view |
| `ida_edit` | rename + comments (bumps revision) |
| `ida_analysis` | wait for auto-analysis |
| `ida_batch` | up to 20 read-only ops per round trip |
| `ida_result` | read spilled large results (`r17` handles) |
| `ida_segments` | segment listing |
| `ida_mutation` | plan - review - apply refactors with snapshots, audit and rollback |
| `ida_evidence` | semantic reverse index: search functions by imports/strings/constants/name |
| `ida_analyze` | composite workflows (function context, cross-referenced views, token-efficient summaries) |
| `ida_deep` | recursive decompilation with type propagation and bounded data-flow; resumable, cached |
| `ida_type_recovery` | struct/vtable recovery from member evidence; UDT create/match/apply |
| `ida_intel` | crypto constants, API-hash resolution, recovered strings |
| `ida_deobfuscate` | analysis-only detection of flattening, opaque branches, junk code, tail jumps |
| `ida_sig` | multi-family function fingerprints; cross-IDB export/identify/map |
| `ida_health` | worker/backend liveness and diagnostics |

Large outputs spill to a result store; truncation is always flagged, never silent.

## Guarantees

- **Optimistic concurrency** - every mutation (`ida_edit`, `ida_bytes
  action=patch`, `ida_types action=set`) accepts `expected_revision`. A stale
  value is rejected with `revision_conflict` before anything is touched; the
  revision increments only after a confirmed successful mutation.
- **Honest capabilities** - unimplemented operations fail with
  `capability_unavailable` instead of faking success. See
  [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for what is not implemented.
- **Bounded output** - every list/search/graph has hard caps; oversized
  responses spill to handles read via `ida_result`.

## Architecture

```
agent ←→ broker (reverse-mcp.exe serve, MCP stdio or `serve --http 127.0.0.1:8750`)
              └→ spawns itself in `worker` mode per open DB
                    └→ idalib (IDA 9.2 native FFI, one IDB per process)
```

- **One worker per DB** - IDA's idalib is single-threaded per database; the broker serializes requests and enforces `max_workers`.
- **Portable layout** - everything lives next to the exe (`plugins\`, `cache\`, `logs\`, `reverse-mcp.toml`). Plugins come only from the exe-relative `plugins\` dir (via `IDAUSR`); the IDA install dir and `%APPDATA%\.idapro` are never touched.
- **Multi-version aware** -`reverse-mcp ida list` shows every discovered install with a backend status. v0.1 ships a verified backend for 9.2 only; other versions are discovered and reported as `backend unavailable`, never silently driven.

## Discovery order

1. `--ida-dir` / config
2. `IDADIR`
3. `ida-config.json` (`%APPDATA%\Hex-Rays\IDA Pro` / `~/.idapro`)
4. OS-native (uninstall registry, App Paths, macOS/Linux equivalents)
5. common default paths
6. `ida.reg` hints
7. cached drive-root scan

Every candidate is validated (runtime libs present, version read from the PE version resource / name hints) and the worker re-verifies at startup via `get_library_version()`.

## Versioned backends

Backends are pinned per IDA SDK revision in a checked-in registry
(`crates/rmcp-core/src/backend_registry.rs`): the exact SDK version/commit,
FFI source revision, binding-generator versions, and verified architectures.
Discovery marks an install `backend ready` only when a verified manifest
exists for its version - other versions are never silently driven.

Layout correctness is enforced by an **ABI probe** (`backends/abi/`): the
C++ contract file is compiled against the exact vendored SDK headers and
static_asserts every recorded sizeof/alignof/offsetof from
`backends/abi/expected-9_2.json`; the same JSON is checked against the Rust
mirrors in `crates/reverse-ida-sys` unit tests, so C++ and Rust are verified
against one source of truth. Run it locally with
`pwsh scripts/run-abi-probe.ps1` (needs the SDK headers + any clang++, the
pinned `zig c++` driver works).

Build tools (clang via `zig`, `ninja`) are pinned with
[DotSlash](https://dotslash-cli.com) pinfiles under `toolchain/dotslash/`;
Rust is pinned by `rust-toolchain.toml`. Only redistributable build tools
are pinned there - never IDA/Hex-Rays material. See
[`toolchain/README.md`](toolchain/README.md).

`reverse-mcp doctor` reports all of the above: toolchain pins, backend
manifests, ABI-probe status, and discovered installs.

## Prerequisites

- Windows x86_64 (Linux/macOS untested - see platform matrix in `doctor`/docs)
- **IDA Pro 9.2** with a valid license (launched at least once)
- Rust stable (building only; version pinned via `rust-toolchain.toml`)

## Quick start

```powershell
cargo build --release -p reverse-mcp --features idalib

# sanity check: discovery + worker + real IDA chain
.\target\release\reverse-mcp.exe selftest

# list IDA installs and their backend status
.\target\release\reverse-mcp.exe ida list

# run the MCP server over stdio (or: serve --http 127.0.0.1:8750)
.\target\release\reverse-mcp.exe serve
```

### Grok Build / Claude Desktop config

```json
{
  "mcpServers": {
    "reverse-mcp": {
      "command": "D:\\path\\to\\reverse-mcp.exe",
      "args": ["serve"]
    }
  }
}
```

### Recommended agent workflow (minimal token usage)

1. Open once: `ida_db action=open` -> keep the returned `db1`-style handle.
2. Pull context via resources (`ida://db/{id}/metadata|segments|imports|info`)
   instead of tool calls where possible.
3. Analyze with `ida_batch` for independent reads; `ida_capabilities` tells
   you what the backend supports and the output budgets.
4. Mutate through `ida_mutation`: `plan` -> review -> `apply` with
   `expected_revision`; take a `snapshot` before byte patches; verify with
   `audit`.
5. Large responses arrive as `result_ref: rN` - fetch with `ida_result`.
6. Reach for the specialized engines when basic reads are not enough:
   `ida_evidence` to find functions by behavior, `ida_deep` for recursive
   analysis (budgeted, resumable, cached), `ida_type_recovery` for
   structs/vtables, `ida_intel` for crypto/API-hash/strings,
   `ida_deobfuscate` for obfuscation passes, `ida_sig` for cross-IDB
   mapping. Long calls accept `timeout_ms` (clamped 5s..30min) and return
   partial results with a resume token instead of dying on budget hit.

The `ida_survey_binary` / `ida_analyze_function_deep` / `ida_safe_refactor`
MCP prompts encode these steps and can be listed via `prompts/list`.
## Development

```powershell
cargo test -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker -p rmcp-broker -p reverse-ida-sys
cargo clippy -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker -p rmcp-broker --all-targets -- -D warnings

# real-IDA integration tests (local, requires IDADIR + license)
cargo test --release -p reverse-mcp --features idalib --test idalib_real -- --ignored

# ABI probe: verify SDK layouts against backends/abi/expected-9_2.json
pwsh scripts/run-abi-probe.ps1

# reproducible benchmark (mock mode; add --real-ida locally with IDADIR set)
cargo run --release -p reverse-mcp -- bench
```

Note: the `--features idalib` build statically imports `ida.dll`/`idalib.dll`,
so the exe requires the IDA install directory on `PATH` at startup. Mock-only
builds (feature off, the default) have no IDA imports and run anywhere - this
is what CI exercises.

## Contributing

`main` is protected: changes land via PR (squash merge preferred). CI runs fmt, clippy `-D warnings`, and the mock-backend test suite on windows-latest. The real-IDA suite runs locally before any release.

## License & scope

- IDA Pro, idalib, and the Hex-Rays decompilers are **proprietary Hex-Rays products**; they are never bundled, downloaded, or redistributed by this repo. You need your own licensed install.
- Everything else in this repository: see `LICENSE`.
