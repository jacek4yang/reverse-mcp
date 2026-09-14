# reverse-mcp

[![ci](https://github.com/jacek4yang/reverse-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/jacek4yang/reverse-mcp/actions/workflows/ci.yml)

MCP server that gives AI agents headless, programmatic control over **IDA Pro 9.2** — a single `reverse-mcp.exe` (broker + self-spawned workers in the same binary) driving IDA through its native idalib API (no `idat`, no Python).

- Architecture details: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Tool reference: [`docs/MCP_TOOLS.md`](docs/MCP_TOOLS.md)
- Honest limitations & roadmap: [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md)

## What it does

An agent connects over MCP (stdio) and gets 17 tools:

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

Large outputs spill to a result store; truncation is always flagged, never silent.

## Guarantees

- **Optimistic concurrency** — every mutation (`ida_edit`, `ida_bytes
  action=patch`, `ida_types action=set`) accepts `expected_revision`. A stale
  value is rejected with `revision_conflict` before anything is touched; the
  revision increments only after a confirmed successful mutation.
- **Honest capabilities** — unimplemented operations fail with
  `capability_unavailable` instead of faking success. See
  [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for what is not implemented.
- **Bounded output** — every list/search/graph has hard caps; oversized
  responses spill to handles read via `ida_result`.

## Architecture

```
agent ←→ broker (reverse-mcp.exe serve, MCP stdio)
              └→ spawns itself in `worker` mode per open DB
                    └→ idalib (IDA 9.2 native FFI, one IDB per process)
```

- **One worker per DB** — IDA's idalib is single-threaded per database; the broker serializes requests and enforces `max_workers`.
- **Portable layout** — everything lives next to the exe (`plugins\`, `cache\`, `logs\`, `reverse-mcp.toml`). Plugins come only from the exe-relative `plugins\` dir (via `IDAUSR`); the IDA install dir and `%APPDATA%\.idapro` are never touched.
- **Multi-version aware** — `reverse-mcp ida list` shows every discovered install with a backend status. v0.1 ships a verified backend for 9.2 only; other versions are discovered and reported as `backend unavailable`, never silently driven.

## Discovery order

1. `--ida-dir` / config
2. `IDADIR`
3. `ida-config.json` (`%APPDATA%\Hex-Rays\IDA Pro` / `~/.idapro`)
4. OS-native (uninstall registry, App Paths, macOS/Linux equivalents)
5. common default paths
6. `ida.reg` hints
7. cached drive-root scan

Every candidate is validated (runtime libs present, version read from the PE version resource / name hints) and the worker re-verifies at startup via `get_library_version()`.

## Prerequisites

- Windows x86_64 (Linux/macOS untested)
- **IDA Pro 9.2** with a valid license (launched at least once)
- Rust stable (building only)

## Quick start

```powershell
cargo build --release -p reverse-mcp --features idalib

# sanity check: discovery + worker + real IDA chain
.\target\release\reverse-mcp.exe selftest

# list IDA installs and their backend status
.\target\release\reverse-mcp.exe ida list

# run the MCP server over stdio
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

## Development

```powershell
cargo test -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker -p rmcp-broker
cargo clippy -p reverse-mcp -p rmcp-core -p rmcp-ida -p rmcp-worker -p rmcp-broker --all-targets -- -D warnings

# real-IDA integration tests (local, requires IDADIR + license)
cargo test --release -p reverse-mcp --features idalib --test idalib_real -- --ignored
```

Note: the `--features idalib` build statically imports `ida.dll`/`idalib.dll`,
so the exe requires the IDA install directory on `PATH` at startup. Mock-only
builds (feature off, the default) have no IDA imports and run anywhere — this
is what CI exercises.

## Contributing

`main` is protected: changes land via PR (squash merge preferred). CI runs fmt, clippy `-D warnings`, and the mock-backend test suite on windows-latest. The real-IDA suite runs locally before any release.

## License & scope

- IDA Pro, idalib, and the Hex-Rays decompilers are **proprietary Hex-Rays products**; they are never bundled, downloaded, or redistributed by this repo. You need your own licensed install.
- Everything else in this repository: see `LICENSE`.
