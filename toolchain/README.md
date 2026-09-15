# DotSlash toolchain

Reproducible native build tools for reverse-mcp, fetched on demand with
[DotSlash](https://dotslash-cli.com) and pinned by size + hash in the
checked-in pinfiles under `dotslash/`.

## What is pinned

| Tool  | Version | Purpose                                     | Pinfile          |
| ----- | ------- | ------------------------------------------- | ---------------- |
| zig   | 0.14.1  | `zig c++` driver for the IDA ABI probe      | `dotslash/zig`   |
| ninja | 1.12.1  | build backend for the autocxx/cxx C++ build | `dotslash/ninja` |

libclang for the idalib feature build itself continues to come from the
system (`LIBCLANG_PATH`); the pinned zig driver is used by the ABI probe.

## Bootstrap from a clean checkout

1. Install DotSlash once (see <https://dotslash-cli.com/docs/installation>).
2. Provision the tools:

   ```sh
   dotslash toolchain/dotslash/zig
   dotslash toolchain/dotslash/ninja
   ```

   Each invocation downloads, verifies, caches and executes the pinned
   artifact; the printed version output confirms the pin.
3. Run the ABI probe against a local IDA SDK checkout:

   ```powershell
   pwsh scripts/run-abi-probe.ps1 -Clang toolchain/bin/zig
   ```

   The probe only *compiles* against the SDK headers; it needs no IDA
   runtime, decompiler, or license and produces no proprietary artifacts.

## Policy

- Only redistributable build tools are pinned here. IDA runtime,
  Hex-Rays decompilers, licenses, and any other proprietary Hex-Rays
  material must **never** be distributed via DotSlash (or any other
  channel) — see also `scripts/check-distribution.ps1`.
- Bump a pin by updating the version, URLs, sizes, and digests together,
  and note the reason in the PR. Re-run the ABI probe afterwards; the
  expected layout values change only when the SDK changes, never with the
  compiler choice.
