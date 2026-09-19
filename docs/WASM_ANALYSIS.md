# WASM Analysis (Issue #71)

Static-only WebAssembly analysis fusing **IDA Pro's native WASM loader** with
the independent **rmcp-wasm** semantic parser. Never executes module code.

## Architecture

```text
            .wasm module file
             |            |
             v            v
      IDA native       rmcp-wasm parser (wasmparser 0.259)
      WASM loader      bounded, normalized module model
      names/segments        |
             |            v
             |      cfg / calls / indirect / pseudocode
             +--------+---------+
                      v
              ida_wasm MCP tool
        cross-engine checks + fusion
```

- **IDA side**: loader + processor provide function discovery, names
  (name custom section), and EA mapping of wasm sections. Exposed through
  the existing `ida_functions` / `ida_segments` surfaces.
- **Parser side** (`crates/rmcp-wasm`): normalized module model
  (sections with exact byte ranges, types, imports/exports, functions with
  code offsets, locals, globals, tables, memories, element/data segments,
  feature map, name/producers custom sections), structured CFG that
  preserves block/loop/if structure, operand-stack-to-SSA value analysis,
  indirect-call resolution with evidence, deterministic WASM-native
  pseudocode.
- **Fusion** (`ida_wasm`): every row in `functions` carries per-row
  provenance (`parser` / `ida` / `parser+ida`); cross-engine checks compare
  function counts and code-section EA coverage. Disagreements surface as
  `diagnostics`, never silently hidden.

## The `ida_wasm` tool

| action | result |
|---|---|
| `info` | module overview: version, sections, feature map, counts, cross-engine checks, Hex-Rays honesty note |
| `sections` / `types` | exact byte ranges (offset+size per section), signatures |
| `imports` | import entries with WASI capability grouping |
| `exports` / `globals` / `tables` / `memories` / `elements` / `datas` | full index-space listings |
| `functions` | fused rows: wasm index, type, code offset/size, parser name, IDA name/EA, name source |
| `cfg` | structured control flow for one function (`index`): block/loop/if regions preserved, never flattened |
| `pseudocode` | deterministic WASM-native C-like rendering. **NOT Hex-Rays output** (IDA has no WASM decompiler) |
| `indirect_targets` | evidence-backed `call_indirect` resolution: confirmed / candidate / unresolved, never fabricated certainty |

All actions are static, bounded, and cache-friendly. Malformed modules fail
locally with a bounded diagnostic; the broker and worker never crash.

## Hex-Rays honesty

IDA 9.2 ships no WASM decompiler. `ida_wasm` reports
`hexrays: unavailable` on every info response, and the `pseudocode` action
is explicitly labeled as the deterministic rmcp-wasm renderer.

## WASM crash fix (audit finding)

IDA's WASM processor emits `op_t.type` values outside the classic operand
range for `br_if <depth>`. Two failure modes were identified and fixed:

1. **Vendor safety** (`vendor/idalib/src/insn.rs`): `Operand::type_()`
   used `mem::transmute` over the raw type byte and panicked on
   out-of-range discriminants ("trying to construct an enum from an invalid
   value 0xe"). It is now a total mapping with an `UnknownIdp` variant;
   `dtype()` returns the raw byte.
2. **Backend hardening** (`rmcp-ida` `disassemble`): label rendering for
   `br_if` inside `generate_disasm_line` capacity-overflows in headless
   idalib (repro: `tests/fixtures/wasm/audit_minimal.wasm` @ `0xb2` kills
   the worker). The backend now detects `br_if` from the raw opcode byte
   (`0x0d`) and renders the line synthetically, never calling IDA's
   renderer for that EA. Zero-length decodes terminate the walk.

Regression gates (`--ignored`, run with `IDADIR` set):

```text
cargo test -p reverse-mcp --features idalib --test wasm_real -- --ignored --test-threads=1
```

- `wasm_db_full_chain`: open -> functions/segments -> disassemble (br_if)
  -> CFG -> session health.
- `wasm_ida_wasm_tool_actions`: `ida_wasm` info/functions/cfg/pseudocode/
  indirect_targets through the registry + malformed-module bounded failure.

## Feature matrix

Parsed and reported in `info.features`: multi-value, bulk memory, reference
types, SIMD, relaxed SIMD, tail calls, exception handling, threads, memory64,
multi-memory, GC. Unsupported constructs (e.g. stack-switching `cont` types)
fail locally with an explicit parse error.

## Provenance and cache keys

Module parse results are keyed by binary sha256 + analysis revision +
parser/engine version; a parser upgrade never serves stale IR.
