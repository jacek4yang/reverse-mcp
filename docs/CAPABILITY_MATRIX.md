# Capability Matrix (issue #18)

Classification per capability: **unsupported** / **partial** / **implemented** /
**real-IDA tested** / **different approach** (same information via a more
composable/bounded workflow). Evidence links point to source, tests, or docs.
Last audited: 2026-09 (against each project's public README/source layout at
that time; re-audit before relying on a competitor row).

Scope note: competitor rows summarize publicly documented capabilities at the
capability-group level; they are audit targets, not benchmarks of code quality.

| Capability | reverse-mcp | ida-pro-mcp (mrexodia) | ida-mcp (debugpro) | ida-pro-mcp (GrecAndrei) | ida-fast-mcp | hrtng | HexRaysPyTools | findcrypt-yara | BinDiff |
|---|---|---|---|---|---|---|---|---|---|
| runtime/session | implemented, real-IDA tested ([worker pool](../crates/rmcp-broker/src/worker_pool.rs)) | implemented (in-process plugin) | implemented | implemented | implemented | n/a (IDA plugin) | n/a | n/a | separate GUI tool |
| functions | implemented, real-IDA tested ([backend](../crates/rmcp-ida/src/idalib_backend.rs)) | implemented | implemented | implemented | implemented | implemented | partial | n/a | implemented |
| CFG/callgraph | implemented ([graph](../crates/rmcp-ida/src/idalib_backend.rs)) | partial | partial | partial | partial | implemented | partial | n/a | implemented |
| xrefs | implemented, real-IDA tested | implemented | implemented | implemented | implemented | implemented | partial | n/a | implemented |
| imports/exports | implemented, real-IDA tested | implemented | implemented | implemented | implemented | implemented | n/a | n/a | implemented |
| strings/search | implemented, real-IDA tested | implemented | implemented | implemented | implemented | implemented | n/a | n/a | partial |
| bytes/data | implemented, real-IDA tested | implemented | implemented | implemented | implemented | implemented | n/a | n/a | n/a |
| Hex-Rays pseudocode | implemented, real-IDA tested ([hr](../crates/rmcp-ida/src/idalib_backend.rs)) | implemented | implemented | implemented | implemented | implemented | implemented | n/a | n/a |
| ctree | implemented (bounded walk, [caps](../vendor/idalib/src/caps.rs)) | n/a | n/a | n/a | n/a | implemented | implemented | n/a | n/a |
| microcode | implemented (generation+inspection via `ida_hr action=microcode`, real-IDA tested; transforms are proposals, tracked in #46) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | n/a |
| types/structs/enums | implemented, real-IDA tested ([types](../crates/rmcp-worker/src/types.rs)) | implemented | implemented | implemented | implemented | implemented | implemented | n/a | n/a |
| stack frames/lvars | implemented (lvar rename, real-IDA tested) | implemented | implemented | implemented | partial | implemented | implemented | n/a | n/a |
| vtable/classes | implemented (evidence + vtable scan, real-IDA tested) | partial | partial | partial | n/a | implemented | implemented | n/a | n/a |
| register/value tracking | partial (ctree/call-site evidence) | n/a | n/a | n/a | n/a | partial | partial | n/a | n/a |
| data flow | implemented, real-IDA tested ([deep](../crates/rmcp-worker/src/deep.rs)) | n/a | n/a | n/a | n/a | partial | partial | n/a | partial |
| crypto detection | implemented, real-IDA tested ([crypto](../crates/rmcp-worker/src/crypto.rs)); extensible rule packs with provenance (#47) | n/a | n/a | n/a | n/a | implemented | n/a | implemented | n/a |
| API hashing | implemented (registry + corpus verification) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | n/a |
| string recovery | implemented (stack/array immediates) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | n/a |
| deobfuscation/unflattening | partial (analysis-only detection + proposals) | n/a | n/a | n/a | n/a | implemented (analysis + explicit patch transforms w/ validate+rollback; microcode transforms pending) | n/a | n/a | n/a |
| signatures/similarity | implemented, real-IDA tested ([signatures](../crates/rmcp-worker/src/signatures.rs)) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | implemented (best in class) |
| cross-IDB diff | function-level mapping + block-level diff with equal/modified/added/removed classification and evidence-fallback pairing (#45); no visual diff | n/a | n/a | n/a | n/a | implemented (block-level) | n/a | n/a | implemented (best in class) |
| patching/assembly | implemented (patch_bytes, real-IDA tested) | implemented | implemented | implemented | implemented | implemented | n/a | n/a | n/a |
| define/undefine | partial (func create/delete/resize) | implemented | implemented | implemented | implemented | implemented | n/a | n/a | n/a |
| snapshots/rollback | implemented (file-level snapshots, real-IDA tested) | n/a | n/a | n/a | n/a | partial | n/a | n/a | n/a |
| semantic/evidence search | implemented, real-IDA tested ([index](../crates/rmcp-core/src/analysis_index.rs)) | n/a | n/a | n/a | n/a | partial | n/a | n/a | n/a |
| high-level Agent workflows | implemented (one-call composite workflows) | n/a | n/a | n/a | n/a | partial | n/a | n/a | n/a |
| multi-IDB | implemented (multiple sessions, real-IDA tested) | n/a (single IDB) | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| multi-client | implemented (stdio + HTTP, shared broker) | n/a (stdio only) | partial | partial | partial | n/a | n/a | n/a | n/a |
| crash recovery | implemented (bounded restart, real-IDA tested) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| token/output controls | implemented (budgets, spill, ranking everywhere) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| cross-platform/multi-version | partial (Windows 9.2 real-IDA tested; multi-version discovery with honest registry gating; OS specifics behind `rmcp_core::platform` adapter, Linux CI mock job; Linux/macOS real-IDA acceptance pending #48) | multi-platform | Windows | multi-platform | multi-platform | multi-platform | multi-platform | multi-platform | multi-platform |
| worker probe hardening | implemented (re-entrancy guard + IDA-dir-aware probe, PR #26) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| reproducible benchmark | implemented (`reverse-mcp bench`, mock mode; real-IDA mode tracked in #50) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |

## Where reverse-mcp takes a different approach
- One-call composite workflows (#8) instead of many atomic calls: the agent
  spends fewer round trips and less context.
- Everything index-backed and revision-keyed: repeated queries are free,
  mutations invalidate.
- Analysis-only deobfuscation with proposal/apply separation, never silent.
- Strict/relaxed signature policy with conflict detection before any rename.

## Explicit follow-ups (competitor advantages not yet matched)
Tracked as GitHub issues: 1→#43, 2→#45, 3→#47. Follow-up 5 (#48,
non-Windows real-IDA verification) is in progress: the platform adapter is
landed and CI carries a Linux mock job; full closure requires the gated
real-IDA suite to pass on Linux/macOS installs (tested facts only).
