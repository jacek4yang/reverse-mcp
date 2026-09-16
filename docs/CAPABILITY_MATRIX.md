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
| microcode | partial (analysis hooks; no transforms yet) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | n/a |
| types/structs/enums | implemented, real-IDA tested ([types](../crates/rmcp-worker/src/types.rs)) | implemented | implemented | implemented | implemented | implemented | implemented | n/a | n/a |
| stack frames/lvars | implemented (lvar rename, real-IDA tested) | implemented | implemented | implemented | partial | implemented | implemented | n/a | n/a |
| vtable/classes | implemented (evidence + vtable scan, real-IDA tested) | partial | partial | partial | n/a | implemented | implemented | n/a | n/a |
| register/value tracking | partial (ctree/call-site evidence) | n/a | n/a | n/a | n/a | partial | partial | n/a | n/a |
| data flow | implemented, real-IDA tested ([deep](../crates/rmcp-worker/src/deep.rs)) | n/a | n/a | n/a | n/a | partial | partial | n/a | partial |
| crypto detection | implemented, real-IDA tested ([crypto](../crates/rmcp-worker/src/crypto.rs)) | n/a | n/a | n/a | n/a | implemented | n/a | implemented | n/a |
| API hashing | implemented (registry + corpus verification) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | n/a |
| string recovery | implemented (stack/array immediates) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | n/a |
| deobfuscation/unflattening | partial (analysis-only detection + proposals) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | n/a |
| signatures/similarity | implemented, real-IDA tested ([signatures](../crates/rmcp-worker/src/signatures.rs)) | n/a | n/a | n/a | n/a | implemented | n/a | n/a | implemented (best in class) |
| cross-IDB diff | partial (function-level mapping; no block-level diff) | n/a | n/a | n/a | n/a | partial | n/a | n/a | implemented (best in class) |
| patching/assembly | implemented (patch_bytes, real-IDA tested) | implemented | implemented | implemented | implemented | implemented | n/a | n/a | n/a |
| define/undefine | partial (func create/delete/resize) | implemented | implemented | implemented | implemented | implemented | n/a | n/a | n/a |
| snapshots/rollback | implemented (file-level snapshots, real-IDA tested) | n/a | n/a | n/a | n/a | partial | n/a | n/a | n/a |
| semantic/evidence search | implemented, real-IDA tested ([index](../crates/rmcp-core/src/analysis_index.rs)) | n/a | n/a | n/a | n/a | partial | n/a | n/a | n/a |
| high-level Agent workflows | implemented (one-call composite workflows) | n/a | n/a | n/a | n/a | partial | n/a | n/a | n/a |
| multi-IDB | implemented (multiple sessions, real-IDA tested) | n/a (single IDB) | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| multi-client | implemented (stdio + HTTP, shared broker) | n/a (stdio only) | partial | partial | partial | n/a | n/a | n/a | n/a |
| crash recovery | implemented (bounded restart, real-IDA tested) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| token/output controls | implemented (budgets, spill, ranking everywhere) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |
| cross-platform/multi-version | partial (Windows real-IDA tested; version discovery) | multi-platform | Windows | multi-platform | multi-platform | multi-platform | multi-platform | multi-platform | multi-platform |

## Where reverse-mcp takes a different approach
- One-call composite workflows (#8) instead of many atomic calls: the agent
  spends fewer round trips and less context.
- Everything index-backed and revision-keyed: repeated queries are free,
  mutations invalidate.
- Analysis-only deobfuscation with proposal/apply separation, never silent.
- Strict/relaxed signature policy with conflict detection before any rename.

## Explicit follow-ups (competitor advantages not yet matched)
1. Microcode-level transforms (hrtng implements real passes; #9 scope note).
2. Block-level binary diff (BinDiff is best in class; #13 scope note).
3. YARA-style external rule packs for crypto detection (findcrypt-yara).
4. Full decompiler-plugin ecosystem (HexRaysPyTools struct inference UX).
5. Non-Windows real-IDA verification (currently Windows-tested).
