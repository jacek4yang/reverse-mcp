# Changelog

All notable changes to `reverse-mcp` are documented here.
Format follows Keep a Changelog; versioning follows SemVer.

## [1.0.0] - 2026-09-19

First production release. Support contract:
**Windows x86_64 + IDA Pro 9.2: production supported and real-IDA tested.**
Linux/macOS real-IDA verification and IDA versions other than 9.2 are
architecture-supported only (not v1.0 production promises). Static analysis
does not guarantee full recovery of arbitrary packed/virtualized/
self-modifying malware.

### Added
- MCP server (stdio + HTTP) exposing 35 analysis tools over IDA/idalib:
  one-call composite workflows (#8), deep recursive decompilation with type
  propagation and dataflow (#10), type recovery (#11), crypto/API-hash/
  string intel (#12), signatures/similarity/cross-IDB mapping (#13),
  evidence index with structured queries (#14), function-structure
  operations (#19), microcode inspection (#43), value/register propagation
  (#44), block-level binary diff (#45), analysis-only deobfuscation with
  audited transform apply/rollback (#46), external rule packs (#47).
- Agent autonomy: bounded budgets on every long call; timeouts return
  partial results + resume tokens (#57); background job park/collect
  (`ida_jobs`); result spill store with cap/TTL janitor (#20).
- Cross-architecture hardening (#66): machine-readable processor/loader
  diagnostics in `db.info`, generic zero-function recovery (bounded
  `create_insn`+`add_func` sweep; verified on real MIPS malware, 0→357
  functions), precise machine-readable reasons instead of silent
  zero-function success.
- Multi-OS/multi-arch acceptance (#64): Tier-B real-malware corpus — 11
  hash-pinned samples across LockBit/CobaltStrike/Lumma/Remcos/DCRat/
  Rhadamanthys/BruteRatel/PlugX (Windows AMD64 PE), Rekoobe (Linux x86_64
  ELF), Mirai (ARM ELF), Mozi (MIPS ELF) — analyzed end-to-end through the
  public MCP surface, static-analysis-only, with evidence-backed dossiers.
- Real-IDA benchmark mode (#50): `reverse-mcp bench --real-ida` runs the
  agent-facing scenarios through the actual idalib worker with
  cache-hit verification (second pass must be cached), single-decompile
  verification, timeout→resume coverage, p50/p95 latency reporting and a
  doctor-style hard failure when no verified backend is available (never a
  silent mock fallback).
- Windows x86_64 release tooling (#69): idalib-enabled production build,
  fail-closed artifact verification, machine-path-free tool resolution,
  versioned ZIP + SHA-256 packaging with proprietary-material guards.

### Platform
- Windows x86_64: production (real-IDA gated suite, hostile-input corpus,
  Tier-A/Tier-B acceptance, real-IDA benchmark, 60s/12h/24h soak gates).
- Linux: adapter-ready, CI build/mock job green, real-IDA acceptance
  pending (#48). macOS: explicitly unverified.

### Reliability
- Worker-per-DB isolation, bounded restart with backoff, crash-recovery
  stress coverage; result-store cap + TTL janitor; hello-frame timeout;
  delayed-load IDA runtime with prebound handles.
