# Static-Analysis Corpus (issue #57)

All corpus samples are **static byte inputs only**: they are parsed by
IDA/idalib for analysis testing and are **never executed** — not by tests,
not by agents, not in CI, not on developer machines. No automatic malware
download exists in this repository, and none will be added.

## Checked-in fixtures (synthetic, inert)

| fixture | built from | purpose |
|---|---|---|
| `corpus_hostile.exe` (+`.pdb`, `.c`) | `corpus_hostile.c`, MSVC `/Od /Zi` | hostile-analysis stressors: deep recursion (self-edge), 8-leaf fan-out hub, volatile-based opaque predicates, ror13 API-hash dispatch, rolling-key XOR string decoder, vtable-style indirect calls, flattened dispatcher switch, fake-AES constant fragments. Inert: output is a printed checksum only. |
| `corpus_malformed.bin` | synthetic bytes | valid DOS header + `PE\0\0` then truncated garbage: the loader must reject or bound gracefully; the broker must stay alive. |
| `corpus_entropy.bin` | PRNG blob (seed 0xC0FFEE), 4 KiB | high-entropy non-PE bytes: no structure to hang on; same broker-liveness requirement. |
| `deep.exe`, `crypto.exe`, `obfuscated.exe`, `sig_v1.exe`/`sig_v1b.exe`, `types.exe`, `simple.exe` | existing #8–#47 fixtures | regression chain (call chains, crypto markers, junk/opaque obfuscation, cross-IDB diff pairs, UDT shapes). |

## Ground truth per case (asserted in `tests/idalib_real.rs`)

- `corpus_hostile.exe`: named functions exist (`deep_sum`, `wide_hub`,
  `opaque_chain`, `flattened`, `vtable_dispatch`, `const_noise`);
  `deep_sum` shows a self-edge (recursion) in the calls graph;
  `wide_hub` fans out to >= 8 direct callees; a tight deep-walk budget
  yields `budget_hit: true` plus a resumable frontier (no data loss);
  `deob.run` on `flattened` stays `analysis_only`, runs 5 passes with
  evidence; the API-hash query answers structurally (empty or resolved —
  never fabricated confidence for non-import names).
- `corpus_malformed.bin` / `corpus_entropy.bin`: structured error or
  bounded behavior; afterwards the broker still opens and serves a valid
  DB (failure isolation).
- Fake-AES constant fragments: the scanner must NOT report `confirmed`
  for 4-byte fragments (the not-claiming path is the tested behavior).

## Real-world benign corpus (#60)

`docs/corpus_real/manifest.json` pins 33 real Windows x86_64 binaries from
local trusted installs only (Windows OS binaries, the local IDA Pro 9.2
install, the local Rust toolchain): SHA-256 + size + source per entry.
Categories covered: OS command tools, C++/RTTI-heavy apps (Taskmgr, mmc,
explorer), the kernel image (ntoskrnl), template/STL-heavy libraries
(libclang 50 MB, libz3, Qt6), and Rust binaries.

**Static byte inputs only - never executed.** Analysis runs exclusively
through the public MCP surface (`tests/corpus_real.rs`); one bounded JSON
dossier per binary lands in `docs/corpus_real/dossiers/`, and
`docs/corpus_real/report.json` is the acceptance report (open/analyze
success, function counts, deep-analysis completion vs bounded partial,
confirmed/heuristic counts, timeout/fallback events, worker health).

Run: `cargo test -p reverse-mcp --release --features idalib --test
corpus_real -- --ignored --test-threads=1` (needs licensed IDA 9.2).

## Real-malware research samples


Policy: only user-provided, hash-pinned samples with documented provenance
and license permission; local-only (never committed, never downloaded by
CI). When used, treat exactly like the fixtures above: IDA parses bytes,
nothing executes. Record sample SHA-256 + source + date in a local
`corpus_local.md` (git-ignored) and reuse the same acceptance assertions
(function recovery, bounded budgets, fallback paths, broker liveness).
