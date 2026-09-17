# Deep Logic Reconstruction Acceptance (#62)

Methodology, safety boundary, and source list for the analysis-quality gate
that goes beyond #60's scale/stability result.

## Safety boundary (hard rules)
- **Static analysis only.** Corpus binaries are byte inputs for IDA/idalib.
  Nothing here executes, launches, installs, or emulates any sample.
- **No malware acquisition.** Nothing in this repo or its CI downloads
  samples. Tier B (real malware) runs only on user-provided, local-only,
  SHA-256-pinned samples (git-ignored) and is currently **PENDING** — no
  local samples were supplied, so no malware acceptance is claimed.
- Public reference services listed in the issue (MITRE ATT&CK, CISA MAR,
  Malpedia, MalwareBazaar, SOREL-20M, EMBER) are for *human* provenance and
  family cross-checking only; no automated acquisition pipeline exists here.

## Tier A: source-ground-truth corpus (manifest.json)
15 difficult Windows x86_64 binaries, each with source-level ground truth:
- **8 binaries from this workspace** (built here from `src/` + `Cargo.toml`,
  the ultimate ground truth): reverse-mcp itself (9.7 MB: async runtime,
  serde generics, MCP protocol handling), the e2e/HTTP multi-client test
  drivers (HTTP stack), recovery (process management), soak, corpus,
  stress (concurrency), ida_versions.
- **Official Rust-toolchain tools** (3): cargo-clippy, cargo-audit,
  cargo-deny — large LTO'd binaries with regex/serde/TLS stacks.
- **Microsoft OS builds** (2): curl (crypto/TLS, string-heavy) and bsdtar.
- **IDA 9.2 components** (2): libz3 (SMT solver: deep recursion, templates)
  and the dwarf loader plugin (format-parsing C++).

Required difficult shapes all present: large CFGs, templates/RTTI/vtables,
callbacks/indirect calls, jump tables, crypto/string-heavy logic, deep and
wide call graphs.

## Method
1. The analyzer sees only the binary (a temp copy; the analyzer never sees
   source/PDB/map paths).
2. Every probe goes through the **external MCP client path**:
   `MCP client -> initialize -> tools/list -> tools/call -> broker ->
   WorkerPool -> worker -> idalib` (stdio). No `WorkerSession` shortcut —
   the #60 artifacts (`unknown method 'imports'`, invalid `index.query`)
   came from that shortcut and are structurally impossible here; schema
   drift fails the run at `tools/list`.
3. Deep reconstruction uses **automatic resume**: a `budget_hit` partial is
   re-dispatched with `resume_from` until a terminal state (goal completed /
   explicit global function budget exhausted with a saved frontier /
   capability unavailable / deterministic failure recorded).
4. Every semantic claim is tagged `confirmed` / `heuristic` / `unavailable`
   with provenance (EA, function, import name, xref, string).
5. **Ground-truth scoring happens after analysis**, from the workspace's own
   source trees for the `our_*` binaries: known import usage (CreateFileW,
   CloseHandle, LoadLibraryExW, ...), known string constants, and known
   subsystem structure. Denominators are explicit; /O2-removed edges are
   excluded from the denominator rather than counted as failures.

## Acceptance report
`report.json` (written by `tests/logic_acceptance.rs`, gated on IDA 9.2):
per-binary dossier summary + aggregate import/string recovery percentages
with denominators, false-confirmed count (must be 0), manual-review subset
count. Run:
```
$env:IDADIR="<IDA 9.2>"
cargo test -p reverse-mcp --release --features idalib --test logic_acceptance -- --ignored --test-threads=1
```

## Tier B: real malware static-validation set
**PENDING.** No local user-provided malware samples were available for this
run. When samples exist: 5–10 samples across multiple behavior families,
each with SHA-256, acquisition date/source, Malpedia/MalwareBazaar family
aliases, and CISA MAR / vendor-report references recorded in a local
git-ignored manifest; analysis static-only; ATT&CK mappings only where
concrete static evidence supports them; claims cross-checked against the
referenced manual analyses — never against AV labels.
