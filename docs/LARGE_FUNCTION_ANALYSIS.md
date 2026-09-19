# Large-Function Hierarchical Analysis (Issue #72)

Whole-function Hex-Rays fails on very large functions (`too big function`,
`function frame is wrong`, `huge stack frame`). Before #72 those errors
blocked analysis entirely. Now the agent gets a working, evidence-first
path - without touching the normal-function fast path.

## Failure model (real-IDA audit)

On the giant fixture (`tests/fixtures/largefn/giant_switch_3000.dll`:
one function, 185,815 bytes, 3005 basic blocks / 6005 edges):

- `decompile` / `hr.cfunc` / `hr.microcode`: fast-fail with
  `too big function` (MERR_FUNCSIZE, ~48 ms);
- `hr.cfunc` on some machines surfaces as `function frame is wrong`
  (MERR_BADFRAME);
- `graph kind=cfg`: fully healthy (3005 nodes, 336 KB, ~51 ms).

Low-level evidence is intact even when the decompiler refuses. The
hierarchical path builds on exactly that.

## Pipeline

```text
preflight (worker graph+function_at, no Hex-Rays)
  mode = Normal | Large | Pathological          (Thresholds)
    |
    |- Normal  -> unchanged whole-function path (no regression)
    |- Large/Pathological
         v
partition CFG into virtual regions          (regions.rs, Tarjan SCC,
  Loop / Dispatcher / Chunk regions           iterative, no recursion)
    |
    v
per-region evidence in DISPOSABLE workers   (isolation.rs)
  region.evidence: bounded disassembly window
  + structured Hex-Rays failure capture
  (true hard timeout; primary session never at risk)
    |
    v
bounded cross-region dataflow fixpoint      (dataflow.rs)
  frontier is resumable; budget/deadline/convergence stop reasons
    |
    v
overview-first response + function_region drill-in
```

## Thresholds (default)

| tier | blocks | edges | bytes | SCCs |
|---|---|---|---|---|
| Large | >= 1500 | >= 2500 | >= 100 KB | - |
| Pathological | >= 10000 | >= 20000 | >= 500 KB | >= 50 |

Deterministic: the same complexity facts always produce the same mode.

## Isolation layer (the leak line)

Per-region risky work runs in a **disposable worker**: a one-shot
`<exe> worker` child (select -> open -> one method -> exit) with

- a **true hard timeout** (kill tree, not a cooperative budget);
- a Windows **Job Object** (kill-on-close + 2 GiB memory cap) so crash or
  timeout can never orphan the process;
- a **Drop guard** that synchronously kills + reaps on every path,
  including `?`;
- a process-wide **concurrency cap** (2) with explicit rejection;
- an **IsoStats ledger** (spawned == terminal) surfaced in every response.

Leak probes (`crates/rmcp-broker/tests/isolation_leak_probe.rs`): N
spawn/kill cycles leave **zero** `reverse-mcp` processes behind (counted by
exact executable path, other agents' servers excluded), the ledger balances,
the cap rejects excess, and hard timeouts kill cleanly.

## MCP surface

```text
ida_analyze workflow=function_hierarchical
  ea, max_regions (1..256, default 16), hard_timeout_ms (5s..30min)
-> mode, complexity, per-region outcomes, analysis_status,
   hexrays_failures, resume.frontier, dataflow summary, isolation stats

ida_analyze workflow=function_region
  ea, region_id, max_insns, try_hexrays, hard_timeout_ms
-> region role/blocks/preds/succs, disassembly window,
   per-region Hex-Rays attempt (structured failure capture)
```

Region identity is stable: same graph -> same partition -> same region ids,
so an agent can drill in by `region_id` from the overview.

## Verified gates

- `tests/largefn_real.rs` (real IDA, `--ignored`): the giant classifies as
  large/pathological with real complexity facts (3005 blocks), all requested
  regions produce usable evidence (complete or raw-IDA fallback), the
  primary session stays healthy, `function_region` drill-in returns a
  disassembly window, a small control function keeps the normal path, and
  no worker processes leak.
- Broker unit tests: preflight classification, region partitioner
  (stable ids, loop/dispatcher/chunk), dataflow fixpoint (convergence,
  budget, frontier).

```text
cargo test -p reverse-mcp --features idalib --test largefn_real -- --ignored --test-threads=1
```

## Explicitly not done

- Raising decompiler limits (prohibited by the issue): the failure is
  worked around structurally, not by pushing thresholds.
- Hex-Rays region snippets beyond what the decompiler can serve: failures
  are captured structurally (stage / error / fallback) and the agent gets
  raw-IDA evidence instead.
