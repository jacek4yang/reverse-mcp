# Engineering Principles

These requirements apply to every reverse-mcp feature, backend and future issue.

## Priorities

In order: **correctness, reliability, long-running stability, performance, portability, then feature breadth**. A feature that is fast but unreliable, or broad but unverifiable, is not complete.

## Cross-platform architecture

Windows is currently the only real-IDA-tested platform, not an architectural dependency. Portable core logic must remain OS-neutral. Isolate OS-specific process, loader, path, IPC and runtime integration behind explicit platform adapters. Keep IDA-version-specific code behind versioned backend boundaries so Windows/Linux/macOS and future IDA versions can be added without redesigning the core.

## Reliability and long-running operation

Assume reverse-mcp may run continuously under autonomous agents. Design for crash isolation, bounded recovery, deterministic cleanup, no leaked workers/handles/temp files, safe cancellation, cycle guards, resource limits and graceful shutdown. Never allow worker failures, malformed binaries or pathological analysis to cascade into broker failure or unbounded process creation.

## Performance

Minimize IDA/Hex-Rays calls, decompilation count, rescans, IPC round trips, allocations and repeated work. Prefer revision-aware caches, incremental analysis, batching, resumable computation and bounded parallelism where IDA thread-safety permits it. Performance changes must remain measurable and regression-testable.

## Accuracy and evidence

Never fabricate certainty. Results must distinguish confirmed facts, heuristics, proposals, partial results and unsupported capabilities. Derived results should carry provenance/evidence whenever practical. Prefer explicit failure or lower-confidence output over a plausible-looking incorrect answer.

## Fallback and graceful degradation

Advanced analysis must have useful lower-level fallbacks where possible. If Hex-Rays, microcode, symbols, types, plugins, a loader/processor feature or another advanced capability is unavailable or fails, fall back through lower-level IDA data such as ctree, disassembly, CFG, xrefs, bytes and metadata instead of failing the entire workflow. Report which path produced the result and its limitations.

## Complex and hostile binaries

Treat huge, malformed, packed, obfuscated and adversarial binaries as normal inputs. No algorithm may assume analysis will terminate cheaply. Expensive work must support budgets/timeouts, bounded memory/output, partial results, truncation reporting, checkpoints/resume where useful and cache reuse. The design target is to remain responsive and return the best defensible partial analysis quickly rather than hang while chasing completeness.

## Safe mutation

Analysis is read-only by default. Mutations require explicit intent, validation, revision guards and auditable outcomes; destructive or wide changes should support preview/proposal and rollback/snapshot where feasible. Never silently rewrite an IDB based on heuristic analysis.

## Verification

Every substantial feature should include the appropriate combination of unit, integration, real-IDA gated, regression, stress, fuzz/adversarial and long-running tests. Cover malformed inputs, huge CFGs, recursion/cycles, timeouts, cancellation, worker crashes, fallback paths and repeated sessions. Benchmarks should measure correctness together with latency, work avoided/cache effectiveness, round trips and output volume.

These principles are acceptance criteria, not aspirations. New issues and PRs should reference this document instead of duplicating these requirements.