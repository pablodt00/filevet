# 6. Run each analyzer in its own subprocess (isolation v0)

Date: 2026-11-11

## Status

Accepted

## Context

Analyzers parse hostile files, often with libraries that wrap native code. A parser bug can hang, allocate without limit or crash the interpreter. One bad analyzer must not take the scan down with it or hide what the other analyzers found. The full sandbox (no network, read-only filesystem, seccomp, dropped privileges) is Phase 4 work. Phase 0 needs something simple that holds until then.

## Decision

The pipeline forks a fresh process for every analyzer run. The child sets `RLIMIT_AS` to the memory limit, runs `analyze()`, and sends the result back over a pipe as JSON. The parent waits up to the timeout, then kills the child whatever happened. It validates the JSON against `AnalyzerResult`. Nothing crosses the pipe as a pickle, so a broken or compromised worker can't send back anything the parent would execute. A timeout, crash, exception, invalid result or oversized result becomes a `pipeline.analyzer_error` finding with severity `high`.

We use `multiprocessing` directly, not `ProcessPoolExecutor`. A pool can't kill a worker that's stuck past its timeout without reaching into private attributes, and with `max_tasks_per_child=1` it starts one process per task anyway.

## Consequences

Each analyzer run costs one fork, a few milliseconds. `supports()` still runs in the parent, so it has to stay cheap and only look at the detected type. Forking only works on Unix. If the parent process is multithreaded, as a future REST API might be, a fork can deadlock on a lock held by another thread. Python warns about this under pytest-xdist. Phase 4 replaces this mechanism with a `Sandbox` interface, and that's when a `forkserver` or spawned worker pool should come in.
