# 13. Run analyzers behind a Sandbox interface with nsjail and gVisor backends

Date: 2026-11-16

## Status

Accepted. Supersedes [ADR 6](0006-subprocess-isolation-v0.md).

## Context

ADR 6 gave each analyzer run a forked process with a timeout and an address-space limit. A parser compromised by a crafted file could still open sockets, read any file the filevet user can read, write to disk and fork. filevet is meant for production, where it handles hostile files by design, so the scanner has to treat its own parsers as the main attack surface.

## Decision

`filevet.core.sandbox` defines a `Sandbox` protocol with one method, `run(analyzer, artifact, ctx)`, which returns a status, an `AnalyzerResult` and an error. `scan()`, `extract_text()` and `sanitize()` take a `sandbox` argument. When it's left out, `FILEVET_SANDBOX` picks the backend (`subprocess` by default).

| Backend | Boundary | Meant for |
| --- | --- | --- |
| `subprocess` | The ADR 6 fork with `RLIMIT_AS`, a timeout and a JSON result | Development, and pods that already run under gVisor |
| `nsjail` | Linux namespaces, a seccomp allow-list and rlimits, set up by `nsjail` | Hosts and containers where unprivileged user namespaces are allowed |
| `gvisor` | `runsc run` with an OCI bundle filevet writes for each run | Hosts with gVisor installed |

The two jailed backends start a fresh `python -I -m filevet.core.sandbox` for every analyzer run. The parent sends a JSON request on stdin: the analyzer's import path and attributes, the artifact metadata, the context and `sys.path`. The worker sends back the same JSON result as the fork backend, on stdout, into a temp file whose size the jail's `RLIMIT_FSIZE` caps. Nothing crosses in either direction as a pickle, so analyzers must keep their state in plain attributes that serialize to JSON.

Inside the jail the worker has no network namespace interfaces (not even loopback). The root filesystem is read-only and empty except for the Python runtime, the import path, `/dev/null`, `/dev/urandom`, the sample at `/sample` (read-only) and a size-limited tmpfs at `/work`. It runs as uid 65534 with no capabilities and `no_new_privs`, under limits on address space, CPU time, file size, open files and processes. The seccomp allow-list lives in one tuple, `SYSCALLS`. It becomes a Kafel policy for nsjail and an OCI profile for gVisor. `clone` is only allowed with `CLONE_THREAD`, so threads work and `fork` fails. Everything else returns `ENOSYS`.

Escape tests in `tests/unit/test_sandbox.py` run test-only analyzers that open a socket, read `/etc/passwd`, write outside the work directory, fork in a loop and allocate past the limit. CI builds nsjail from a pinned commit, installs a pinned gVisor release and runs them on every pull request.

## Consequences

A jailed run costs a Python start-up and the analyzer's imports, measured at 0.3 to 1 s per run (pyHanko alone takes about a second to import), against about 20 ms for a fork. Jailed backends suit queue workers better than synchronous API calls. Analyzers that hold non-JSON state (open handles, compiled objects) have to build it inside `analyze()`. The syscall names in the allow-list are x86-64 names, so the nsjail backend is x86-64 only for now. In Kubernetes the chart runs workers under the `gvisor` RuntimeClass with the `subprocess` backend inside, so the pod itself is the gVisor boundary. Fork-based isolation still has the multithreaded-parent caveat from ADR 6. The jailed backends don't, because they start a new interpreter.
