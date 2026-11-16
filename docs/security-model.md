# Security model

filevet parses hostile files on purpose, so its own parsers are the most exposed code it has. Every analyzer run happens inside a sandbox, and the sandbox decides what a compromised parser can still reach. This page covers what each backend guarantees and where each one stops. The reasons behind the design are in [ADR 13](adr/0013-sandbox-backends.md), and the wider threats are in the [threat model](threat-model.md).

## Choosing a backend

Set `FILEVET_SANDBOX` for the CLI, the API and the workers, or pass `sandbox=` to `scan()`, `extract_text()` and `sanitize()`.

| Value | Needs | Use it for |
| --- | --- | --- |
| `subprocess` (default) | Linux or macOS | Development, CI, and pods that already run under the gVisor RuntimeClass |
| `nsjail` | `nsjail` on `PATH`, x86-64, unprivileged user namespaces allowed | Production hosts and VMs |
| `gvisor` | `runsc` on `PATH` | Production hosts with gVisor installed |

An unknown value, or a jailed backend whose binary is missing, stops the scan with a usage error instead of falling back to something weaker.

On Ubuntu 24.04 and later, AppArmor blocks unprivileged user namespaces by default. Both `nsjail` and rootless `runsc` need them: either allow them with `sysctl kernel.apparmor_restrict_unprivileged_userns=0` or give the binary its own AppArmor profile.

## What every backend does

- Each analyzer run gets a new process that handles one artifact and is then killed. No state carries over from one file to the next.
- The run is limited by `--timeout` (wall clock) and `memory_bytes` (address space).
- The result comes back as JSON and is validated against `AnalyzerResult`. Oversized results are rejected. Nothing is ever unpickled, in either direction.
- A timeout, crash, exception or invalid result becomes a `pipeline.analyzer_error` finding with severity `high`, so a parser can't hide a file by crashing.
- Only the exception type reaches the report, never its message.

## What the jailed backends add

`nsjail` and `gvisor` start a new interpreter, `python -I -m filevet.core.sandbox`, for every run. Inside the jail:

| Control | nsjail | gvisor |
| --- | --- | --- |
| Network | New network namespace with no interfaces, not even loopback | `--network=none` |
| Root filesystem | Empty and read-only | Empty and read-only (OCI `root.readonly`) |
| Mounted | Python runtime and import path (read-only), the sample at `/sample` (read-only), `/dev/null`, `/dev/urandom`, a tmpfs at `/work` the size of `max_input_bytes` | The same, plus gVisor's own `/proc` and `/dev` |
| User | uid and gid 65534, mapped to the filevet user outside | uid and gid 65534 inside the sandbox |
| Capabilities | None | None |
| `no_new_privs` | Yes | Yes |
| Seccomp | Allow-list (`SYSCALLS` in `core/sandbox.py`) as a Kafel policy, everything else returns `ENOSYS` | The same allow-list as an OCI profile, loaded with `--oci-seccomp`, on top of gVisor's own syscall layer |
| Limits | rlimits on address space, CPU seconds, file size, open files (64) and processes (16) | The same rlimits, plus memory and PID cgroup limits when `runsc` runs as root |
| Process creation | `clone` only with `CLONE_THREAD`, so threads work and `fork` fails | The same |

So a parser that a crafted file has taken over can read the sample and the Python files, write up to `max_input_bytes` into `/work`, and use CPU and memory until a limit stops it. It can't open a network connection, read `/etc` or the filevet user's home, write anywhere that survives the run, start processes or gain privileges.

## Escape tests

`tests/unit/test_sandbox.py` runs five test-only analyzers through each jailed backend: one opens a socket, one reads `/etc/passwd`, one writes outside the work directory, one forks in a loop and one allocates past the memory limit. Each attempt must come back as `test.blocked` or as a `pipeline.analyzer_error`, never as `test.escaped`. A sixth, harmless analyzer must succeed, so a jail that can't start Python at all can't pass by blocking everything. The `sandbox` job in `ci.yml` builds nsjail from a pinned commit, installs a pinned gVisor release and runs these tests on every pull request.

Run them yourself with `uv run pytest -m "requires_nsjail or requires_gvisor"`. They're skipped when the binaries aren't on `PATH`.

## Limits and known gaps

- `subprocess` isn't a security boundary. It contains crashes, hangs and memory blowups. A compromised parser can still use the network and read whatever the filevet user can. Use it only for development, or inside a pod that's already isolated (see [Kubernetes](kubernetes.md)).
- The Python runtime is readable inside the jail. That includes every directory on `sys.path`. Don't install filevet into an environment that also holds secrets.
- `execve` is allowed, because the jail has to start Python. Only binaries from the mounted directories can be run, and they run under the same restrictions.
- x86-64 only for nsjail. The allow-list uses x86-64 syscall names. On arm64, use `gvisor` or the `subprocess` backend inside a gVisor pod.
- Rootless gVisor has no cgroup limits. Without root, `runsc` runs with `--rootless --ignore-cgroups`, so memory and PID limits come from rlimits alone.
- Analyzer state must be JSON. The jailed backends rebuild the analyzer from its class and its attributes. Analyzers that keep open handles or compiled objects on `self` get a `pipeline.analyzer_error` saying their state is not JSON.
- Jails cost start-up time. A jailed run takes 0.3 to 1 s against about 20 ms for a fork, mostly for Python start-up and imports. See [capacity planning](capacity.md).
- `supports()` runs in the parent. It must look only at the detected type, as the analyzer contract already requires.
- Native parsers aren't fuzzed with coverage. Fuzzing (see [fuzzing](fuzzing.md)) instruments filevet's Python code. Native code in qpdf, YARA and expat only gets black-box inputs.

## Reporting a sandbox escape

A file that gets out of the sandbox is a vulnerability. Report it privately as described in [SECURITY.md](https://github.com/pablodt00/filevet/blob/master/SECURITY.md).
