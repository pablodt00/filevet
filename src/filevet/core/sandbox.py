import json
import math
import multiprocessing
import os
import resource
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from importlib import import_module
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from filevet.core.analyzer import AnalysisContext, Analyzer, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.errors import ScanError
from filevet.core.limits import Limits
from filevet.core.report import Status

Outcome = tuple[Status, AnalyzerResult, str | None]

SAMPLE = "/sample"
WORK = "/work"
NOBODY = 65534
MAX_PROCS = 16
MAX_FILES = 64
CLONE_THREAD = 0x10000
SYSCALLS = (
    "read", "write", "readv", "writev", "pread64", "pwrite64", "lseek", "close", "close_range",
    "dup", "dup2", "dup3", "fcntl", "ioctl", "open", "openat", "stat", "fstat", "lstat",
    "newfstatat", "statx", "access", "faccessat", "faccessat2", "readlink", "readlinkat",
    "getdents64", "getcwd", "chdir", "fchdir", "mkdir", "mkdirat", "unlink", "unlinkat", "rename",
    "renameat", "ftruncate", "fsync", "fdatasync", "umask", "statfs", "fstatfs", "pipe", "pipe2",
    "poll", "ppoll", "select", "pselect6", "epoll_create1", "epoll_ctl", "epoll_wait",
    "epoll_pwait", "eventfd2", "mmap", "munmap", "mprotect", "mremap", "madvise", "brk", "futex",
    "set_robust_list", "get_robust_list", "set_tid_address", "rseq", "arch_prctl", "sched_yield",
    "sched_getaffinity", "getrandom", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
    "sigaltstack", "tgkill", "getpid", "gettid", "getppid", "getuid", "geteuid", "getgid",
    "getegid", "getgroups", "uname", "sysinfo", "getrlimit", "prlimit64", "getrusage",
    "clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep", "gettimeofday", "time",
    "exit", "exit_group", "execve",
)  # fmt: skip
KAFEL_NAMES = {"stat": "newstat", "fstat": "newfstat", "lstat": "newlstat", "uname": "newuname"}
_mp = multiprocessing.get_context("fork")


class Sandbox(Protocol):
    name: str

    def run(self, analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext) -> Outcome: ...


def get_sandbox(name: str | None = None) -> Sandbox:
    name = name or os.environ.get("FILEVET_SANDBOX") or "subprocess"
    if name not in BACKENDS:
        raise ScanError(f"unknown sandbox {name!r}, expected one of {', '.join(BACKENDS)}")
    return BACKENDS[name]()


class SubprocessSandbox:
    name = "subprocess"

    def run(self, analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext) -> Outcome:
        receiver, sender = _mp.Pipe(duplex=False)
        worker = _mp.Process(target=_fork_worker, args=(analyzer, artifact, ctx, sender))
        worker.start()
        sender.close()
        try:
            if not receiver.poll(ctx.limits.timeout_s):
                return _timeout(ctx.limits)
            payload = receiver.recv_bytes(_result_cap(ctx.limits))
        except EOFError:
            worker.join(ctx.limits.timeout_s)
            return "error", AnalyzerResult(), f"worker exited with code {worker.exitcode}"
        except OSError:
            return "error", AnalyzerResult(), "result too large"
        finally:
            worker.kill()
            worker.join()
            receiver.close()
        return _parse(payload)


class _Jailed:
    name: str
    binary: str

    def run(self, analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext) -> Outcome:
        cls = type(analyzer)
        try:
            request = json.dumps(
                {
                    "analyzer": f"{cls.__module__}:{cls.__qualname__}",
                    "state": vars(analyzer),
                    "artifact": artifact.model_dump(mode="json"),
                    "ctx": ctx.model_dump(mode="json"),
                    "sample": self.sample(artifact),
                    "path": [p for p in sys.path if Path(p).is_dir()],
                }
            ).encode()
        except TypeError:
            return "error", AnalyzerResult(), "analyzer state is not JSON"
        executable = shutil.which(self.binary)
        if executable is None:
            raise ScanError(f"the {self.name} sandbox needs {self.binary} on PATH")
        cap = _result_cap(ctx.limits)
        with (
            tempfile.TemporaryDirectory(prefix="filevet-jail-") as tmp,
            tempfile.TemporaryFile() as out,
        ):
            argv = self.argv(executable, Path(tmp), artifact.path, ctx.limits)
            try:
                proc = subprocess.run(  # noqa: S603 - fixed argv from argv(), the sample is only a mount path
                    argv,
                    input=request,
                    stdout=out,
                    stderr=subprocess.DEVNULL,
                    timeout=ctx.limits.timeout_s,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return _timeout(ctx.limits)
            finally:
                self.cleanup(executable, Path(tmp))
            out.seek(0)
            payload = out.read(cap + 1)
        if len(payload) > cap:
            return "error", AnalyzerResult(), "result too large"
        if not payload:
            return "error", AnalyzerResult(), f"worker exited with code {proc.returncode}"
        return _parse(payload)

    def sample(self, artifact: Artifact) -> str:
        return SAMPLE

    def argv(self, executable: str, tmp: Path, sample: Path, limits: Limits) -> list[str]:
        raise NotImplementedError

    def cleanup(self, executable: str, tmp: Path) -> None:
        return None


class NsjailSandbox(_Jailed):
    name = "nsjail"
    binary = "nsjail"

    def argv(self, executable: str, tmp: Path, sample: Path, limits: Limits) -> list[str]:
        policy = tmp / "policy.kafel"
        policy.write_text(_kafel())
        mounts = [arg for d in runtime_dirs() for arg in ("-R", d)]
        return [
            executable,
            "--mode", "o",
            "--really_quiet",
            "--user", str(NOBODY),
            "--group", str(NOBODY),
            "--hostname", "filevet",
            "--disable_proc",
            "--iface_no_lo",
            "--time_limit", str(math.ceil(limits.timeout_s) + 1),
            "--rlimit_as", str(_mb(limits.memory_bytes)),
            "--rlimit_cpu", str(math.ceil(limits.timeout_s)),
            "--rlimit_fsize", str(_mb(_result_cap(limits))),
            "--rlimit_nofile", str(MAX_FILES),
            "--rlimit_nproc", str(MAX_PROCS),
            "--seccomp_policy", str(policy),
            "-m", f"none:{WORK}:tmpfs:size={limits.max_input_bytes}",
            "-R", f"{sample}:{SAMPLE}",
            "-B", "/dev/null",
            "-R", "/dev/urandom",
            *mounts,
            "--cwd", WORK,
            *(arg for kv in _env() for arg in ("--env", kv)),
            "--", sys.executable, "-I", "-m", __name__,
        ]  # fmt: skip


class GvisorSandbox(_Jailed):
    name = "gvisor"
    binary = "runsc"

    def argv(self, executable: str, tmp: Path, sample: Path, limits: Limits) -> list[str]:
        bundle = tmp / "bundle"
        (bundle / "rootfs").mkdir(parents=True)
        (bundle / "config.json").write_text(json.dumps(oci_spec(sample, limits)))
        rootless = ["--rootless", "--ignore-cgroups"] if os.geteuid() else []
        return [
            executable, "--root", str(tmp / "state"), "--network=none", "--oci-seccomp",
            *rootless, "run", "--bundle", str(bundle), tmp.name,
        ]  # fmt: skip

    def cleanup(self, executable: str, tmp: Path) -> None:
        subprocess.run(  # noqa: S603 - fixed argv, the container id is our temp dir name
            [executable, "--root", str(tmp / "state"), "delete", "--force", tmp.name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


BACKENDS: dict[str, type[Sandbox]] = {
    "subprocess": SubprocessSandbox,
    "nsjail": NsjailSandbox,
    "gvisor": GvisorSandbox,
}


def runtime_dirs(path: Sequence[str] | None = None) -> list[str]:
    wanted = {sys.prefix, sys.base_prefix, *(path if path is not None else sys.path)}
    wanted |= {d for d in ("/lib", "/lib64", "/usr/lib", "/usr/lib64") if Path(d).is_dir()}
    dirs = sorted(str(Path(d).absolute()) for d in wanted if d and Path(d).is_dir())
    return [d for i, d in enumerate(dirs) if not any(d.startswith(p + "/") for p in dirs[:i])]


def oci_spec(sample: Path, limits: Limits) -> dict[str, Any]:
    cpu = math.ceil(limits.timeout_s)
    rlimits = {
        "RLIMIT_AS": limits.memory_bytes,
        "RLIMIT_CPU": cpu,
        "RLIMIT_FSIZE": _result_cap(limits),
        "RLIMIT_NOFILE": MAX_FILES,
        "RLIMIT_NPROC": MAX_PROCS,
    }
    ro = ["bind", "ro", "nosuid", "nodev"]
    return {
        "ociVersion": "1.0.2",
        "hostname": "filevet",
        "root": {"path": "rootfs", "readonly": True},
        "process": {
            "args": [sys.executable, "-I", "-m", __name__],
            "env": _env(),
            "cwd": WORK,
            "user": {"uid": NOBODY, "gid": NOBODY},
            "noNewPrivileges": True,
            "capabilities": {
                k: [] for k in ("bounding", "effective", "permitted", "inheritable", "ambient")
            },
            "rlimits": [{"type": t, "hard": v, "soft": v} for t, v in rlimits.items()],
        },
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs"},
            {
                "destination": WORK,
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "nodev", f"size={limits.max_input_bytes}"],
            },
            {"destination": SAMPLE, "type": "bind", "source": str(sample), "options": ro},
            *(
                {"destination": d, "type": "bind", "source": d, "options": ro}
                for d in runtime_dirs()
            ),
        ],
        "linux": {
            "namespaces": [{"type": t} for t in ("pid", "network", "ipc", "uts", "mount")],
            "resources": {"memory": {"limit": limits.memory_bytes}, "pids": {"limit": MAX_PROCS}},
            "seccomp": {
                "defaultAction": "SCMP_ACT_ERRNO",
                "defaultErrnoRet": 38,
                "syscalls": [
                    {"names": list(SYSCALLS), "action": "SCMP_ACT_ALLOW"},
                    {
                        "names": ["clone"],
                        "action": "SCMP_ACT_ALLOW",
                        "args": [
                            {
                                "index": 0,
                                "value": CLONE_THREAD,
                                "valueTwo": CLONE_THREAD,
                                "op": "SCMP_CMP_MASKED_EQ",
                            }
                        ],
                    },
                ],
            },
        },
    }


def main() -> None:
    request = json.loads(sys.stdin.buffer.read(1 << 24))
    sys.path[:0] = [p for p in request["path"] if p not in sys.path]
    module, _, qualname = request["analyzer"].partition(":")
    cls: Any = import_module(module)
    for part in qualname.split("."):
        cls = getattr(cls, part)
    analyzer = cls.__new__(cls)
    analyzer.__dict__.update(request["state"])
    ctx = AnalysisContext.model_validate(request["ctx"])
    artifact = Artifact.model_validate({**request["artifact"], "path": request["sample"]})
    sys.stdout.buffer.write(_analyze(analyzer, artifact, ctx))


def _fork_worker(
    analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext, conn: Connection
) -> None:
    conn.send_bytes(_analyze(analyzer, artifact, ctx))


def _analyze(analyzer: Analyzer, artifact: Artifact, ctx: AnalysisContext) -> bytes:
    memory = ctx.limits.memory_bytes
    resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
    try:
        result = analyzer.analyze(artifact, ctx)
        return AnalyzerResult.model_validate(result).model_dump_json().encode()
    except Exception as exc:
        return b"!" + type(exc).__name__.encode("ascii", "replace")


def _parse(payload: bytes) -> Outcome:
    if payload.startswith(b"!"):
        return "error", AnalyzerResult(), f"raised {payload[1:].decode('ascii', 'replace')}"
    try:
        return "ok", AnalyzerResult.model_validate_json(payload), None
    except ValidationError:
        return "error", AnalyzerResult(), "returned an invalid result"


def _timeout(limits: Limits) -> Outcome:
    return "timeout", AnalyzerResult(), f"no result after {limits.timeout_s:g} s"


def _result_cap(limits: Limits) -> int:
    return 2 * limits.max_total_expanded_bytes + (1 << 20)


def _mb(n: int) -> int:
    return max(1, math.ceil(n / (1 << 20)))


def _env() -> list[str]:
    return [f"TMPDIR={WORK}", f"HOME={WORK}", "PYTHONDONTWRITEBYTECODE=1", "LANG=C.UTF-8"]


def _kafel() -> str:
    return (
        "POLICY filevet {\n  ALLOW {\n    "
        + ",\n    ".join(KAFEL_NAMES.get(s, s) for s in SYSCALLS)
        + f",\n    clone {{ (clone_flags & {CLONE_THREAD:#x}) == {CLONE_THREAD:#x} }}"
        + "\n  }\n}\nUSE filevet DEFAULT ERRNO(38)\n"
    )


if __name__ == "__main__":
    main()
