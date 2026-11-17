import shutil
import socket
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from filevet.core.analyzer import Analyzer
from filevet.core.artifact import Artifact
from filevet.core.errors import ScanError
from filevet.core.limits import Limits
from filevet.core.pipeline import scan
from filevet.core.sandbox import (
    MAX_PROCS,
    SYSCALLS,
    GvisorSandbox,
    NsjailSandbox,
    Sandbox,
    SubprocessSandbox,
    _Jailed,
    _kafel,
    get_sandbox,
    oci_spec,
    runtime_dirs,
)
from tests import fakes


class Direct(_Jailed):
    name = "direct"
    binary = sys.executable

    def sample(self, artifact: Artifact) -> str:
        return str(artifact.path)

    def argv(self, executable: str, tmp: Path, sample: Path, limits: Limits) -> list[str]:
        return [executable, "-I", "-m", "filevet.core.sandbox"]


def test_backend_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    assert isinstance(get_sandbox(), SubprocessSandbox)
    monkeypatch.setenv("FILEVET_SANDBOX", "nsjail")
    assert isinstance(get_sandbox(), NsjailSandbox)
    assert isinstance(get_sandbox("gvisor"), GvisorSandbox)
    with pytest.raises(ScanError, match="unknown sandbox 'docker'"):
        get_sandbox("docker")


def test_missing_binary_is_a_scan_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(ScanError, match="needs nsjail on PATH"):
        scan(b"x", analyzers=[fakes.Fake()], sandbox=NsjailSandbox())


def test_runtime_dirs_keep_only_the_outermost(tmp_path: Path) -> None:
    inner = tmp_path / "a" / "b"
    inner.mkdir(parents=True)
    dirs = runtime_dirs([str(inner), str(tmp_path / "a"), str(tmp_path / "missing")])
    assert str(tmp_path / "a") in dirs
    assert str(inner) not in dirs
    assert "/etc" not in dirs


def test_runtime_dirs_keep_symlinked_paths(tmp_path: Path) -> None:
    (tmp_path / "usr").mkdir()
    (tmp_path / "lib64").symlink_to("usr")
    assert str(tmp_path / "lib64") in runtime_dirs([str(tmp_path / "lib64")])


def test_seccomp_allow_list_leaves_out_network_and_process_creation() -> None:
    blocked = {"socket", "connect", "fork", "vfork", "clone3", "ptrace", "mount", "setuid"}
    assert not blocked & set(SYSCALLS)
    assert "clone { (clone_flags & 0x10000) == 0x10000 }" in _kafel()
    assert "DEFAULT ERRNO(38)" in _kafel()


def test_oci_spec_is_locked_down(tmp_path: Path) -> None:
    spec = oci_spec(tmp_path / "sample", Limits())
    assert spec["root"]["readonly"] is True
    assert spec["process"]["user"] == {"uid": 65534, "gid": 65534}
    assert spec["process"]["noNewPrivileges"] is True
    assert not any(spec["process"]["capabilities"].values())
    assert {"type": "network"} in spec["linux"]["namespaces"]
    assert spec["linux"]["resources"]["pids"]["limit"] == MAX_PROCS
    binds = {m["destination"]: m for m in spec["mounts"] if m["type"] == "bind"}
    assert binds["/sample"]["source"] == str(tmp_path / "sample")
    assert all("ro" in m["options"] for m in binds.values())
    assert "/etc" not in binds


def test_nsjail_argv(tmp_path: Path) -> None:
    argv = NsjailSandbox().argv("nsjail", tmp_path, tmp_path / "s", Limits(timeout_s=2.5))
    joined = " ".join(argv)
    for flag in ("--user 65534", "--iface_no_lo", "--time_limit 4", "--rlimit_nproc 16"):
        assert flag in joined
    assert f"-R {tmp_path / 's'}:/sample" in joined
    assert argv[argv.index("--") + 1 :] == [sys.executable, "-I", "-m", "filevet.core.sandbox"]
    assert (tmp_path / "policy.kafel").read_text() == _kafel()


@pytest.mark.parametrize(
    ("broken", "status", "error"),
    [
        (fakes.Sleeps(), "timeout", "no result after 3 s"),
        (fakes.Raises(), "error", "raised ValueError"),
        (fakes.Exits(), "error", "worker exited with code 3"),
        (fakes.ReturnsGarbage(), "error", "raised ValidationError"),
    ],
    ids=["timeout", "exception", "exit", "garbage"],
)
def test_jailed_worker_protocol(broken: fakes.Fake, status: str, error: str) -> None:
    report = scan(
        b"secret payload", Limits(timeout_s=3), analyzers=[broken, fakes.Fake()], sandbox=Direct()
    )
    broken_run, ok_run = report.analyzer_runs
    assert (broken_run.status, broken_run.error) == (status, error)
    assert ok_run.status == "ok"
    assert "secret payload" not in report.model_dump_json()


def test_jailed_worker_rebuilds_analyzer_state() -> None:
    report = scan(b"root", analyzers=[fakes.Children(count=2, size=3)], sandbox=Direct())
    assert [a.size for a in report.artifacts] == [4, 3, 3]


def test_jailed_worker_rejects_oversized_results() -> None:
    limits = Limits(max_total_expanded_bytes=0)
    report = scan(b"x", limits, analyzers=[fakes.Children(count=1, size=2 << 20)], sandbox=Direct())
    assert report.analyzer_runs[0].error == "result too large"


def test_analyzer_state_must_be_json() -> None:
    analyzer = fakes.Fake()
    analyzer.handle = object()  # type: ignore[attr-defined]
    [run] = scan(b"x", analyzers=[analyzer], sandbox=Direct()).analyzer_runs
    assert run.error == "analyzer state is not JSON"


JAILS = [
    pytest.param(
        backend,
        id=backend.name,
        marks=[
            getattr(pytest.mark, f"requires_{backend.name}"),
            pytest.mark.skipif(not shutil.which(backend.binary), reason=f"no {backend.binary}"),
        ],
    )
    for backend in (NsjailSandbox, GvisorSandbox)
]


@pytest.fixture
def listener() -> Iterator[int]:
    with socket.create_server(("127.0.0.1", 0)) as server:
        yield server.getsockname()[1]


@pytest.mark.parametrize("backend", JAILS)
@pytest.mark.parametrize(
    "attempt", ["socket", "read_host", "write_outside", "fork_bomb", "memory", "ok"]
)
def test_escape_attempts_are_blocked(
    backend: type[Sandbox], attempt: str, listener: int, tmp_path: Path
) -> None:
    target = tmp_path / "escaped"
    analyzer: Analyzer = {
        "socket": fakes.OpensSocket(listener),
        "read_host": fakes.ReadsHostFile(),
        "write_outside": fakes.WritesOutside(str(target)),
        "fork_bomb": fakes.ForkBomb(4 * MAX_PROCS),
        "memory": fakes.AllocatesTooMuch(),
        "ok": fakes.Fake(),
    }[attempt]
    limits = Limits(timeout_s=20, memory_bytes=512 << 20)
    report = scan(b"%PDF-1.4\n", limits, analyzers=[analyzer], sandbox=backend())

    rule_ids = {f.rule_id for f in report.findings}
    assert "test.escaped" not in rule_ids
    assert not target.exists()
    if attempt == "ok":
        assert rule_ids == {"test.ran"}, [run.error for run in report.analyzer_runs]
    elif attempt == "memory":
        assert rule_ids == {"pipeline.analyzer_error"}
    else:
        assert rule_ids & {"test.blocked", "pipeline.analyzer_error"}
