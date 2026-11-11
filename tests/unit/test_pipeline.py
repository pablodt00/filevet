import hashlib
import json
import logging
import stat
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from filevet.analyzers.basic.type_mismatch import TypeMismatch
from filevet.core.analyzer import AnalysisContext, AnalyzerResult, load_analyzers
from filevet.core.artifact import Artifact
from filevet.core.errors import ScanError
from filevet.core.limits import Limits
from filevet.core.pipeline import scan
from filevet.core.report import Report
from tests import fakes

PLUGIN = Path(__file__).resolve().parents[1] / "plugin"


def test_ingest_hashes_and_cleans_up(benign_pdf: Path) -> None:
    seen: list[tuple[Path, int, int]] = []

    class Records(fakes.Fake):
        def supports(self, artifact: Artifact) -> bool:
            path = artifact.path
            seen.append((path, stat.S_IMODE(path.stat().st_mode), path.parent.stat().st_mode))
            return False

    report = scan(benign_pdf, analyzers=[Records()])
    [artifact] = report.artifacts
    data = benign_pdf.read_bytes()
    assert artifact.sha256 == hashlib.sha256(data).hexdigest()
    assert artifact.md5 == hashlib.md5(data, usedforsecurity=False).hexdigest()
    assert (artifact.declared_type, artifact.detected_type) == ("pdf", "pdf")
    [(path, mode, dir_mode)] = seen
    assert mode == 0o400
    assert dir_mode & 0o077 == 0
    assert not path.parent.exists()


def test_cleans_up_when_the_scan_fails(benign_pdf: Path) -> None:
    seen: list[Path] = []

    class Boom(fakes.Fake):
        def supports(self, artifact: Artifact) -> bool:
            seen.append(artifact.path)
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        scan(benign_pdf, analyzers=[Boom()])
    assert not seen[0].exists()


@pytest.mark.parametrize("source", [b"x" * 11, "path"])
def test_rejects_input_over_the_size_limit(source: bytes | str, tmp_path: Path) -> None:
    if source == "path":
        source = tmp_path / "big.csv"
        source.write_bytes(b"x" * 11)
    with pytest.raises(ScanError):
        scan(source, Limits(max_input_bytes=10), analyzers=[])


def test_findings_are_stamped_with_artifact_and_analyzer() -> None:
    report = scan(b"hello", analyzers=[fakes.Fake()])
    [finding] = report.findings
    assert finding.artifact_id == report.artifacts[0].id
    assert finding.analyzer == "test.fake/0.0.0"
    assert report.analyzer_runs[0].status == "ok"


@pytest.mark.parametrize(
    ("broken", "status", "error"),
    [
        (fakes.Sleeps(), "timeout", "no result after 0.5 s"),
        (fakes.AllocatesTooMuch(), "error", "raised MemoryError"),
        (fakes.Raises(), "error", "raised ValueError"),
        (fakes.Exits(), "error", "worker exited with code 3"),
        (fakes.ReturnsGarbage(), "error", "raised ValidationError"),
        (fakes.SupportsRaises(), "error", "supports() raised RuntimeError"),
    ],
    ids=["timeout", "memory", "exception", "exit", "garbage", "supports"],
)
def test_broken_analyzer_becomes_error_finding(
    broken: fakes.Fake, status: str, error: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="filevet")
    report = scan(b"secret payload", Limits(timeout_s=0.5), analyzers=[broken, fakes.Fake("ok")])

    broken_run, ok_run = report.analyzer_runs
    assert (broken_run.status, broken_run.error) == (status, error)
    assert ok_run.status == "ok"
    assert {f.rule_id: f.severity for f in report.findings} == {
        "pipeline.analyzer_error": "high",
        "test.ran": "info",
    }
    assert "secret payload" not in report.model_dump_json()
    assert "secret payload" not in caplog.text
    assert [json.loads(r.message)["analyzer"] for r in caplog.records] == [broken.name, "ok"]


def test_invalid_result_from_worker_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AnalyzerResult, "model_dump_json", lambda self: '{"findings": 1}')
    [run] = scan(b"x", analyzers=[fakes.Fake()]).analyzer_runs
    assert run.error == "returned an invalid result"


def test_oversized_result_is_rejected() -> None:
    limits = Limits(max_total_expanded_bytes=0)
    [run] = scan(b"x", limits, analyzers=[fakes.Children(count=1, size=2 << 20)]).analyzer_runs
    assert run.error == "result too large"


@pytest.mark.parametrize(
    ("limits", "count", "scanned", "limit"),
    [
        (Limits(max_children=3), 5, 4, "max_children"),
        (Limits(max_total_expanded_bytes=25), 5, 3, "max_total_expanded_bytes"),
        (Limits(max_depth=0), 2, 1, "max_depth"),
        (Limits(), 5, 6, None),
    ],
)
def test_recursion_limits(limits: Limits, count: int, scanned: int, limit: str | None) -> None:
    report = scan(b"root", limits, analyzers=[fakes.Children(count=count, size=10)])

    assert len(report.artifacts) == scanned
    assert all(a.parent_id == report.artifacts[0].id for a in report.artifacts[1:])
    assert {a.depth for a in report.artifacts[1:]} <= {1}
    reached = [f.title for f in report.findings if f.rule_id == "pipeline.limit_exceeded"]
    assert reached == ([f"Scan stopped at the {limit} limit"] if limit else [])


@settings(deadline=None, max_examples=25)
@given(st.binary(max_size=2048))
def test_never_raises_on_arbitrary_bytes(data: bytes) -> None:
    report = scan(data, analyzers=[TypeMismatch()])
    assert isinstance(report, Report)
    assert json.loads(report.model_dump_json())["verdict"] in {"pass", "review", "block"}


def test_third_party_analyzer_is_discovered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(PLUGIN))
    names = [a.name for a in load_analyzers()]
    assert names == ["basic.type_mismatch", "example.seen_text"]

    report = scan(b"plain text\n")
    assert "example.seen_text" in {f.rule_id for f in report.findings}


def test_context_carries_limits() -> None:
    limits = Limits(max_depth=2)
    assert AnalysisContext(limits=limits).limits.max_depth == 2
