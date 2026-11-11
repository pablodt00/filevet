import json
from pathlib import Path

import pytest

from filevet import __version__
from filevet.analyzers.basic.type_mismatch import TypeMismatch
from filevet.core.limits import Limits
from filevet.core.pipeline import scan
from filevet.interfaces import cli
from tests import fakes
from tests.corpus import generators

PLUGIN = Path(__file__).resolve().parents[1] / "plugin"


def test_benign_pdf_passes(benign_pdf: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scan", str(benign_pdf)]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["artifacts"][0]["name"] == "benign.pdf"
    assert report["findings"] == []
    assert report["verdict"] == "pass"


def test_renamed_executable_is_blocked(
    sample_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = generators.disguised(sample_dir, name="invoice.pdf", parts=["pe_stub"])
    assert cli.main(["scan", str(path)]) == 2

    report = json.loads(capsys.readouterr().out)
    assert {f["rule_id"]: f["severity"] for f in report["findings"]} == {
        "basic.type_mismatch": "critical",
        "basic.executable": "high",
    }
    assert report["verdict"] == "block"


def test_mismatch_needs_review(sample_dir: Path) -> None:
    path = generators.disguised(sample_dir, name="statement.csv", parts=["html"])
    assert cli.main(["scan", str(path)]) == 1


def test_nested_zip_past_max_depth_is_cut_off(sample_dir: Path) -> None:
    path = generators.nested_zip(sample_dir, depth=4)
    report = scan(path, Limits(max_depth=2), analyzers=[TypeMismatch(), fakes.Unzips()])

    assert max(a.depth for a in report.artifacts) == 2
    assert [f.rule_id for f in report.findings] == ["pipeline.limit_exceeded"]
    assert report.verdict == "block"


def test_table_format_escapes_markup(sample_dir: Path, tmp_path: Path) -> None:
    path = generators.disguised(sample_dir, name="[bold]invoice.pdf", parts=["html"])
    out = tmp_path / "report.txt"
    assert cli.main(["scan", str(path), "--format", "table", "--output", str(out)]) == 1
    text = out.read_text()
    assert "basic.type_mismatch" in text
    assert "[bold]" in text
    assert "verdict: review" in text


def test_options_reach_the_limits(
    benign_pdf: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: list[Limits] = []
    monkeypatch.setattr(cli, "scan", lambda path, limits: seen.append(limits) or scan(path))
    cli.main(["scan", str(benign_pdf), "--max-depth", "1", "--timeout", "2.5"])
    assert (seen[0].max_depth, seen[0].timeout_s) == (1, 2.5)


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "missing.pdf"],
        ["scan", "{pdf}", "--max-depth", "-1"],
        ["scan", "{pdf}", "--format", "xml"],
        ["bogus"],
        [],
    ],
)
def test_usage_errors_exit_3(argv: list[str], benign_pdf: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([a.format(pdf=benign_pdf) for a in argv])
    assert exc.value.code == 3


def test_oversized_input_exits_3(benign_pdf: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "Limits", lambda **kw: Limits(max_input_bytes=1, **kw))
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", str(benign_pdf)])
    assert exc.value.code == 3


def test_internal_error_exits_4(
    benign_pdf: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*args: object) -> None:
        raise RuntimeError("file contents")

    monkeypatch.setattr(cli, "scan", fail)
    assert cli.main(["scan", str(benign_pdf)]) == 4
    assert capsys.readouterr().err == "filevet: internal error: RuntimeError\n"


def test_analyzers_lists_builtin_and_plugins(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.syspath_prepend(str(PLUGIN))
    assert cli.main(["analyzers"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "basic.type_mismatch 0.1.0: all",
        "example.seen_text 0.1.0: text",
    ]


def test_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["schema"]) == 0
    assert "Finding" in json.loads(capsys.readouterr().out)["$defs"]


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.strip() == f"filevet {__version__}"
