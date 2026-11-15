import hashlib
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
    monkeypatch.setattr(cli, "scan", lambda path, limits, **_: seen.append(limits) or scan(path))
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


def test_context_file_flags_unknown_iban(
    sample_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    known, other = generators.fake_iban(2), generators.fake_iban(5)
    path = generators.pdf(sample_dir, text=f"Muster Lieferant GmbH\nIBAN {other}")
    context = tmp_path / "context.yaml"
    context.write_text(f"parties:\n  Muster Lieferant GmbH:\n    ibans: [{known}]\n")
    assert cli.main(["scan", str(path), "--context", str(context)]) == 1
    out = capsys.readouterr().out
    assert "integrity.iban_not_allowlisted" in out
    assert known not in out and known[-4:] not in out
    assert other not in out
    cli.main(["scan", str(path), "--context", str(context), "--no-mask"])
    assert other in capsys.readouterr().out


@pytest.mark.parametrize(
    "content",
    ["parties: [1, 2]", "parties:\n  Secret GmbH:\n    iban: [x]", "key: [", "x" * (2 << 20)],
)
def test_invalid_context_exits_3(
    content: str, benign_pdf: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    context = tmp_path / "context.yaml"
    context.write_text(content)
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", str(benign_pdf), "--context", str(context)])
    assert exc.value.code == 3
    assert "Secret" not in capsys.readouterr().err


def test_missing_context_exits_3(benign_pdf: Path, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", str(benign_pdf), "--context", str(tmp_path / "none.yaml")])
    assert exc.value.code == 3


def test_oversized_input_exits_3(benign_pdf: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "Limits", lambda **kw: Limits(max_input_bytes=1, **kw))
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", str(benign_pdf)])
    assert exc.value.code == 3


def test_internal_error_exits_4(
    benign_pdf: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*args: object, **kwargs: object) -> None:
        raise RuntimeError("file contents")

    monkeypatch.setattr(cli, "scan", fail)
    assert cli.main(["scan", str(benign_pdf)]) == 4
    assert capsys.readouterr().err == "filevet: internal error: RuntimeError\n"


def test_analyzers_lists_builtin_and_plugins(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.syspath_prepend(str(PLUGIN))
    monkeypatch.delenv("FILEVET_CLAMD", raising=False)
    assert cli.main(["analyzers"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert "basic.type_mismatch 0.1.0: all" in lines
    assert "malware.clamav 0.1.0: none" in lines
    assert "malware.pdf_active_content 0.1.0: pdf" in lines
    assert "example.seen_text 0.1.0: text" in lines


def test_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["schema"]) == 0
    assert "Finding" in json.loads(capsys.readouterr().out)["$defs"]


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["version"]) == 0
    assert capsys.readouterr().out.strip() == f"filevet {__version__}"


def test_several_paths_give_a_list(
    benign_pdf: Path, sample_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exe = generators.disguised(sample_dir, name="invoice.pdf", parts=["pe_stub"])
    assert cli.main(["scan", str(benign_pdf), str(exe)]) == 2
    assert [r["verdict"] for r in json.loads(capsys.readouterr().out)] == ["pass", "block"]


@pytest.mark.parametrize("fmt", ["sarif", "junit", "markdown", "table"])
def test_other_formats(fmt: str, benign_pdf: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scan", str(benign_pdf), "--format", fmt]) == 0
    assert capsys.readouterr().out.strip()


def test_policy_and_fail_on(sample_dir: Path) -> None:
    path = generators.pdf(sample_dir, uri="https://example.invalid/terms")
    assert cli.main(["scan", str(path)]) == 0
    assert cli.main(["scan", str(path), "--policy", "strict"]) == 2
    assert cli.main(["scan", str(path), "--fail-on", "low"]) == 1
    assert cli.main(["scan", str(path), "--fail-on", "review"]) == 0


def test_suppressions(sample_dir: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = generators.disguised(sample_dir, name="statement.csv", parts=["html"])
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    rules = tmp_path / "suppressions.yaml"
    entry = "  - {rule_id: basic.type_mismatch, sha256: %s, reason: known, expires: %s}\n"
    rules.write_text("suppressions:\n" + entry % (sha, "2999-01-01"))
    assert cli.main(["scan", str(path), "--suppressions", str(rules)]) == 0
    rules.write_text("suppressions:\n" + entry % (sha, "2000-01-01"))
    assert cli.main(["scan", str(path), "--suppressions", str(rules)]) == 1
    assert "expired on 2000-01-01" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "{pdf}", "--policy", "missing.yaml"],
        ["scan", "{pdf}", "--policy", "{bad}"],
        ["scan", "{pdf}", "--suppressions", "{bad}"],
        ["scan", "{pdf}", "--llm-verify", "nothing-installed"],
        ["policy", "test", "strict", "--corpus", "{pdf}"],
        ["extract", "missing.pdf"],
        ["worker"],
    ],
)
def test_more_usage_errors(
    argv: list[str], benign_pdf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("FILEVET_REDIS_URL", raising=False)
    bad = tmp_path / "bad.yaml"
    bad.write_text("policy_version: 9\nname: x\n")
    with pytest.raises(SystemExit) as exc:
        cli.main([a.format(pdf=benign_pdf, bad=bad) for a in argv])
    assert exc.value.code == 3


def test_policy_test_shows_changes(sample_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    generators.pdf(sample_dir, name="link.pdf", uri="https://example.invalid/terms")
    generators.pdf(sample_dir, name="plain.pdf")
    assert cli.main(["policy", "test", "strict", "--corpus", str(sample_dir)]) == 0
    out = capsys.readouterr().out
    assert "1 of 2 files change verdict" in out
    assert "link.pdf" in out


def test_extract_visible_only(sample_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = generators.pdf(sample_dir, text="Invoice 2026-0001", hidden_text="secret note")
    assert cli.main(["extract", str(path), "--visible-only"]) == 0
    assert capsys.readouterr().out == "Invoice 2026-0001\n"
    assert cli.main(["extract", str(path)]) == 0
    assert "secret note" in capsys.readouterr().out


def test_policy_schema(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["schema", "policy"]) == 0
    assert "Rule" in json.loads(capsys.readouterr().out)["$defs"]


def test_library_api(benign_pdf: Path) -> None:
    import asyncio

    from filevet import Policy, ascan
    from filevet import scan as top_scan

    assert top_scan(str(benign_pdf), policy=Policy.load("strict")).decision.policy == "strict"
    assert asyncio.run(ascan(benign_pdf)).verdict == "pass"


def test_symlinks_are_refused(benign_pdf: Path, tmp_path: Path) -> None:
    link = tmp_path / "link.pdf"
    link.symlink_to(benign_pdf)
    with pytest.raises(SystemExit) as exc:
        cli.main(["scan", str(link)])
    assert exc.value.code == 3


def test_paths_after_double_dash_are_not_options(
    benign_pdf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "--policy=evil.yaml").write_bytes(benign_pdf.read_bytes())
    assert cli.main(["scan", "--policy", "strict", "--", "--policy=evil.yaml"]) == 0
