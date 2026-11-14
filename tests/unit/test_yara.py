from pathlib import Path

import pytest

from filevet.analyzers.malware.yara import Yara
from tests.corpus import generators
from tests.helpers import rules, run


@pytest.mark.parametrize(
    ("generator", "kwargs", "rule"),
    [
        ("disguised", {"name": "a.csv", "parts": ["csv", "pe"]}, "filevet_embedded_pe"),
        ("disguised", {"name": "a.bin", "parts": ["csv", "lnk_stub"]}, "filevet_embedded_lnk"),
        ("pdf", {"javascript": "app.alert(1)"}, "filevet_pdf_auto_javascript"),
        ("pdf", {"launch": "C:\\missing\\x.exe"}, "filevet_pdf_launch"),
        ("csv_rows", {"rows": [["=cmd|' /C calc'!A0"]]}, "filevet_dde_command"),
        (
            "camt053",
            {"doctype": '<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/hostname">]>'},
            "filevet_xml_external_entity",
        ),
    ],
)
def test_bundled_rules(
    generator: str, kwargs: dict[str, object], rule: str, sample_dir: Path
) -> None:
    result = run(Yara(), getattr(generators, generator)(sample_dir, **kwargs))
    assert [f.title for f in result.findings] == [f"YARA rule {rule} matched"]


@pytest.mark.parametrize(
    ("generator", "kwargs"),
    [
        ("pdf", {"text": "Invoice"}),
        ("disguised", {"name": "a.exe", "parts": ["pe"]}),
        ("disguised", {"name": "a.lnk", "parts": ["lnk_stub"]}),
        ("bank_statement_csv", {}),
        ("camt053", {}),
    ],
)
def test_benign_files_are_quiet(
    generator: str, kwargs: dict[str, object], sample_dir: Path
) -> None:
    assert rules(run(Yara(), getattr(generators, generator)(sample_dir, **kwargs))) == {}


def test_user_rules(sample_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "team.yar").write_text(
        'rule team_marker { meta: severity = "critical" reference = "https://example.invalid" '
        'strings: $a = "Muster Lieferant" condition: $a }\n'
        'rule team_default { strings: $a = "Muster" condition: $a }\n'
    )
    monkeypatch.setenv("FILEVET_YARA_RULES", str(tmp_path))
    result = run(Yara(), generators.pdf(sample_dir, text="Muster Lieferant GmbH"))
    assert {f.title: f.severity for f in result.findings} == {
        "YARA rule team_marker matched": "critical",
        "YARA rule team_default matched": "medium",
    }
    assert result.findings[0].references == ["https://example.invalid"]
