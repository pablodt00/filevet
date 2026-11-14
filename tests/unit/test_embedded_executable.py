from pathlib import Path

import pytest

from filevet.analyzers.malware.embedded_executable import EmbeddedExecutable
from tests.corpus import generators
from tests.helpers import rules, run


@pytest.mark.parametrize(
    ("name", "parts"),
    [
        ("invoice.exe", ["pe_stub"]),
        ("report", ["elf_stub"]),
        ("statement.pdf.lnk", ["lnk_stub"]),
        ("run.ps1", ["csv"]),
        ("install", ["script"]),
    ],
)
def test_children_that_run_code(name: str, parts: list[str], sample_dir: Path) -> None:
    path = generators.disguised(sample_dir, name=name, parts=parts)
    assert rules(run(EmbeddedExecutable(), path, depth=1)) == {
        "malware.embedded_executable": "critical"
    }
    assert rules(run(EmbeddedExecutable(), path)) == {}


@pytest.mark.parametrize(("name", "parts"), [("a.pdf", ["pdf"]), ("a.csv", ["csv"]), ("x", [])])
def test_documents_are_quiet(name: str, parts: list[str], sample_dir: Path) -> None:
    path = generators.disguised(sample_dir, name=name, parts=parts)
    assert rules(run(EmbeddedExecutable(), path, depth=1)) == {}
