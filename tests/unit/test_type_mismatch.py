from pathlib import Path

import pytest

from filevet.analyzers.basic.type_mismatch import TypeMismatch
from filevet.core.analyzer import AnalysisContext
from filevet.core.artifact import Artifact
from filevet.core.limits import DEFAULT_LIMITS


def _rules(name: str, declared: str | None, detected: str) -> dict[str, str]:
    artifact = Artifact(
        name=name,
        size=1,
        sha256="",
        md5="",
        declared_type=declared,
        detected_type=detected,
        path=Path(),
    )
    result = TypeMismatch().analyze(artifact, AnalysisContext(limits=DEFAULT_LIMITS))
    return {f.rule_id: f.severity for f in result.findings}


@pytest.mark.parametrize(
    ("name", "declared", "detected"),
    [
        ("invoice.pdf", "pdf", "pdf"),
        ("statement.xlsx", "zip", "zip"),
        ("export.csv", "text", "text"),
        ("page.html", "html", "xml"),
        ("empty.pdf", "pdf", "empty"),
        ("README", None, "text"),
        ("blob", None, "unknown"),
    ],
)
def test_matching_types_are_quiet(name: str, declared: str | None, detected: str) -> None:
    assert _rules(name, declared, detected) == {}


def test_executable_disguised_as_document_is_critical() -> None:
    assert _rules("invoice.pdf", "pdf", "pe") == {
        "basic.type_mismatch": "critical",
        "basic.executable": "high",
    }


def test_other_mismatch_is_medium() -> None:
    assert _rules("statement.csv", "text", "html") == {"basic.type_mismatch": "medium"}


@pytest.mark.parametrize(
    ("name", "declared", "detected"),
    [("tool.exe", "pe", "pe"), ("run.ps1", "script", "text"), ("blob", None, "elf")],
)
def test_executables_are_flagged(name: str, declared: str | None, detected: str) -> None:
    assert _rules(name, declared, detected) == {"basic.executable": "high"}
