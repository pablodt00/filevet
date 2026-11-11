import json
from pathlib import Path
from uuid import uuid4

import pytest

from filevet.core.finding import Finding
from filevet.core.report import Report

SCHEMA = Path(__file__).resolve().parents[2] / "docs" / "schema" / "report.schema.json"


def _report(*severities: str) -> Report:
    findings = [Finding(rule_id="basic.test", title="t", severity=s) for s in severities]
    return Report(artifacts=[], findings=findings, analyzer_runs=[])


@pytest.mark.parametrize(
    ("severities", "verdict"),
    [
        ((), "pass"),
        (("info", "low"), "pass"),
        (("low", "medium"), "review"),
        (("medium", "high"), "block"),
        (("critical",), "block"),
    ],
)
def test_verdict_follows_highest_severity(severities: tuple[str, ...], verdict: str) -> None:
    assert _report(*severities).verdict == verdict


def test_summary_counts_every_severity() -> None:
    summary = json.loads(_report("high", "high", "info").model_dump_json())["summary"]
    assert summary == {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 1}


def test_artifact_path_is_not_serialized(benign_pdf: Path) -> None:
    from filevet.core.artifact import Artifact

    artifact = Artifact(
        name="a",
        size=0,
        sha256="",
        md5="",
        declared_type=None,
        detected_type="empty",
        parent_id=uuid4(),
        path=benign_pdf,
    )
    assert "path" not in artifact.model_dump()


def test_committed_schema_is_current() -> None:
    assert json.loads(SCHEMA.read_text()) == Report.model_json_schema(mode="serialization")
