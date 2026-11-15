import json
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from filevet.core.artifact import Artifact
from filevet.core.finding import Finding
from filevet.policies import BUILT_IN, Policy, Suppression, load_suppressions

SCHEMA = Path(__file__).resolve().parents[2] / "docs" / "schema" / "policy.schema.json"
SHA = "a" * 64
ARTIFACT = Artifact(
    name="f", size=0, sha256=SHA, md5="", declared_type=None, detected_type="pdf", path=Path()
)
TODAY = date(2026, 11, 15)


def _finding(rule_id: str, severity: str = "medium", evidence: str = "") -> Finding:
    return Finding(
        rule_id=rule_id, title="t", severity=severity, evidence=evidence, artifact_id=ARTIFACT.id
    )


def _policy(**fields: object) -> Policy:
    return Policy.model_validate({"policy_version": 1, "name": "test", **fields})


def _verdict(policy: Policy, *findings: Finding) -> str:
    return policy.apply([ARTIFACT], list(findings), [], today=TODAY).verdict


EXAMPLE = _policy(
    rules=[
        {"match": {"severity": "critical"}, "action": "block"},
        {"match": {"rule_id": "malware.*", "severity": ["high"]}, "action": "block"},
        {"match": {"rule_id": "integrity.*"}, "action": "review", "when": {"min_count": 2}},
        {"match": {"rule_id": "format.iso20022_schema"}, "action": "allow"},
    ],
    overrides=[
        {
            "match": {"rule_id": "malware.pdf_active_content", "evidence_contains": "/URI"},
            "severity": "low",
        }
    ],
)


@pytest.mark.parametrize(
    ("findings", "verdict"),
    [
        ((), "pass"),
        ((_finding("basic.x", "critical"),), "block"),
        ((_finding("malware.x", "high"),), "block"),
        ((_finding("parser.x", "high"),), "pass_with_findings"),
        ((_finding("integrity.a"),), "pass_with_findings"),
        ((_finding("integrity.a"), _finding("integrity.b")), "review"),
        ((_finding("format.iso20022_schema"),), "pass"),
        ((_finding("malware.pdf_active_content", "high", "/URI x"),), "pass_with_findings"),
        ((_finding("malware.pdf_active_content", "high", "/JS x"),), "block"),
    ],
)
def test_issue_example_policy(findings: tuple[Finding, ...], verdict: str) -> None:
    assert _verdict(EXAMPLE, *findings) == verdict


def test_decision_names_the_rule() -> None:
    report = EXAMPLE.apply(
        [ARTIFACT], [_finding("integrity.a"), _finding("integrity.b"), _finding("basic.c")], []
    )
    assert report.decision.rule == 2
    assert report.decision.rule_ids == ["integrity.a", "integrity.b"]
    assert "rule 2 of policy test sets review" in report.decision.reason


def test_override_changes_reported_severity() -> None:
    report = EXAMPLE.apply([ARTIFACT], [_finding("malware.pdf_active_content", "high", "/URI")], [])
    assert report.findings[0].severity == "low"


def test_suppression_moves_matching_finding_aside() -> None:
    active = Suppression(rule_id="basic.x", sha256=SHA, reason="known", expires=TODAY)
    other_file = active.model_copy(update={"sha256": "b" * 64})
    report = EXAMPLE.apply(
        [ARTIFACT], [_finding("basic.x", "critical")], [], [active, other_file], today=TODAY
    )
    assert (report.verdict, len(report.suppressed), report.warnings) == ("pass", 1, [])


def test_expired_suppression_warns_and_does_not_apply() -> None:
    expired = Suppression(rule_id="basic.x", sha256=SHA, reason="old", expires=date(2026, 1, 1))
    report = EXAMPLE.apply([ARTIFACT], [_finding("basic.x", "critical")], [], [expired], TODAY)
    assert report.verdict == "block"
    assert report.warnings == [f"suppression of basic.x for {SHA[:12]} expired on 2026-01-01"]


@pytest.mark.parametrize(
    "entry",
    [
        {"rule_id": "basic.x", "sha256": SHA, "expires": "2027-01-01"},
        {"rule_id": "basic.x", "sha256": SHA, "reason": "", "expires": "2027-01-01"},
        {"rule_id": "basic.x", "sha256": SHA, "reason": "r"},
        {"rule_id": "basic.x", "sha256": "short", "reason": "r", "expires": "2027-01-01"},
    ],
)
def test_suppression_needs_reason_expiry_and_hash(entry: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        Suppression.model_validate(entry)


def test_load_suppressions(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.yaml"
    path.write_text(
        f"suppressions:\n  - rule_id: basic.x\n    sha256: {SHA}\n    reason: r\n"
        "    expires: 2027-01-01\n"
    )
    assert load_suppressions(path)[0].expires == date(2027, 1, 1)


@pytest.mark.parametrize(
    "fields",
    [
        {"policy_version": 2, "name": "x"},
        {"policy_version": 1, "name": "x", "rules": [{"match": {}, "action": "explode"}]},
        {"policy_version": 1, "name": "x", "rules": [{"match": {"rule": "a"}, "action": "block"}]},
        {"policy_version": 1, "name": "x", "extra": True},
    ],
)
def test_invalid_policies_are_rejected(fields: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate(fields)


@pytest.mark.parametrize("name", BUILT_IN)
def test_built_in_policies_load(name: str) -> None:
    assert Policy.load(name).name == name


def test_strict_is_stricter_than_default() -> None:
    link = _finding("malware.pdf_active_content", "low", "/URI")
    assert _verdict(Policy.load("default"), link) == "pass_with_findings"
    assert _verdict(Policy.load("strict"), link) == "block"


def test_ai_ingestion_blocks_hidden_text() -> None:
    hidden = _finding("ai.hidden_text")
    assert _verdict(Policy.load("default"), hidden) == "review"
    assert _verdict(Policy.load("ai-ingestion"), hidden) == "block"


def test_oversized_policy_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "big.yaml"
    path.write_text("x" * (2 << 20))
    with pytest.raises(ValueError, match="larger than"):
        Policy.load(path)


def test_committed_policy_schema_is_current() -> None:
    assert json.loads(SCHEMA.read_text()) == Policy.model_json_schema(mode="serialization")
