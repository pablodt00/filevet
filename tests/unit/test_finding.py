import pytest
from pydantic import ValidationError

from filevet.core.finding import MAX_EVIDENCE, Finding, Severity


def _finding(**kwargs: object) -> Finding:
    return Finding(rule_id="basic.test", title="t", severity="low", **kwargs)


def test_evidence_is_escaped_and_truncated() -> None:
    assert _finding(evidence="a\x1b[31m\nb").evidence == "a\\x1b[31m\\nb"
    assert _finding(evidence=b"\x00\xff").evidence == "\\x00\\xff"
    assert len(_finding(evidence="é" * 1000).evidence) == MAX_EVIDENCE


@pytest.mark.parametrize("rule_id", ["type_mismatch", "Basic.x", "basic.", "basic.a-b"])
def test_rule_id_must_be_namespaced(rule_id: str) -> None:
    with pytest.raises(ValidationError):
        Finding(rule_id=rule_id, title="t", severity="low")


def test_confidence_is_bounded() -> None:
    with pytest.raises(ValidationError):
        _finding(confidence=1.5)


def test_severity_rank_follows_order() -> None:
    assert [s.rank for s in Severity] == [0, 1, 2, 3, 4]
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
