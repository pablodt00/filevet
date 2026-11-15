import pytest

from filevet.core.finding import Finding
from filevet.llm import load_verifier, second_opinion
from filevet.policies import Policy


class Verifier:
    def __init__(self, value: float | Exception) -> None:
        self.value = value

    def confidence(self, finding: Finding) -> float:
        if isinstance(self.value, Exception):
            raise self.value
        return self.value


def _findings() -> list[Finding]:
    return [
        Finding(rule_id="ai.hidden_text", title="t", severity="medium", confidence=0.5),
        Finding(rule_id="basic.x", title="t", severity="medium", confidence=0.5),
    ]


@pytest.mark.parametrize(
    ("value", "expected"), [(0.9, [0.9, 0.5]), (0.1, [0.5, 0.5]), (RuntimeError(), [0.5, 0.5])]
)
def test_second_opinion_only_raises(value: float | Exception, expected: list[float]) -> None:
    report = Policy.load("default").apply([], _findings(), [])
    checked = second_opinion(report, Verifier(value))
    assert [f.confidence for f in checked.findings] == expected


def test_missing_verifier() -> None:
    with pytest.raises(LookupError):
        load_verifier("nothing-installed")
