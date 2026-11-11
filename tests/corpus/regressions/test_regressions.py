from pathlib import Path
from typing import Any

import pytest
import yaml

from filevet.core.report import scan
from tests.corpus import generators
from tests.corpus.judge import judge

SCENARIOS = Path(__file__).resolve().parents[3] / "ai-tests" / "scenarios"
CASES = yaml.safe_load(Path(__file__).with_name("cases.yaml").read_text()) or []


def _param(case: dict[str, Any]) -> Any:
    marks = [pytest.mark.xfail(reason=case["xfail"], strict=True)] if case.get("xfail") else []
    return pytest.param(case, id=case["id"], marks=marks)


@pytest.mark.parametrize("case", [_param(c) for c in CASES])
def test_regression(case: dict[str, Any], sample_dir: Path) -> None:
    scenario = yaml.safe_load((SCENARIOS / f"{case['scenario']}.yaml").read_text())
    path = getattr(generators, case["generator"])(sample_dir, **case["args"])
    assert judge(scan(path), scenario["expected"])
