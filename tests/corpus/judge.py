from typing import Any

from filevet.core.finding import Severity


def judge(report: dict[str, Any], expected: dict[str, Any]) -> bool:
    if report["verdict"] != expected["verdict"]:
        return False
    wanted = expected.get("must_find", [])
    floor = Severity(expected.get("min_severity", "info")).rank
    return not wanted or any(
        f["rule_id"] in wanted and Severity(f["severity"]).rank >= floor for f in report["findings"]
    )
