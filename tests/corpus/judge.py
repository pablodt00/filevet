from typing import Any

from filevet.core.report import SEVERITIES

RANK = {severity: rank for rank, severity in enumerate(reversed(SEVERITIES))}


def judge(report: dict[str, Any], expected: dict[str, Any]) -> bool:
    if report["verdict"] != expected["verdict"]:
        return False
    wanted = expected.get("must_find", [])
    floor = RANK[expected.get("min_severity", "info")]
    return not wanted or any(
        f["rule_id"] in wanted and RANK[f["severity"]] >= floor for f in report["findings"]
    )
