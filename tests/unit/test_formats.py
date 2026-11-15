import json
from pathlib import Path

from defusedxml.ElementTree import fromstring

from filevet.core.artifact import Artifact
from filevet.core.finding import Finding
from filevet.core.report import Report
from filevet.interfaces import formats
from filevet.policies import Policy

TOP = Artifact(
    name="a", size=0, sha256="", md5="", declared_type=None, detected_type="zip", path=Path()
)


def _report(*findings: Finding) -> Report:
    child = Artifact.model_validate(
        {**TOP.model_dump(), "name": "inner/x.csv", "depth": 1, "path": Path()}
    )
    stamped = [f.model_copy(update={"artifact_id": child.id}) for f in findings]
    return Policy.load("default").apply([TOP, child], stamped, [])


HOSTILE = Finding(
    rule_id="parser.csv_formula_injection",
    title="Formula <b>|`x`",
    description="d\x01",
    severity="high",
    evidence="=cmd|' /C calc'!A0",
)


def test_sarif() -> None:
    log = json.loads(formats.sarif([("dir/a.zip", _report(HOSTILE)), ("b.pdf", _report())]))
    assert log["version"] == "2.1.0"
    [result] = log["runs"][0]["results"]
    assert (result["ruleId"], result["level"]) == ("parser.csv_formula_injection", "error")
    location = result["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "dir/a.zip"
    assert location["logicalLocations"] == [{"name": "inner/x.csv", "kind": "member"}]
    rule = log["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"].endswith("docs/rules/parser.csv_formula_injection.md")


def test_junit_is_valid_xml_and_escaped() -> None:
    xml = formats.junit([("a<&>.zip", _report(HOSTILE)), ("b.pdf", _report())])
    root = fromstring(xml.split("\n", 1)[1])
    assert (root.get("tests"), root.get("failures")) == ("2", "1")
    cases = list(root)
    assert cases[0].get("name") == "a<&>.zip"
    assert cases[0][0].get("message") == "block"
    assert len(cases[1]) == 0


def test_markdown_escapes_markup() -> None:
    text = formats.markdown([("a`b.zip", _report(HOSTILE))])
    assert "<b>" not in text
    assert "&lt;b&gt;" in text
    assert "`a'b.zip`" in text
    row = next(line for line in text.splitlines() if line.startswith("| high"))
    assert row.count(" | ") == 3


def test_fails() -> None:
    report = _report(HOSTILE)
    assert formats.fails(report, "high") and formats.fails(report, "block")
    assert not formats.fails(report, "critical")
    assert not formats.fails(_report(), "pass_with_findings")
