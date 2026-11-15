import html
import json
import re
from collections.abc import Sequence

from filevet import __version__
from filevet.core.finding import Finding, Severity
from filevet.core.report import Report

Scanned = Sequence[tuple[str, Report]]
RULES_URL = "https://github.com/pablodt00/filevet/blob/master/docs/rules/{}.md"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning"}
XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|~])")


def sarif(scanned: Scanned) -> str:
    results, rules = [], {}
    for path, report in scanned:
        names = {a.id: a.name for a in report.artifacts if a.depth}
        for f in report.findings:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.rule_id},
                "helpUri": RULES_URL.format(f.rule_id),
            }
            location: dict[str, object] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": 1},
                }
            }
            inner = names.get(f.artifact_id) if f.artifact_id else None
            if inner:
                location["logicalLocations"] = [{"name": inner, "kind": "member"}]
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": SARIF_LEVEL.get(f.severity, "note"),
                    "message": {"text": _message(f)},
                    "locations": [location],
                    "properties": {
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "verdict": report.verdict,
                    },
                }
            )
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "filevet",
                        "version": __version__,
                        "informationUri": "https://github.com/pablodt00/filevet",
                        "rules": sorted(rules.values(), key=lambda r: str(r["id"])),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(log, indent=2)


def junit(scanned: Scanned) -> str:
    failures = sum(r.verdict in {"review", "block"} for _, r in scanned)
    cases = []
    for path, report in scanned:
        body = ""
        if report.verdict in {"review", "block"}:
            text = "\n".join(f"{f.severity} {f.rule_id}: {_message(f)}" for f in report.findings)
            body = f'<failure message="{_xml(report.verdict)}">{_xml(text)}</failure>'
        cases.append(f'<testcase classname="filevet" name="{_xml(path)}">{body}</testcase>')
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="filevet" tests="{len(scanned)}" failures="{failures}">'
        + "".join(cases)
        + "</testsuite>"
    )


def markdown(scanned: Scanned) -> str:
    out = []
    for path, report in scanned:
        out.append(f"### filevet: `{_md_code(path)}` is **{report.verdict}**\n")
        out.append(f"{_md(report.decision.reason)}\n")
        if report.findings:
            out.append("| Severity | Rule | Title | Evidence |\n| --- | --- | --- | --- |")
            for f in sorted(report.findings, key=lambda f: -f.severity.rank):
                cells = (f.severity, f.rule_id, _md(f.title), f"`{_md_code(f.evidence)}`")
                out.append("| " + " | ".join(cells) + " |")
            out.append("")
    return "\n".join(out)


def fails(report: Report, threshold: str) -> bool:
    if threshold in {s.value for s in Severity}:
        floor = Severity(threshold).rank
        return any(f.severity.rank >= floor for f in report.findings)
    order = ["pass", "pass_with_findings", "review", "block"]
    return order.index(report.verdict) >= order.index(threshold)


def _message(f: Finding) -> str:
    return f"{f.title}. {f.description}".strip() + (
        f" Evidence: {f.evidence}" if f.evidence else ""
    )


def _xml(text: str) -> str:
    return html.escape(XML_INVALID.sub("", text), quote=True)


def _md(text: str) -> str:
    return MARKDOWN_SPECIAL.sub(r"\\\1", html.escape(" ".join(text.split()), quote=False))


def _md_code(text: str) -> str:
    return " ".join(text.split()).replace("`", "'").replace("|", "\\|")
