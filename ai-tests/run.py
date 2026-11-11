import argparse
import csv
import json
import multiprocessing
import resource
import shutil
import sys
from collections import Counter
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

import yaml

from filevet.core.report import scan

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.corpus import generators  # noqa: E402
from tests.corpus.judge import judge  # noqa: E402

SCENARIOS = ROOT / "ai-tests" / "scenarios"
REPORTS = ROOT / "ai-tests" / "reports"
METRICS = ROOT / "ai-tests" / "metrics.csv"
SAMPLES = ROOT / "tmp-samples"
TIMEOUT_S = 30
MEMORY_BYTES = 1 << 30
SCANNED = ("ok", "miss", "false_positive")


def _scan_child(path: Path, conn: Connection) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT_S, TIMEOUT_S))
    try:
        conn.send(("ok", scan(path)))
    except Exception as exc:
        conn.send(("crash", type(exc).__name__))


def scan_limited(path: Path) -> tuple[str, Any]:
    ctx = multiprocessing.get_context("fork")
    receiver, sender = ctx.Pipe(duplex=False)
    child = ctx.Process(target=_scan_child, args=(path, sender))
    child.start()
    sender.close()
    try:
        if not receiver.poll(TIMEOUT_S):
            return "timeout", f"no result after {TIMEOUT_S} s"
        return receiver.recv()
    except EOFError:
        child.join()
        return "crash", f"scanner process exited with code {child.exitcode}"
    finally:
        child.kill()
        child.join()


def load_scenario(scenario_id: str) -> dict[str, Any]:
    path = SCENARIOS / f"{scenario_id}.yaml"
    if path.parent != SCENARIOS or not path.is_file():
        raise SystemExit(f"unknown scenario: {scenario_id}")
    return yaml.safe_load(path.read_text())


def run_variant(variant: dict[str, Any], out: Path, scenario: dict[str, Any]) -> dict[str, Any]:
    name, args = variant["generator"], variant.get("args", {})
    result: dict[str, Any] = {"generator": name, "args": args}
    if name not in generators.__all__:
        return {**result, "status": "generator_error", "detail": "unknown generator"}
    try:
        path = getattr(generators, name)(out, **args)
    except Exception as exc:
        return {**result, "status": "generator_error", "detail": f"{type(exc).__name__}: {exc}"}
    result |= {"file": path.name, "size": path.stat().st_size}
    if result["size"] > scenario["budget"]["max_file_kb"] * 1024:
        return {**result, "status": "over_budget"}
    status, payload = scan_limited(path)
    if status != "ok":
        return {**result, "status": status, "detail": payload}
    expected = scenario["expected"]
    if judge(payload, expected):
        status = "ok"
    else:
        status = "false_positive" if expected["verdict"] == "pass" else "miss"
    rule_ids = sorted({f["rule_id"] for f in payload["findings"]})
    return {**result, "status": status, "verdict": payload["verdict"], "rule_ids": rule_ids}


def summarize(
    scenario_id: str, scenario: dict[str, Any], run_id: str, results: list[dict[str, Any]]
) -> dict[str, Any]:
    counts = Counter(r["status"] for r in results)
    scanned = sum(counts[s] for s in SCANNED)
    benign = scenario["expected"]["verdict"] == "pass"
    rate = (counts["false_positive" if benign else "ok"] / scanned) if scanned else None
    return {
        "run_id": run_id,
        "scenario": scenario_id,
        "date": datetime.now(UTC).date().isoformat(),
        "variants": len(results),
        "counts": dict(counts),
        "detection_rate": None if benign else rate,
        "false_positive_rate": rate if benign else None,
        "crashes": counts["crash"] + counts["timeout"],
        "results": results,
    }


def _pct(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate:.0%}"


def markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# AI test run {report['run_id']}",
        "",
        f"- Scenario: `{report['scenario']}`, {report['variants']} variants",
        f"- Detection rate: {_pct(report['detection_rate'])}",
        f"- False-positive rate: {_pct(report['false_positive_rate'])}",
        f"- Crashes and timeouts (critical, possible DoS in filevet): {report['crashes']}",
        "",
        "| # | Status | Generator call | Verdict | Rule IDs | Detail |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for i, r in enumerate(report["results"], 1):
        call = f"{r['generator']}({json.dumps(r['args'], ensure_ascii=False)})"
        cells = [
            str(i),
            r["status"],
            f"`{call}`",
            r.get("verdict", ""),
            ", ".join(r.get("rule_ids", [])),
            str(r.get("detail", "")),
        ]
        lines.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return "\n".join(lines) + "\n"


def record_metrics(report: dict[str, Any]) -> None:
    new = not METRICS.exists()
    with METRICS.open("a", newline="") as f:
        writer = csv.writer(f)
        if new:
            writer.writerow(
                ["date", "scenario", "variants", "detection_rate", "false_positive_rate", "crashes"]
            )
        writer.writerow(
            [
                report["date"],
                report["scenario"],
                report["variants"],
                "" if report["detection_rate"] is None else f"{report['detection_rate']:.3f}",
                ""
                if report["false_positive_rate"] is None
                else f"{report['false_positive_rate']:.3f}",
                report["crashes"],
            ]
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ai-tests/run.py")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--plan", required=True, type=Path, help="JSON list of generator calls")
    args = parser.parse_args(argv)
    scenario = load_scenario(args.scenario)
    variants = json.loads(args.plan.read_text())
    if len(variants) > scenario["budget"]["variants"]:
        parser.error(f"{len(variants)} variants, budget is {scenario['budget']['variants']}")

    run_id = f"{args.scenario}-{datetime.now(UTC):%Y%m%dT%H%M%SZ}"
    out = SAMPLES / run_id
    out.mkdir(parents=True)
    try:
        results = [run_variant(v, out, scenario) for v in variants]
    finally:
        shutil.rmtree(out)

    report = summarize(args.scenario, scenario, run_id, results)
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / f"{run_id}.json").write_text(json.dumps(report, indent=2) + "\n")
    (REPORTS / f"{run_id}.md").write_text(markdown(report))
    record_metrics(report)
    print(REPORTS / f"{run_id}.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
