import importlib.util
import json
import os
import time
from pathlib import Path
from types import ModuleType

import pytest

RUNNER = Path(__file__).resolve().parents[2] / "ai-tests" / "run.py"


@pytest.fixture
def runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    spec = importlib.util.spec_from_file_location("ai_tests_run", RUNNER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "REPORTS", tmp_path / "reports")
    monkeypatch.setattr(module, "METRICS", tmp_path / "metrics.csv")
    return module


def _plan(tmp_path: Path, variants: list[dict[str, object]]) -> str:
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(variants))
    return str(path)


def _only_report(tmp_path: Path) -> dict[str, object]:
    [path] = (tmp_path / "reports").glob("*.json")
    return json.loads(path.read_text())


def test_hostile_run_reports_misses(runner: ModuleType, tmp_path: Path) -> None:
    plan = _plan(
        tmp_path,
        [
            {"generator": "csv_rows", "args": {"rows": [["a"], ["\t=1+1"]]}},
            {"generator": "open", "args": {"file": "/etc/passwd"}},
            {"generator": "csv_rows", "args": {"bogus": 1}},
        ],
    )
    assert runner.main(["--scenario", "csv-formula-injection-variants", "--plan", plan]) == 0

    report = _only_report(tmp_path)
    assert report["counts"] == {"miss": 1, "generator_error": 2}
    assert report["detection_rate"] == 0
    assert (tmp_path / "reports" / f"{report['run_id']}.md").is_file()
    assert len((tmp_path / "metrics.csv").read_text().splitlines()) == 2
    assert not (runner.SAMPLES / report["run_id"]).exists()


def test_benign_run_measures_false_positives(runner: ModuleType, tmp_path: Path) -> None:
    plan = _plan(tmp_path, [{"generator": "bank_statement_csv", "args": {"rows": 10}}])
    runner.main(["--scenario", "benign-statements", "--plan", plan])

    report = _only_report(tmp_path)
    assert report["false_positive_rate"] == 0
    assert report["detection_rate"] is None


def test_plan_over_budget_is_rejected(runner: ModuleType, tmp_path: Path) -> None:
    plan = _plan(tmp_path, [{"generator": "csv_rows", "args": {"rows": [["a"]]}}] * 16)
    with pytest.raises(SystemExit):
        runner.main(["--scenario", "csv-formula-injection-variants", "--plan", plan])


@pytest.mark.parametrize("scenario_id", ["missing", "../scenarios/csv-formula-injection-variants"])
def test_unknown_scenario_is_rejected(runner: ModuleType, scenario_id: str) -> None:
    with pytest.raises(SystemExit):
        runner.load_scenario(scenario_id)


def test_scenario_ids_match_file_names(runner: ModuleType) -> None:
    for path in runner.SCENARIOS.glob("*.yaml"):
        assert runner.load_scenario(path.stem)["id"] == path.stem


def test_scanner_crash_is_reported(
    runner: ModuleType, sample_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "scan", lambda path: os._exit(3))
    assert runner.scan_limited(sample_dir) == (
        "crash",
        "scanner process exited with code 3",
    )


def test_scanner_hang_is_reported(
    runner: ModuleType, sample_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "TIMEOUT_S", 1)
    monkeypatch.setattr(runner, "scan", lambda path: time.sleep(10))
    assert runner.scan_limited(sample_dir)[0] == "timeout"


def test_scanner_exception_is_reported(
    runner: ModuleType, sample_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "scan", lambda path: [0] * (1 << 40))
    assert runner.scan_limited(sample_dir) == ("crash", "MemoryError")
