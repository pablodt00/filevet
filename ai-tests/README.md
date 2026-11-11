# AI tests

The pytest suite only checks the files someone thought to write. AI tests add a second layer on top. Claude plays an adversarial tester: it reads a threat scenario, builds synthetic variants of the threat with the repo's own generators, scans them with filevet and reports what got through (misses) and what got flagged by mistake (false positives).

Whatever it finds becomes a deterministic pytest case, so it keeps being checked long after the AI run is over.

AI runs aren't deterministic, so they're never a required check and never block a merge.

## Safety rules

- Synthetic structures only. No working exploits, no real malware, no real data, no network.
- Samples are created only by calling the generators in `tests/corpus/generators/`, which refuse to write anywhere except a run directory directly under `tmp-samples/`. Nobody, human or AI, writes sample bytes by hand.
- Payloads stay inert: `=1+1`, `app.alert()`, `example.invalid` URLs, paths that don't exist. Zip bombs are capped at 64 MiB expanded.
- Hostile files live only in `tmp-samples/` (git-ignored), and the runner deletes them at the end of each run.
- The runner scans each sample in a separate process with a 30 s CPU and wall-clock limit and a 1 GB memory limit, and treats every generated file as untrusted.
- Samples are never opened, run or rendered outside the scanner.

## Layout

| Path | What it holds |
| --- | --- |
| `ai-tests/scenarios/*.yaml` | One threat per file: what to try, which generators to use, what a correct result looks like and a budget |
| `ai-tests/run.py` | The runner: builds the variants from a plan, scans them, judges the results and writes a report |
| `ai-tests/plans/` | The generator calls Claude chose for a run (git-ignored) |
| `ai-tests/reports/` | JSON and Markdown report for each run (git-ignored, uploaded as an artifact in CI) |
| `ai-tests/metrics.csv` | One row per run: date, scenario, variants, detection rate, false-positive rate, crashes |
| `tests/corpus/generators/` | The generator library |
| `tests/corpus/regressions/cases.yaml` | Every past finding as a generator call, checked by `test_regressions.py` on every test run |

## Scenarios

```yaml
id: csv-formula-injection-variants
threat: CSV/formula injection in a bank export
formats: [csv, xlsx]
generators: [csv_rows, xlsx]
goal: Produce cells that would execute a formula in Excel/LibreOffice while evading naive "starts with =" checks.
techniques_allowed: [leading whitespace, tab/CR prefixes, unicode lookalikes, quoted fields, DDE payloads, HYPERLINK]
expected:
  must_find: [parser.csv_formula_injection]
  min_severity: high
  verdict: block
budget: { variants: 15, max_file_kb: 512 }
```

A variant passes when the report has the expected verdict and, if `must_find` isn't empty, at least one finding with one of those rule IDs at `min_severity` or higher. A scenario whose expected verdict is `pass` is benign. Its failures count as false positives, and its IDs start with `benign-`.

## Running

In Claude Code:

- `/ai-test <scenario-id>` or `/ai-test all` runs the full loop: plan, generate, scan, minimize, add regression cases, file issues.
- `/ai-test-benign [scenario-id|all]` does the same with realistic legitimate files, to hunt for false positives.

The runner on its own, with a plan you wrote:

```sh
uv run python -I ai-tests/run.py --scenario csv-formula-injection-variants --plan ai-tests/plans/csv-formula-injection-variants.json
```

A plan is a JSON list of generator calls:

```json
[{"generator": "csv_rows", "args": {"rows": [["description"], ["\t=1+1"]]}}]
```

Each variant ends up with one of these statuses: `ok`, `miss`, `false_positive`, `crash`, `timeout`, `over_budget` or `generator_error`. A crash or timeout is a bug in filevet and may let an attacker knock the scanner over, so treat it as critical.

In CI, `.github/workflows/ai-tests.yml` runs `/ai-test all` when you start it by hand from the Actions tab. It needs the Claude GitHub app and the `CLAUDE_CODE_OAUTH_TOKEN` secret. It uploads the reports as an artifact and opens a PR with any new regression cases and the metrics row. It never runs on pull requests.

## From finding to regression test

Each miss or false positive is minimized to the smallest generator call that still reproduces it, then added to `tests/corpus/regressions/cases.yaml`:

```yaml
- id: csv-tab-prefixed-formula
  scenario: csv-formula-injection-variants
  generator: csv_rows
  args:
    rows: [["description"], ["\t=1+1"]]
  xfail: parser.csv_formula_injection does not exist yet
```

The case is judged against its scenario's `expected` block. While `xfail` is set, the case is expected to fail. It's strict, so once a fix makes it pass the suite goes red until someone removes the `xfail` line. The fix itself comes in a separate, human-reviewed change, never in the same step that adds the case.
