---
description: Scaffold a new analyzer with its tests, corpus generator stub and README row
argument-hint: <family.name> <file-types>
---

Scaffold the analyzer `$1` for file types `$2`, following "Adding an analyzer" in CLAUDE.md and "Writing a new analyzer" in CONTRIBUTING.md.

1. Check that `src/filevet/core/` has the `Artifact`, `Analyzer` and `Finding` contracts. If they're missing, stop and say so. Don't invent them.
2. Split `$1` into family and name (`parser.csv_formula_injection` gives family `parser`, module `csv_formula_injection`). Copy the structure of an existing analyzer in the same family if there is one.
3. Create `src/filevet/analyzers/<family>/<name>.py` with a class that implements `Analyzer`. `supports()` checks only the detected type against `$2`. `analyze()` returns an empty result for now and turns any parse error into a finding, never an exception.
4. Register it under `[project.entry-points."filevet.analyzers"]` in `pyproject.toml`.
5. Create `tests/unit/test_<name>.py` with a benign case, a malformed-input case that expects a finding, and a skipped placeholder per planned rule.
6. Create a generator stub in `tests/corpus/generators/` that writes under `tmp-samples/`, with an expected-findings file next to it. No binary or hostile content in the repo.
7. Add a row to the analyzer table in `README.md`.
8. Run `make lint typecheck test` and fix what fails.

Finish with the list of files created and the rule IDs still to implement.
