# CLAUDE.md

filevet is a self-hosted scanner that checks files (invoices, bank statements, KYC documents, payment files) for security risks before anyone opens or ingests them. Several independent analyzers inspect a file and the results go into one JSON report with a verdict.

- Scope and non-goals: [docs/SCOPE.md](docs/SCOPE.md)
- Pipeline, contracts and isolation model: [docs/architecture.md](docs/architecture.md)
- Threat model: [docs/threat-model.md](docs/threat-model.md)
- Decisions: [docs/adr/](docs/adr/)

The project is pre-1.0. Parts of the layout below are still planned. Check what exists before assuming a module is there.

## Commands

| Task | Command |
| --- | --- |
| Set up | `uv sync` |
| All tests | `uv run pytest` |
| One test | `uv run pytest tests/unit/test_report.py::test_name` |
| Tests as CI runs them, with the coverage gate | `make test` |
| Lint and format check | `make lint` (`uv run ruff check .` and `uv run ruff format --check .`) |
| Fix lint and format, run all commit hooks | `uv run pre-commit run --all-files` |
| Typecheck | `make typecheck` (`uv run mypy src/`) |
| Build sdist and wheel | `make build` |
| Docker image and smoke test | `make docker` (needs Docker) |
| Run the CLI on a sample | `mkdir -p tmp-samples && printf '%%PDF-1.4\n%%%%EOF\n' > tmp-samples/benign.pdf && uv run filevet scan tmp-samples/benign.pdf` |
| Tests that need ClamAV | `uv run pytest -m requires_clamav` (skipped unless `clamd` is reachable, see below) |

ClamAV tests run only when `FILEVET_CLAMD` is set to the address of a running `clamd`, for example `unix:/run/clamav/clamd.sock` or `tcp:localhost:3310`. Without it they are skipped, so the suite needs no network and no ClamAV.

## Architecture map

```
src/filevet/
  core/          contracts, pipeline, type detection, limits, report (report.py exists today)
  analyzers/     one subpackage per family: basic/, malware/, parser/, format/
  interfaces/    CLI and later the REST API (the CLI is in src/filevet/cli.py for now)
  policies/      default verdict policy
tests/
  unit/          tests for single modules
  integration/   end-to-end scans
  corpus/        generators/ for the synthetic corpus, one expected.yaml per case
docs/            scope, architecture, threat model, ADRs
```

Three contracts, all in `src/filevet/core/`. Analyzers depend only on these and never on each other.

- `Artifact` (`core/artifact.py`): one immutable file being scanned, the input or an extracted child.
- `Analyzer` (`core/analyzer.py`): a protocol with `name`, `version`, `supports(artifact)` and `analyze(artifact, ctx) -> AnalyzerResult`.
- `Finding` (`core/finding.py`): one observation with a stable namespaced `rule_id`, severity, confidence, location and escaped evidence of at most 256 characters.

Analyzers report what they saw. The policy decides block, review or pass. Never put verdict logic in an analyzer.

Analyzers are discovered through the `filevet.analyzers` entry point group in `pyproject.toml`.

## Adding an analyzer

Use `/new-analyzer <family.name> <file-types>`. By hand:

1. Make sure there's an agreed new-analyzer issue with the rule IDs.
2. Add `src/filevet/analyzers/<family>/<name>.py`. The family matches the rule ID prefix (`malware`, `parser`, `format`, `basic`).
3. Implement `Analyzer`. `supports()` looks only at the detected type. `analyze()` reads the artifact, never writes it, never runs or renders it, and never uses the network.
4. Register it under `[project.entry-points."filevet.analyzers"]` in `pyproject.toml`.
5. Unit tests in `tests/unit/` for every rule, including inputs that must not trigger it, plus a test that malformed input produces a finding and not an exception.
6. At least one benign and one malicious corpus case: a generator in `tests/corpus/generators/` and its `expected.yaml`. Use `/add-corpus-case`.
7. Add a row to the analyzer table in `README.md`.

## Conventions

- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`, `chore:`). release-please builds the version and the CHANGELOG from them. Never edit `CHANGELOG.md` or the version by hand.
- Type hints on every function. mypy runs in strict mode on `filevet.core.*`.
- Ruff with line length 100. Ruff's `S` (bandit) rules are on. Don't silence them without a reason in the same line.
- No new runtime dependency without an ADR in `docs/adr/` (or an update to the relevant one) and a license on the allow list in `.github/workflows/security.yml`. Dev dependencies go in `[dependency-groups] dev`.
- An analyzer must never crash the pipeline. Catch errors inside `analyze()` and return a finding that says the file couldn't be parsed. If an analyzer still fails or times out, the pipeline records `pipeline.analyzer_error`.
- Logs hold hashes, rule IDs and timings only, never file contents.

## Security rules (non-negotiable)

- Never download, fetch or commit real malware, real customer data or real financial data. Fake names and fake IBANs with valid checksums only.
- Hostile test files are created only by the generators in `tests/corpus/generators/`, written under `tmp-samples/` (git-ignored), and never committed. Commit the generator, not its output.
- Never put the EICAR string or executable bytes in a committed file. Generators build them at run time from parts.
- Never open, execute or render a sample file outside the test sandbox. No external viewers, no `subprocess` on samples.
- Parse XML with `defusedxml` only. Never use `eval`, `exec`, `pickle`, `shell=True`, or unbounded reads of untrusted input. Every read of a sample has a size limit.
- Run any Python that touches samples with `python -I`.
- No network calls in code or tests. Releases only go through CI. Never run `uv publish` or `twine`.

## Definition of done

- `make lint`, `make typecheck` and `make test` pass.
- New behavior has tests. Bug fixes have a test that fails without the fix.
- Docs updated: `README.md` analyzer table, `docs/architecture.md` or an ADR when the design changes.
- The commit type matches the change so the CHANGELOG comes out right.
