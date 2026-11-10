# Contributing to filevet

Thanks for helping. This guide covers setup, project layout, how to add an analyzer, and how changes get merged.

Questions go to [Discussions](https://github.com/pablodt00/filevet/discussions). Vulnerabilities go through [SECURITY.md](SECURITY.md), never public issues.

## Development setup

You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run pre-commit install
uv run pytest
```

## Project layout

```
src/filevet/
  core/          contracts (Artifact, Finding, Analyzer), pipeline, type detection, limits, report
  analyzers/     one subpackage per family: basic/, malware/, parser/, format/
  interfaces/    CLI (and later the REST API)
  policies/      default verdict policy
tests/
  unit/          tests for single modules
  integration/   end-to-end scans
  corpus/        generators for the synthetic benign and malicious corpus
docs/            scope, architecture, threat model, ADRs
```

The design behind it is in [docs/architecture.md](docs/architecture.md).

## Writing a new analyzer

1. Open a [new analyzer issue](https://github.com/pablodt00/filevet/issues/new?template=new_analyzer.yml) first, so we can agree on the approach and the rule IDs.
2. Add a module under `src/filevet/analyzers/<family>/`. The family matches the rule ID prefix: `malware`, `parser`, `format` and so on.
3. Implement the `Analyzer` protocol from `filevet.core.analyzer`. The contract is described in [docs/architecture.md](docs/architecture.md#core-contracts).

   - `supports()` must be cheap. It looks at the detected type, not the file contents.
   - `analyze()` returns findings plus any extracted children. It reads the artifact and never writes to it.
   - Each finding needs a stable, namespaced `rule_id`, a severity, a location and evidence. Evidence is truncated and escaped, never the raw payload.
   - Never let an exception escape. If the file can't be parsed, return a finding that says so.
   - Never execute, render or open the file with an external program, and never use the network.

4. Register it as an entry point in `pyproject.toml`:

   ```toml
   [project.entry-points."filevet.analyzers"]
   my_analyzer = "filevet.analyzers.parser.my_analyzer:MyAnalyzer"
   ```

   Third-party packages register analyzers the same way, without forking filevet.

5. Add tests:
   - Unit tests in `tests/unit/` for each rule, including inputs that must not trigger it.
   - At least one malicious and one benign corpus case in `tests/corpus/`, each with an `expected.yaml`.
   - A test that malformed input produces a finding instead of an exception.

6. Add the analyzer to the table in the README.

## Test samples

- No real malware in the repository, ever. The EICAR test string is the only "malware" we use, and it's generated at test time.
- No real customer or personal data. Use fake names and fake IBANs with valid checksums.
- Every hostile fixture is built by code during the test run and written to `tmp-samples/`, which is git-ignored. Commit the generator, not its output.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/). release-please reads them to pick the next version and write the changelog, so the type decides the version bump.

| Type | Use for |
| --- | --- |
| `feat:` | A new feature or analyzer (minor version bump) |
| `fix:` | A bug fix (patch version bump) |
| `docs:` | Documentation only |
| `refactor:` | Code changes that don't change behavior |
| `test:` | Adding or fixing tests |
| `ci:` | CI and workflow changes |
| `chore:` | Maintenance, dependency updates |

Add `!` after the type, or a `BREAKING CHANGE:` footer, for breaking changes.

## Pull requests

- One topic per PR.
- New behavior needs tests, and bug fixes need a test that fails without the fix.
- CI must pass before merging.
- PRs are squash-merged, so the PR title becomes the commit message and must follow Conventional Commits.

## AI-assisted contributions

You're welcome to use AI tools. You're still the author: you need to understand the code you submit, have run its tests, and be able to answer questions about it in review. The rules Claude Code follows in this repository are in [CLAUDE.md](CLAUDE.md).
