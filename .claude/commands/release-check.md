---
description: Check the release-please PR for consistent version, changelog and docs
allowed-tools: Read, Grep, Glob, Bash(git diff *), Bash(git log *), Bash(uv build *), Bash(uv run filevet *)
---

Check that the release in the current branch is consistent before the release-please PR is merged. Don't change any files. Report what's wrong.

- The version is the same in `pyproject.toml`, `.release-please-manifest.json` and the top entry of `CHANGELOG.md`.
- Every `feat` and `fix` commit since the last tag (`git log <last-tag>..HEAD`) appears in the changelog, and nothing breaking is hidden in a `chore`.
- `README.md`: the status note, quickstart and example output match what this version does. The analyzer table lists only analyzers that are registered or clearly marked as planned.
- `docs/architecture.md` and `docs/SCOPE.md` don't contradict the code.
- `uv build` succeeds and `uv run filevet --version` prints the new version.
