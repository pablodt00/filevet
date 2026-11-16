# API stability

From 1.0.0, filevet follows [semantic versioning](https://semver.org/). Everything listed on this page is the public API. A minor or patch release won't break it. Anything not listed here can change in any release.

## Public API

### CLI

- The commands `scan`, `extract`, `sanitize`, `policy test`, `serve`, `worker`, `analyzers`, `schema` and `version`, with the options their `--help` shows.
- Exit codes:

  | Code | Meaning |
  | --- | --- |
  | 0 | `pass` or `pass_with_findings`, or the command succeeded |
  | 1 | `review`, or `--fail-on` was reached |
  | 2 | `block` |
  | 3 | Usage error: bad arguments, unreadable or oversized input, invalid policy or context file, unsupported type for `sanitize` |
  | 4 | Internal error |

- The JSON printed by `filevet sanitize`: `input`, `output` and `removed`, each item with `rule_id`, `title` and `description`.

The `table` output format is for people and can change in any release. Use `json`, `sarif`, `junit` or `markdown` for machines.

### Report

The report JSON is described by [schema/report.schema.json](schema/report.schema.json), which `filevet schema report` prints. 1.0 freezes it at `schema_version: 2`, the version the Phase 3 release introduced. Minor releases can add optional fields and new rule IDs. Removing or renaming a field, changing its type or adding a verdict raises `schema_version` and needs a major release.

Rule IDs are stable. A rule can be retired, and its ID is then never reused for something else. Finding titles, descriptions and evidence are meant for people and can change.

### Policies and suppressions

Policy files with `policy_version: 1`, as described by [schema/policy.schema.json](schema/policy.schema.json) (`filevet schema policy`) and [policies.md](policies.md), and the suppressions file format. The built-in `default`, `strict` and `ai-ingestion` policies can get new rules in minor releases, so pin a policy file of your own if you need verdicts that never move.

### Python

- `filevet.scan`, `filevet.ascan`, `filevet.extract_text`, `filevet.sanitize`, `filevet.Policy`, `filevet.Report` and `filevet.__version__`, with the parameters they have in 1.0.
- `filevet.core.limits.Limits`, `filevet.core.analyzer.Expected` and `filevet.core.errors.ScanError`, which those functions take or raise.
- `filevet.core.sandbox.Sandbox` and the backend names `subprocess`, `nsjail` and `gvisor`.

### Plugins

- The `filevet.analyzers` entry point group and the `Analyzer` protocol: `name`, `version`, `supports(artifact)` and `analyze(artifact, ctx) -> AnalyzerResult`.
- `Artifact`, `AnalysisContext`, `AnalyzerResult`, `ExtractedFile`, `Finding`, `Location` and `Severity`.
- The rule that analyzer state must serialize to JSON (see [security model](security-model.md#limits-and-known-gaps)).
- The `filevet.llm_verifiers` entry point group and the `Verifier` protocol.

### REST API

Everything under `/v1`, as described in [openapi.json](openapi.json), plus `/healthz`, `/readyz` and the metric names on `/metrics`. Breaking changes go under `/v2`, and `/v1` keeps working for at least one more major release.

### Configuration

The `FILEVET_*` environment variables documented in [architecture.md](architecture.md), [api.md](api.md), [security-model.md](security-model.md) and [kubernetes.md](kubernetes.md), and the Helm chart's values.

## Not public

Modules, functions and attributes whose names start with `_`. Any module under `filevet.analyzers`, `filevet.interfaces` or `filevet.core` other than the names listed above. The bundled YARA rules. Log line wording (the field names in JSON log events are public). The test corpus and its generators.

## Deprecation policy

1. A feature is deprecated in a minor release. The CHANGELOG says so, and so do the docs, together with what to use instead.
2. Using it prints a warning: on stderr for the CLI, as a `DeprecationWarning` for Python, and as a `deprecated` log event with the feature's name for the API and workers.
3. It's removed in the next major release at the earliest, and never sooner than six months after the deprecation.

Security fixes are the one exception. If keeping a feature would leave users exposed, it can be changed or removed in a minor release, with a security advisory explaining why.

## Support

Which releases get fixes is described in [SECURITY.md](https://github.com/pablodt00/filevet/blob/master/SECURITY.md#supported-versions).
