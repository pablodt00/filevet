# 7. Define the contracts as pydantic models, and render tables with rich

Date: 2026-11-11

## Status

Accepted

## Context

The report is a public contract. CI jobs and other services parse it, so it needs a published JSON schema that matches the code exactly. The same models carry analyzer results across the process boundary (see ADR 6), where the data has to be validated before the parent trusts it. People reading a report in a terminal also need something easier on the eye than raw JSON.

## Decision

`Artifact`, `Finding`, `AnalyzerResult` and `Report` are frozen pydantic v2 models. pydantic gives us validation, JSON round-trips and the JSON schema from one definition. `filevet schema` prints the schema, and a copy is committed in `docs/schema/`.

`rich` renders `--format table`. Every cell goes in as plain `Text`, so markup in file names or evidence is never interpreted.

The CLI stays on `argparse` from the standard library. We considered `typer`, but four subcommands with a few options don't need a CLI framework.

The direct runtime dependencies are pydantic and rich, and pydantic brings in pydantic-core. All three are MIT licensed. Their own dependencies (annotated-types, typing-inspection, markdown-it-py, mdurl, pygments, typing-extensions) are MIT, BSD-2-Clause or PSF-2.0, all on the allow list.

## Consequences

The schema can't drift from the code. pydantic-core is a compiled Rust extension, so there are wheels per platform and no pure-Python fallback. Changing a model field is a contract change that shows up as a diff in `docs/schema/`.
