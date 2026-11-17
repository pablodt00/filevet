# Writing an analyzer plugin

A separate Python package can add analyzers without forking filevet. filevet finds them through the `filevet.analyzers` entry point group, the same way it finds its own.

## The analyzer

An analyzer is any class with a `name`, a `version`, a `supports()` method and an `analyze()` method:

```python
from filevet.core.analyzer import AnalysisContext, AnalyzerResult
from filevet.core.artifact import Artifact
from filevet.core.finding import Finding, Severity


class SeenText:
    name = "example.seen_text"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type == "text"

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        if b"hello" not in data:
            return AnalyzerResult()
        finding = Finding(
            rule_id="example.seen_text", title="Greeting found", severity=Severity.INFO
        )
        return AnalyzerResult(findings=[finding])
```

The rules:

- `supports()` runs in the main process, so it must be cheap. Look at `artifact.detected_type`, never at the file contents.
- `analyze()` runs in a sandboxed worker. Read the file only with `artifact.read(limit)`. Never write it, run it, render it or open it with another program, and never use the network. The strong sandbox backends block all of these anyway.
- Catch your own parsing errors and return a finding that says the file couldn't be parsed. An exception that escapes becomes a `pipeline.analyzer_error` finding with severity `high`.
- Give every finding a stable, namespaced `rule_id`. Use your own prefix, not one of the built-in families.
- Keep evidence short and escaped. filevet truncates it at 256 characters.
- Report what you saw. Leave the verdict to the policy.
- Extracted content (an attachment, an archive entry) goes in `AnalyzerResult.children` as `ExtractedFile(name=..., data=...)`. The pipeline scans each child with every analyzer, within the recursion limits.
- Keep the analyzer's state in plain attributes that serialize to JSON. The `nsjail` and `gvisor` backends rebuild the analyzer in a fresh process from its class and attributes.

## Registering it

```toml
[project.entry-points."filevet.analyzers"]
"example.seen_text" = "filevet_example_plugin:SeenText"
```

Install the package next to filevet and check that it shows up:

```sh
filevet analyzers
```

The filevet test suite installs a package like this one from `tests/plugin/` to test discovery.

## Testing it

- A unit test per rule, with inputs that must trigger it and inputs that must not.
- A test that malformed input produces a finding and not an exception.
- Build hostile test files with code at test time. Never commit malware, executables or real personal or financial data.

The [`Analyzer` protocol](stability.md) is part of the stable 1.x contract, so a plugin written against 1.0 keeps working until 2.0.
