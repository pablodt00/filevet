# Fuzzing

filevet's format handlers are fuzzed with [Atheris](https://github.com/google/atheris), a coverage-guided fuzzer for Python built on libFuzzer. The harness is `fuzz/fuzz.py`, and the seeds are the synthetic corpus.

## Targets

| Target | What it fuzzes |
| --- | --- |
| `pdf`, `ooxml`, `ole`, `csv`, `xml`, `zip` | Every built-in analyzer that supports the type, called in-process on the input |
| `pipeline` | `scan()` with every analyzer, checking that the report is valid against `docs/schema/report.schema.json` |

The format targets treat any exception that escapes `analyze()` as a crash, because an analyzer must turn bad input into a finding. ClamAV is left out because it needs a daemon.

## Running it

Atheris publishes wheels for Python 3.11, so run it on 3.11, in its own environment so your `.venv` stays as it is:

```console
make corpus
mkdir -p tmp-samples/fuzz/pdf tmp-samples/fuzz/crashes
UV_PROJECT_ENVIRONMENT=.venv-fuzz uv run --python 3.11 --with atheris==2.3.0 python -I fuzz/fuzz.py pdf \
  -max_total_time=600 -timeout=30 -rss_limit_mb=2048 \
  -artifact_prefix=tmp-samples/fuzz/crashes/ \
  tmp-samples/fuzz/pdf tmp-samples/corpus
```

The first directory collects new interesting inputs, and the second holds the seeds. Crashes, hangs (`-timeout`) and out-of-memory errors (`-rss_limit_mb`) are written to `tmp-samples/fuzz/crashes/`, which git ignores. Never commit them.

## Nightly job

The `Fuzz` workflow runs every target for 10 minutes each night, keeps each target's corpus in the Actions cache so coverage keeps growing, and uploads crash files as an artifact when a target fails. Start it by hand with a different time budget from the Actions tab.

## When it finds something

1. Download the crash artifact and reproduce it locally inside the test sandbox.
2. Work out the smallest input that triggers it, and add a generator option to `tests/corpus/generators/` that builds it. Don't commit the crash file itself.
3. Add a test to `tests/unit/test_fuzz_regressions.py`, fix the bug at its root and check that the test failed before the fix.
4. If the crash is in a dependency (qpdf, YARA, expat, olefile), report it upstream through that project's security process, and handle the error in filevet in the meantime.

The first runs found four bugs, all fixed with regression tests: an XML declaration with an unknown encoding raised `LookupError` in four analyzers, a corrupt deflate stream raised `zlib.error` inside `malware.office_macros`, a bare carriage return in a CSV field raised `csv.Error` in `integrity.financial_data`, and a huge `startxref` offset raised `OverflowError` in `malware.pdf_active_content`.

## OSS-Fuzz

Once the project meets OSS-Fuzz's acceptance criteria, the harness can move there. OSS-Fuzz expects one `fuzz_<target>.py` file per target, so `fuzz/fuzz.py` would be split into thin wrappers around the same code. Until then the nightly job takes its place.
