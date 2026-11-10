# 3. Use Python

Date: 2026-11-10

## Status

Accepted

## Context

Most of the work is parsing file formats and looking for known patterns. The best open-source libraries for that are in Python: `pikepdf` and `pdfminer.six` for PDF, `oletools` for Office macros, `defusedxml` and `lxml` for XML, `yara-python` for YARA. Security and data teams, the people likely to contribute analyzers, already know Python. filevet parses hostile input, so memory safety is a real concern.

## Decision

filevet is written in Python and supports 3.11 and newer. We use type hints everywhere and run mypy in strict mode on the core. uv manages dependencies and the lock file.

## Consequences

We get mature parsing libraries and a low barrier for contributors. Python is slower than compiled languages, which is acceptable at our target of a 20 MB PDF in under 10 seconds. Several of these libraries wrap native code that can have memory-safety bugs, so we don't rely on the language for safety: parsers run in isolated workers (see the [architecture](../architecture.md)) and get fuzzed in Phase 4.
