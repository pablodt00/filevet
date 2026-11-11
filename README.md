# filevet

Self-hosted, open-source scanner that checks the files finance teams receive for security risks before anyone opens or ingests them.

[![CI](https://github.com/pablodt00/filevet/actions/workflows/ci.yml/badge.svg)](https://github.com/pablodt00/filevet/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/filevet)](https://pypi.org/project/filevet/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/pablodt00/filevet/badge)](https://scorecard.dev/viewer/?uri=github.com/pablodt00/filevet)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/pablodt00/filevet/blob/master/LICENSE)

## Why

Fintechs and finance teams take in files from outside every day: invoices, bank statements, KYC documents, payment files. Any of them can carry malware, exploit the parser that reads it, or hide instructions meant for an AI system further down the line. Commercial scanners are closed and expensive, and the open-source ones don't understand financial formats like ISO 20022. filevet runs several independent analyzers over a file and returns one report you can act on.

## Status

> [!WARNING]
> filevet is pre-1.0 and not usable yet. The 0.0.x releases on PyPI test the pipeline end to end. So far the only analyzer is `basic.type_mismatch`. Until 1.0, the CLI, report format and Python API may change between minor versions.

## Quickstart

These commands will work from v0.1.0.

```sh
pipx install filevet
# or
uv tool install filevet

filevet scan statement.pdf
```

With Docker, without network access and with the file mounted read-only:

```sh
docker run --rm --network none --read-only --tmpfs /tmp -v "$PWD:/in:ro" ghcr.io/pablodt00/filevet scan /in/statement.pdf
```

## Example

```sh
filevet scan invoice.pdf
```

Trimmed output from a file named `invoice.pdf` that's really a Windows executable (the format may still change):

```json
{
  "filevet_version": "0.0.2",
  "artifacts": [
    {
      "id": "1bf01f46-66b9-4b57-a40c-031d8d71615f",
      "name": "invoice.pdf",
      "sha256": "9f2c…e41a",
      "declared_type": "pdf",
      "detected_type": "pe",
      "depth": 0
    }
  ],
  "findings": [
    {
      "rule_id": "basic.type_mismatch",
      "title": "File content does not match its extension",
      "severity": "critical",
      "confidence": 1.0,
      "evidence": "invoice.pdf",
      "references": ["https://cwe.mitre.org/data/definitions/434.html"],
      "analyzer": "basic.type_mismatch/0.1.0"
    }
  ],
  "summary": { "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0 },
  "verdict": "block"
}
```

`--format table` prints the same report as a table for people. The full report format is in [docs/schema/report.schema.json](https://github.com/pablodt00/filevet/blob/master/docs/schema/report.schema.json), and `filevet schema` prints it too.

Other commands: `filevet analyzers` lists the registered analyzers, and `filevet version` prints the version.

### Exit codes

CI jobs can act on the exit code of `filevet scan` without parsing the report.

| Code | Meaning |
| --- | --- |
| `0` | No findings of `medium` or higher (verdict `pass`) |
| `1` | At least one `medium` finding (verdict `review`) |
| `2` | At least one `high` or `critical` finding (verdict `block`) |
| `3` | Usage error, including a missing input file or one over the size limit |
| `4` | Internal error in filevet |

## What it checks

Planned for v0.1:

| Analyzer | File types | Threats covered |
| --- | --- | --- |
| `basic.type_mismatch` | All | Extension doesn't match content, executables disguised as documents, any executable or script |
| `malware.clamav` (optional) | All | Known malware signatures, via a ClamAV sidecar |
| `malware.yara` | All | Suspicious structure, using bundled or your own YARA rules |
| `malware.pdf_active_content` | PDF | JavaScript, launch actions, auto-actions, embedded files, obfuscated names |
| `malware.office_macros` | XLSX, XLS, DOC | VBA and XLM macros, auto-exec triggers, DDE, remote template injection |
| `malware.embedded_executable` | All containers | PE, ELF, Mach-O, scripts or `.lnk` files inside another file |
| `parser.csv_formula_injection` | CSV, XLSX | Cells that spreadsheet apps will run as formulas, DDE payloads |
| `parser.xml_unsafe` | ISO 20022 XML | DTDs, XXE, entity expansion, XInclude, deep nesting |
| `parser.archive_bomb` | ZIP, OOXML | Extreme compression ratios, deep nesting, overlapping entries, quines |
| `parser.path_traversal` | ZIP | `../` entries, absolute paths, drive letters, symlinks |
| `parser.polyglot` | All | Files that are valid as more than one type |
| `parser.malformed` | All | Broken or parser-repaired structure, a common evasion sign |
| `format.iso20022_schema` | ISO 20022 XML | Messages that don't validate against the official XSD |

## Limitations

- filevet never declares a file safe. It reports what it checked and what it found, and no scanner catches everything.
- It doesn't replace antivirus or EDR, email security, or human review of high-value payments.
- v0.1 doesn't detect document tampering or inconsistent financial data (planned for v0.2), or content aimed at AI pipelines (planned for v0.3).
- It doesn't analyze network traffic, attribute malware to families, or store scanned files.

The full scope is in [docs/SCOPE.md](https://github.com/pablodt00/filevet/blob/master/docs/SCOPE.md).

## Roadmap

Work is split into phases, each tracked as a [milestone](https://github.com/pablodt00/filevet/milestones): foundations, MVP (v0.1), integrity checks (v0.2), platform features such as a REST API and policy engine (v0.3), and hardening for v1.0.

## Contributing

Start with [CONTRIBUTING.md](https://github.com/pablodt00/filevet/blob/master/CONTRIBUTING.md). Everyone taking part is expected to follow the [Code of Conduct](https://github.com/pablodt00/filevet/blob/master/CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately, as described in [SECURITY.md](https://github.com/pablodt00/filevet/blob/master/SECURITY.md). Please don't open public issues for them.

## License

[Apache License 2.0](https://github.com/pablodt00/filevet/blob/master/LICENSE). See also [NOTICE](https://github.com/pablodt00/filevet/blob/master/NOTICE).
