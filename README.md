# filevet

Self-hosted, open-source scanner that checks the files finance teams receive for security risks before anyone opens or ingests them.

[![PyPI](https://img.shields.io/pypi/v/filevet)](https://pypi.org/project/filevet/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/pablodt00/filevet/blob/master/LICENSE)

## Why

Fintechs and finance teams take in files from outside every day: invoices, bank statements, KYC documents, payment files. Any of them can carry malware, exploit the parser that reads it, or hide instructions meant for an AI system further down the line. Commercial scanners are closed and expensive, and the open-source ones don't understand financial formats like ISO 20022. filevet runs several independent analyzers over a file and returns one report you can act on.

## Status

> [!WARNING]
> filevet is pre-1.0 and not usable yet. The 0.0.1 release on PyPI only reserves the name. Until 1.0, the CLI, report format and Python API may change between minor versions.

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
filevet scan invoice.pdf --format json
```

Trimmed output (the format may still change):

```json
{
  "filevet_version": "0.1.0",
  "artifact": {
    "name": "invoice.pdf",
    "sha256": "9f2c…e41a",
    "declared_type": "application/pdf",
    "detected_type": "application/pdf"
  },
  "findings": [
    {
      "rule_id": "malware.pdf_active_content",
      "severity": "high",
      "confidence": 0.9,
      "title": "PDF runs JavaScript when opened",
      "location": { "object": 12 },
      "evidence": "/OpenAction << /S /JavaScript /JS (app.launchURL…) >>",
      "references": ["https://cwe.mitre.org/data/definitions/829.html"]
    }
  ],
  "summary": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
  "verdict": "block"
}
```

## What it checks

Planned for v0.1:

| Analyzer | File types | Threats covered |
| --- | --- | --- |
| `basic.type_mismatch` | All | Extension doesn't match content, executables disguised as documents |
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
