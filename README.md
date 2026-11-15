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
> filevet is pre-1.0. It detects active content, known malware and parser attacks in PDF, CSV, XLSX and legacy Office files, ISO 20022 XML and ZIP archives, signs of tampering and inconsistent financial data, and hidden content aimed at AI pipelines. It runs as a CLI, a Python library or a REST API. It hasn't been tested against real-world traffic yet. Until 1.0, the CLI, report format and Python API may change between minor versions.

## Quickstart

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

To add ClamAV signature scanning, use the Compose file, which runs `clamd` as a sidecar and shares its socket with filevet:

```sh
docker compose --profile clamav up -d clamav
docker compose run --rm filevet scan /in/statement.pdf
```

filevet alone needs about 200 MB of RAM. With ClamAV, plan for 1 to 2 GB more for its signature database.

The same Compose file runs the REST API with an async worker, Redis and ClamAV. [docs/api.md](https://github.com/pablodt00/filevet/blob/master/docs/api.md) covers the setup:

```sh
export FILEVET_SPOOL_KEY=... FILEVET_API_KEYS=...
docker compose up -d
```

## Example

```sh
filevet scan invoice.pdf
```

Trimmed output from a file named `invoice.pdf` that's really a Windows executable (the format may still change):

```json
{
  "filevet_version": "0.1.1",
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
  "decision": {
    "policy": "default",
    "verdict": "block",
    "rule": 0,
    "rule_ids": ["basic.executable", "basic.type_mismatch"],
    "reason": "rule 0 of policy default sets block for basic.executable, basic.type_mismatch"
  },
  "summary": { "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0 },
  "verdict": "block"
}
```

The full report format is in [docs/schema/report.schema.json](https://github.com/pablodt00/filevet/blob/master/docs/schema/report.schema.json), and `filevet schema` prints it too. `filevet scan` takes several files at once. `--format` picks the output:

| Format | For |
| --- | --- |
| `json` (default) | Programs. One report, or a list of reports for several files |
| `table` | People at a terminal |
| `sarif` | GitHub code scanning and other CI tools (SARIF 2.1.0) |
| `junit` | CI dashboards. One test case per file, failed on `review` or `block` |
| `markdown` | Pull request comments |

The verdict comes from a policy: `default`, `strict` (bank-grade intake), `ai-ingestion` (files an LLM will read) or your own YAML file, chosen with `--policy`. `filevet policy test` shows how verdicts change under a policy, and `--suppressions` silences a rule for a known file until a set date. Both are described in [docs/policies.md](https://github.com/pablodt00/filevet/blob/master/docs/policies.md).

Other commands:

- `filevet extract --visible-only file.pdf` prints only the text a person would see, as a safe extraction step before an AI pipeline.
- `filevet serve` and `filevet worker` run the REST API and its async workers ([docs/api.md](https://github.com/pablodt00/filevet/blob/master/docs/api.md)).
- `filevet analyzers` lists the registered analyzers, and `filevet version` prints the version.

### Python

```python
from filevet import Policy, ascan, extract_text, scan

report = scan("invoice.pdf", policy=Policy.load("strict"))
print(report.verdict, report.decision.reason)

report = await ascan(upload_bytes, name="invoice.pdf")
text = extract_text("invoice.pdf", visible_only=True)
```

`examples/` has a FastAPI upload endpoint, an S3 event handler that moves files to a quarantine bucket, and a RAG ingestion script.

### CI and pre-commit

The repository is a GitHub Action that scans the documents a pull request adds or changes and uploads SARIF to code scanning:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: pablodt00/filevet@v0  # pin to a release tag or commit
  with:
    policy: strict
```

The job needs `security-events: write`. For pre-commit:

```yaml
- repo: https://github.com/pablodt00/filevet
  rev: v0.4.0
  hooks:
    - id: filevet
```

Integrity findings are signals for review, not proof of fraud. [docs/integrity.md](https://github.com/pablodt00/filevet/blob/master/docs/integrity.md) explains each technique and its limits. IBANs in the evidence are masked (`ES91 **** **** **** **** 1332`) unless you pass `--no-mask`. [docs/privacy.md](https://github.com/pablodt00/filevet/blob/master/docs/privacy.md) lists what a report can contain.

### Exit codes

CI jobs can act on the exit code of `filevet scan` without parsing the report.

| Code | Meaning |
| --- | --- |
| `0` | Verdict `pass` or `pass_with_findings` |
| `1` | Verdict `review` |
| `2` | Verdict `block` |
| `3` | Usage error, including a missing input file, one over the size limit, or an invalid policy |
| `4` | Internal error in filevet |

With several files, the exit code is the one for the strictest verdict. `--fail-on <severity|verdict>` replaces these codes with `1` when any file reaches that severity or verdict and `0` otherwise, which is often simpler in CI.

## What it checks

Each rule has a page in [docs/rules/](https://github.com/pablodt00/filevet/tree/master/docs/rules) that explains what it means, why it matters for finance files, how to fix the file and when it can be a false positive.

| Rule ID | File types | Detects | Severity | References |
| --- | --- | --- | --- | --- |
| `basic.type_mismatch` | All | Extension doesn't match the content | medium, critical for disguised executables | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) |
| `basic.executable` | All | Programs, scripts and `.lnk` shortcuts | high | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) |
| `malware.clamav` (optional) | All | Known malware signatures, via a ClamAV sidecar | critical | [ADR 5](https://github.com/pablodt00/filevet/blob/master/docs/adr/0005-clamav-optional-sidecar.md) |
| `malware.yara` | All | Bundled or your own YARA rules: embedded PE and `.lnk` headers, DDE commands, XXE, PDF auto-run | from the rule, medium by default | [YARA](https://virustotal.github.io/yara/) |
| `malware.pdf_active_content` | PDF | JavaScript, launch actions, auto-actions, rich media, XFA, form submission, URIs, embedded files, hex-obfuscated names, filter chains | low to critical | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) |
| `malware.office_macros` | XLSX, XLSM, DOCX, DOCM, XLS, DOC | VBA, auto-run macros, `Shell`/`CreateObject`/`URLDownloadToFile`, XLM macro sheets, DDE, remote template injection | medium to critical | [ATT&CK T1137](https://attack.mitre.org/techniques/T1137/), [T1221](https://attack.mitre.org/techniques/T1221/), CVE-2017-0199 |
| `malware.embedded_executable` | All containers | PE, ELF, Mach-O, scripts or `.lnk` files inside another file | critical | [ATT&CK T1027.009](https://attack.mitre.org/techniques/T1027/009/) |
| `parser.csv_formula_injection` | CSV, XLSX | Cells that spreadsheet apps run as formulas, including hidden prefixes, full-width characters and DDE payloads | medium, high | [OWASP](https://owasp.org/www-community/attacks/CSV_Injection), [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html) |
| `parser.xml_unsafe` | XML, ISO 20022 | DTDs, external and parameter entities, entity expansion, XInclude, deep nesting | medium to critical | [CWE-611](https://cwe.mitre.org/data/definitions/611.html), [CWE-776](https://cwe.mitre.org/data/definitions/776.html) |
| `parser.archive_bomb` | ZIP, OOXML | Extreme compression ratios, nested archives, too many entries, overlapping entries, quines | high, critical | [CWE-409](https://cwe.mitre.org/data/definitions/409.html) |
| `parser.path_traversal` | ZIP, OOXML | `../` entries, absolute paths, drive letters, symbolic links | high | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| `parser.polyglot` | All | Files that are valid as more than one type | medium | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) |
| `parser.malformed` | All | Broken structure that viewers would repair, each in its own way | medium | |
| `format.iso20022_schema` | ISO 20022 XML | camt.052/053/054, pain.001/008 and pacs.008 messages that don't match their XSD | low | [ISO 20022](https://www.iso20022.org/iso-20022-message-definitions) |
| `integrity.pdf_incremental_updates` | PDF | Saved again after creation, with what each revision changed | info to medium | [integrity.md](https://github.com/pablodt00/filevet/blob/master/docs/integrity.md) |
| `integrity.pdf_revision_diff` | PDF | Text, amounts, IBANs or dates that differ between revisions | low, medium | [integrity.md](https://github.com/pablodt00/filevet/blob/master/docs/integrity.md) |
| `integrity.pdf_producer_mismatch` | PDF | Producer changed between revisions, XMP and Info disagree, dates run backwards, unexpected producer for the issuer | low, medium | [integrity.md](https://github.com/pablodt00/filevet/blob/master/docs/integrity.md) |
| `integrity.pdf_digital_signature` | PDF | Invalid signatures, content added after signing, untrusted certificates | info to high | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) |
| `integrity.pdf_text_overlay` | PDF | White boxes over text, text drawn over other text | medium | [integrity.md](https://github.com/pablodt00/filevet/blob/master/docs/integrity.md) |
| `integrity.pdf_font_anomaly` | PDF | Digits in a second copy of a font, amount-only fonts, fonts added later | low, medium | [integrity.md](https://github.com/pablodt00/filevet/blob/master/docs/integrity.md) |
| `integrity.iban_invalid` | PDF, text, CSV, XLSX, ISO 20022 | IBANs that fail mod-97, length or country checks | medium | [SWIFT: IBAN](https://www.swift.com/standards/data-standards/iban-international-bank-account-number) |
| `integrity.bic_invalid` | PDF, text, CSV, XLSX, ISO 20022 | Malformed BICs, BIC and IBAN from different countries | low | [SWIFT: BIC](https://www.swift.com/standards/data-standards/bic-business-identifier-code) |
| `integrity.iban_inconsistent` | PDF, text | More than one beneficiary IBAN in a document | medium | |
| `integrity.iban_not_allowlisted` | PDF, text, CSV, XLSX, ISO 20022 | A known supplier with an IBAN that isn't on record (needs `--context`) | medium | |
| `integrity.totals_mismatch` | PDF, text, ISO 20022 | Invoice lines that don't add up, unbalanced statements, camt.053 balances, pain.001 `CtrlSum` and `NbOfTxs` | medium | [ISO 20022](https://www.iso20022.org/iso-20022-message-definitions) |
| `integrity.date_anomaly` | PDF, text, CSV, XLSX, ISO 20022 | Impossible dates, bookings long after the value date or outside the statement period, future dates | medium | [ISO 20022](https://www.iso20022.org/iso-20022-message-definitions) |
| `integrity.duplicate_ids` | ISO 20022 | Repeated `MsgId`, `PmtInfId`, `EndToEndId` and other unique references | low, medium | [ISO 20022](https://www.iso20022.org/iso-20022-message-definitions) |
| `ai.hidden_text` | PDF | Text a reader can't see: invisible rendering mode, transparent, white, under 1 pt, off the page, covered by an image. OCR layers over scans aren't flagged | medium | [OWASP LLM01](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| `ai.hidden_text_office` | DOCX, XLSX | Hidden or white runs, hidden and very hidden sheets, hidden rows and columns, white fonts, custom XML parts | low, medium | [OWASP LLM01](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |
| `ai.metadata_payload` | PDF, DOCX, XLSX | Instruction-like text in Title, Subject, Keywords, XMP or document properties | high | [MITRE ATLAS AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) |
| `ai.unicode_smuggling` | PDF, Office, CSV, XML, text | Unicode tag characters, bidi overrides, zero-width characters inside words, Latin mixed with Cyrillic or Greek look-alikes | medium, high | [Trojan Source](https://trojansource.codes/) |
| `ai.prompt_injection_patterns` | PDF, Office, CSV, XML, text | English and Spanish injection phrases, role markers, exfiltration and tool-call patterns, payment approval instructions. High in hidden text and metadata, low in visible text | low, high | [OWASP LLM01](https://owasp.org/www-project-top-10-for-large-language-model-applications/) |

### Configuration

| Variable | Effect |
| --- | --- |
| `FILEVET_CLAMD` | Address of `clamd`: `unix:/path/clamd.sock` or `tcp:host:port`. Without it, ClamAV isn't used |
| `FILEVET_YARA_RULES` | Directories of extra `.yar` files, separated by `:` |
| `FILEVET_XSD_DIR` | Directory of ISO 20022 XSDs, one `<message>.xsd` per version, such as `camt.053.001.08.xsd` |

The REST API has its own settings, listed in [docs/api.md](https://github.com/pablodt00/filevet/blob/master/docs/api.md#configuration).

`filevet scan --context context.yaml` adds what you already know: the IBANs on record for your suppliers, the PDF producers your banks use, and the certificates you trust for signatures. The format is in [docs/integrity.md](https://github.com/pablodt00/filevet/blob/master/docs/integrity.md#context-file). The context file is never logged or copied into the report.

The synthetic test corpus in `tests/corpus/cases/` has one case per threat and per legitimate look-alike. `uv run pytest tests/corpus` prints a detection matrix showing which rules fire on which case.

## Limitations

- filevet never declares a file safe. It reports what it checked and what it found, and no scanner catches everything.
- PDFs are scanned as raw objects. Content hidden behind encryption, or behind filters other than Flate, isn't decoded.
- 7z, RAR and gzip archives are detected but not extracted, so their contents aren't scanned.
- VBA is found by its source text. P-code-only projects (VBA stomping) can get past it.
- No ISO 20022 XSDs ship with filevet yet, so schema validation only runs once you supply them.
- The rules are tested against a synthetic corpus, not real-world malware.
- It doesn't replace antivirus or EDR, email security, or human review of high-value payments.
- Integrity checks only see traces of editing. A document forged from scratch, or flattened into a new PDF, looks clean to them. Scanned images aren't read.
- PDF signatures are checked offline, against the trust roots you supply, without revocation data.
- Hidden-content checks assume a white page and estimate glyph positions, so text hidden by a dark vector shape, or made unreadable in a way the rules don't model, gets through. The prompt injection patterns are heuristics in English and Spanish only.
- It doesn't analyze network traffic, attribute malware to families, or store scanned files.

The full scope is in [docs/SCOPE.md](https://github.com/pablodt00/filevet/blob/master/docs/SCOPE.md).

## Roadmap

Work is split into phases, each tracked as a [milestone](https://github.com/pablodt00/filevet/milestones): foundations, MVP, integrity checks, platform features (the REST API, policy engine and AI-ingestion checks), and hardening for v1.0.

## Contributing

Start with [CONTRIBUTING.md](https://github.com/pablodt00/filevet/blob/master/CONTRIBUTING.md). Everyone taking part is expected to follow the [Code of Conduct](https://github.com/pablodt00/filevet/blob/master/CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately, as described in [SECURITY.md](https://github.com/pablodt00/filevet/blob/master/SECURITY.md). Please don't open public issues for them.

## License

[Apache License 2.0](https://github.com/pablodt00/filevet/blob/master/LICENSE). See also [NOTICE](https://github.com/pablodt00/filevet/blob/master/NOTICE).
