# filevet scope

## Problem

Fintechs and finance teams receive files from outside all the time: invoices, bank statements, KYC documents, payment files. A file can carry malware, exploit the parser that reads it, be altered to commit fraud, or hide instructions aimed at AI systems that process it. Commercial tools exist but are closed and expensive. Open-source tools cover parts of the problem, and none of them understand financial file formats.

## What filevet is

A self-hosted, open-source tool that inspects a file with several independent analyzers and returns one report: what was checked, what was found, how severe it is, and a recommended verdict of block, review, or pass with findings.

## Who it is for

Engineering and security teams at fintechs, payment companies and finance departments. They run it in upload pipelines, back-office tooling, CI, or AI ingestion pipelines.

## What it promises

- Every finding has a rule ID, a location, evidence and an explanation.
- It runs entirely on your infrastructure. Files never leave it, and by default nothing is kept after the scan.
- Verdicts come from a configurable policy, not hard-coded logic.

## What it does not promise

- It never declares a file safe. It reports what it checked and what it found. No scanner catches everything.
- It does not replace antivirus or EDR, email security, or human review of high-value payments.
- It never executes or opens files outside its sandbox.

## File types in v0.1

PDF, CSV, XLSX, ISO 20022 XML (camt.05x, pain.001, pain.008), and ZIP archives containing these.

## Threat model for v0.1

1. Embedded malware and active content: macros, PDF JavaScript, launch actions, embedded executables.
2. Parser attacks: CSV formula injection, XXE and entity expansion, zip bombs, path traversal in archives.
3. Disguised files: extension and content mismatch, polyglots.

## Planned for later

- v0.2: document tampering and financial data integrity.
- v0.3: hidden content aimed at AI or LLM pipelines.
- v1.x: sanitized output.

## Out of scope

Network traffic analysis, endpoint protection, malware family attribution, and storing or sharing scanned files.

## Design principles

- Self-hosted first.
- No file retention.
- Findings are explainable.
- Findings are kept separate from policy.
- Analyzers are plugins.
- Every parser runs in isolation.
- No real malware in the repository.

## v0.1 success criteria

- `filevet scan <file>` and `docker run` both work.
- It flags every sample in the synthetic malicious corpus and gives no block verdicts on the synthetic benign corpus.
- Results are available as JSON.
- Installing from the README takes under five minutes.
