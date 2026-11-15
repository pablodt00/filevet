# Privacy

filevet runs on your own infrastructure and makes no network calls of its own, so files and reports stay with you. The exceptions are the ones you turn on: webhooks send a report to a host you list, and an LLM verifier you install can see findings. Reports can still hold personal data, and the GDPR covers that data if it applies to you. This page lists what a report can contain, so you can decide where to store reports and for how long.

## What a report contains

- File metadata: the file name, size, SHA-256 and MD5 of the input and of every extracted child. File names often carry names or account numbers (`statement_anna_beispiel_2026-01.pdf`).
- Evidence: each finding quotes at most 256 characters of what it saw. For integrity rules that can be a line of text from a statement or invoice, an amount, a date, a person or company name, or a PDF producer string.
- Locations: page numbers, sheet and cell references, XPaths and byte offsets. On their own these hold no personal data.

## Masking

IBANs in the evidence are masked by default. The first four and the last four characters stay, and the rest becomes `*`, so `ES9121000418450200051332` shows as `ES91 **** **** **** **** 1332`. That's enough to match it against your records without storing the full account number. Amounts, dates and names aren't masked, because the reviewer needs them to judge the finding.

`filevet scan --no-mask` turns masking off. Use it only where the full report is as well protected as the original file.

## The context file

The `--context` file holds the IBANs of your suppliers, issuer names and certificates. filevet reads it into memory and passes it to the analyzers. It's never logged and never copied into the report. A finding from it says which rule fired and quotes the IBAN from the document, never the one on record.

## Logs

Logs hold SHA-256 hashes, analyzer names, rule IDs, statuses and timings. They never contain file contents, evidence or the context file.

## The REST API

Small uploads are scanned in memory and a private temp directory, and nothing is kept once the response is sent. Large uploads wait in Redis, encrypted, until a worker takes them, and are deleted as it does. Results are kept for `FILEVET_RETENTION_S` seconds (one hour by default) and then expire. Webhook bodies hold the full report, including evidence.

## LLM verifiers

`--llm-verify` passes each `ai.*` finding, with its evidence of at most 256 characters, to the verifier you name. What the verifier does with it, including sending it to a model provider, is up to that plugin. No verifier ships with filevet.

## What to consider

- Store reports with the same access control and retention as the documents they describe.
- If you forward reports to a SIEM or ticketing system, keep masking on.
- A data subject access request may cover reports as well as the original documents.
