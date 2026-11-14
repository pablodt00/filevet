# integrity.pdf_incremental_updates

Severity: `medium` when page content changed after the first save. `low` when only pages, fonts or other objects changed. `info` when only metadata, form fields, annotations or signatures changed.

## What it means

The PDF was saved more than once after it was created. Each save appended new objects to the end of the file, so the earlier versions are still inside it. The evidence lists every later revision and what it changed.

## Why it matters for finance files

Statements and invoices come out of a bank or accounting system once and aren't edited afterwards. A statement whose page content changed in a second revision was opened in an editor after it was issued.

## How to fix the file

Ask the issuer for a fresh copy, straight from their system. Compare the revisions with `integrity.pdf_revision_diff`, which shows what the text said before.

## False positives

Filling in a form, adding a comment or signing a PDF also appends a revision. Those come out as `info` or `low`. Some document management systems re-save every file they store.

## References

- [PDF 2.0 (ISO 32000-2), section 7.5.6, incremental updates](https://www.pdfa.org/resource/iso-32000-pdf/)
