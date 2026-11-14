# integrity.pdf_revision_diff

Severity: `medium` when the changed text holds an amount, an IBAN or a date. `low` for any other text change.

## What it means

The text on a page differs between two revisions of the same PDF. The evidence shows the old and the new line, with IBANs masked unless you pass `--no-mask`.

## Why it matters for finance files

This is the direct trace of an edited statement or invoice: the closing balance, the amount due or the beneficiary's IBAN said something else when the document was first saved.

## How to fix the file

Treat the earlier value as the issuer's and ask them to confirm it. Don't act on the document until they do.

## False positives

Documents that are legitimately updated in place, such as a draft invoice finalized in the same file, show their changes here too. Changes to text in fonts without a `ToUnicode` map are missed, because that text isn't read.

## References

- [PDF 2.0 (ISO 32000-2), section 7.5.6, incremental updates](https://www.pdfa.org/resource/iso-32000-pdf/)
