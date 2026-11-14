# integrity.bic_invalid

Severity: `low`.

## What it means

A BIC doesn't follow the ISO 9362 layout (4 letters, 2-letter country, 2 characters, optional 3 more) or its country code doesn't exist. It's also reported when a document has exactly one IBAN and one BIC, and they belong to different countries.

## Why it matters for finance files

An edited payment detail often changes one part and forgets the other. A German IBAN next to a French bank's BIC is worth a second look.

## How to fix the file

Check the bank details with the payee directly.

## False positives

Some banks serve accounts in a neighboring country, and territories such as Jersey or Monaco use another country's IBAN or BIC codes.

## References

- [SWIFT: BIC](https://www.swift.com/standards/data-standards/bic-business-identifier-code)
