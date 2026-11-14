# integrity.iban_not_allowlisted

Severity: `medium`. Needs a context file.

## What it means

The document names a party listed in your context file, next to an IBAN that isn't on record for it. "Next to" means anywhere in a PDF or text document, the same row of a CSV or XLSX file, or the same transaction or entry in an ISO 20022 message. The evidence shows the document's IBAN, masked, never the one on record.

## Why it matters for finance files

This is the direct check for invoice redirection: the supplier is real, the invoice looks right, but the money would go somewhere else.

## How to fix the file

Call the supplier on a number you already have. If the account really changed, update the context file.

## False positives

Suppliers with several accounts need all of them listed. A party name that also appears in unrelated text, such as a reference in a statement, makes the whole document count as theirs.
