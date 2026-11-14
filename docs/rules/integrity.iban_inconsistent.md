# integrity.iban_inconsistent

Severity: `medium`.

## What it means

A PDF or text document gives more than one labeled IBAN. The evidence lists them, masked.

## Why it matters for finance files

In invoice redirection fraud, the attacker adds new payment details to a real invoice, often a "please note our new bank details" line, while the old IBAN still appears in the header or footer.

## How to fix the file

Pay only to an IBAN you have confirmed with the supplier through a known channel.

## False positives

Some invoices list accounts at two banks on purpose. Statements, CSV exports and payment files aren't checked, because they list many counterparties by nature.
