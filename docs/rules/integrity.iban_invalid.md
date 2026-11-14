# integrity.iban_invalid

Severity: `medium`.

## What it means

An IBAN fails its ISO 13616 checks: the mod-97 check digits are wrong, the length doesn't fit the country, or the country has no IBANs. filevet checks IBANs that are labeled as such in text, in IBAN columns of CSV and XLSX files, in ISO 20022 `IBAN` elements, and unlabeled text that has a known country code and the right length. The evidence shows the IBAN, masked.

## Why it matters for finance files

A typo in an IBAN bounces the payment. An IBAN that was edited by hand, digit by digit, often breaks the check digits too.

## How to fix the file

Confirm the account number with the payee through a channel you already trust, not one given in the same document.

## False positives

Account numbers in old national formats, or values that look like an IBAN but are something else, in a column labeled IBAN.

## References

- [SWIFT: IBAN](https://www.swift.com/standards/data-standards/iban-international-bank-account-number)
