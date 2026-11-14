# parser.csv_formula_injection

Severity: `high` for values starting with `=` or `@`, and for any value that calls a function able to run commands or fetch data (`cmd|`, `HYPERLINK`, `WEBSERVICE`, `IMPORTXML`, DDE). `medium` for values starting with `+` or `-` followed by text.

## What it means

A cell starts with a character that spreadsheet apps treat as the start of a formula. filevet also catches the usual disguises: leading spaces, tabs, carriage returns or quotes, and full-width look-alikes such as `＝`. In XLSX files it checks string cells only, so real formulas are left alone, but text that turns into a formula when the sheet is exported to CSV and opened again is caught. The finding gives the cell, and the sheet for XLSX.

Plain numbers such as `-12.50`, `+1,200.00` or `+49 30 1234567` don't trigger it.

## Why it matters for finance files

CSV exports flow from bank portals and customer uploads straight into Excel on someone's desk. A crafted description field in a transaction can run a command, or quietly send the rest of the sheet to an outside server, the moment it is opened.

## How to fix the file

Ask for a clean export, or neutralize the values before opening: prefix the cell with a single quote `'` or strip the leading character. When your own system writes CSV, escape these values the way OWASP describes.

## False positives

Free-text columns sometimes hold values like `- see note`. Those come out as `medium`.

## References

- [OWASP: CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection)
- [CWE-1236](https://cwe.mitre.org/data/definitions/1236.html)
