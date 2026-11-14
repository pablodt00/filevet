# integrity.totals_mismatch

Severity: `medium`.

## What it means

The numbers in the document don't add up:

- invoice line items, plus tax, don't give the total or the subtotal
- a statement's opening balance plus its entries doesn't give the closing balance
- in camt.052 and camt.053, the opening balance (`OPBD` or `PRCD`) plus the booked entries doesn't give the closing balance (`CLBD`)
- in pain.001, pain.008 and pacs.008, `NbOfTxs` or `CtrlSum` doesn't match the transactions, in the group header or in a payment block

## Why it matters for finance files

Editing one figure on a statement or invoice without changing the others leaves the sums broken. In payment files, a control sum that doesn't match can mean transactions were added or changed after the file was built.

## How to fix the file

Ask the issuer for a corrected document. Reject payment files whose control sums don't match.

## False positives

Invoices with discounts, rounding lines or several tax rates that aren't labeled the usual way. Statements in plain text are only checked when entries carry signs.

## References

- [ISO 20022 message definitions](https://www.iso20022.org/iso-20022-message-definitions)
