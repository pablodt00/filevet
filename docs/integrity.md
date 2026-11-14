# Integrity checks

A document can be dangerous without carrying malware. Someone edits the amount on a bank statement before sending it in for a loan, or swaps the IBAN on a supplier's invoice so the payment goes to their own account. filevet's integrity rules look for the traces those edits leave behind.

Integrity findings are signals for a person to review, not proof of fraud. Most rules report `medium` at most. The exception is a broken PDF signature, or content added after signing, which is `high` because the document contradicts its own seal. Until the policy engine arrives in Phase 3, the verdict follows the highest severity, so one integrity signal on its own leads to `review` at most. The Phase 3 policy will raise the verdict when several signals combine, such as a changed amount plus a new producer plus fonts added in the same revision.

Three analyzers produce these findings:

| Analyzer | Input | Rules |
| --- | --- | --- |
| `integrity.pdf_tampering` | PDF | `pdf_incremental_updates`, `pdf_revision_diff`, `pdf_producer_mismatch`, `pdf_text_overlay`, `pdf_font_anomaly` |
| `integrity.pdf_signature` | Signed PDF | `pdf_digital_signature` |
| `integrity.financial_data` | PDF text, plain text, CSV, XLSX, ISO 20022 XML | `iban_invalid`, `bic_invalid`, `iban_inconsistent`, `iban_not_allowlisted`, `totals_mismatch`, `date_anomaly`, `duplicate_ids` |

All rule IDs start with `integrity.`. Each one has a page in [rules/](rules/).

## PDF tampering

### Saved again after creation

Most PDF editors don't rewrite the file when you save. They append the changed objects, a new cross-reference section and a new `%%EOF` at the end. The original bytes stay in place, so every earlier revision can still be read.

filevet splits the file at each `startxref … %%EOF` marker and sorts the objects of every later revision into page content, pages, fonts, metadata, form fields and annotations, signatures, or other. `integrity.pdf_incremental_updates` reports the revision count and what changed in each. A change to page content is `medium`. Pages, fonts or other objects alone are `low`, and metadata, form fields or signatures alone are `info`.

### What the text said before

`integrity.pdf_revision_diff` extracts the text of every revision, groups it into lines by position on the page, and diffs each revision against the one before it. A changed line that contains an amount, an IBAN or a date is `medium`, and any other change (a name, for example) is `low`. The evidence shows the old and the new line, with IBANs masked.

### Who wrote the file

`integrity.pdf_producer_mismatch` compares metadata that should agree:

- the `Producer` of the first revision with that of the last (`low`), as when a statement from a banking system was last saved by a consumer PDF editor
- the `Producer` in the XMP metadata with the one in the Info dictionary (`low`)
- `ModDate` earlier than `CreationDate` (`medium`)
- with a context file, a producer that isn't among the expected ones for an issuer named in the document (`medium`)

### White boxes and text over text

The usual way to change a figure in a PDF without an editor that understands text is to paint a white rectangle over it and write the new value on top. `integrity.pdf_text_overlay` runs the page content stream, tracking the transformation matrix, the fill color, text positions and filled rectangles. It reports a white rectangle painted after text and covering most of it, and text that lands on other, different text. Glyph widths are estimated, not read from font metrics.

### Fonts

When someone retypes a number, the editor often embeds a fresh subset of the font, so the page ends up with two copies of, say, `ABCDEF+Helvetica` and `GHIJKL+Helvetica`. `integrity.pdf_font_anomaly` reports digits set in the rarer copy (`medium`), a font used for amounts and nothing else (`low`), and fonts added in a later revision (`low`).

### Signatures

`integrity.pdf_digital_signature` verifies every signature with pyHanko ([ADR 11](adr/0011-integrity-dependencies.md)):

| Result | Severity |
| --- | --- |
| Valid, trusted, covers the whole file | `info` |
| Valid, but the certificate is untrusted or expired | `low` |
| Valid, then form fields or annotations were added | `low` |
| Valid, then other content was added | `high` |
| Invalid, or the signature can't be read | `high` |

filevet trusts no certificates by default, not even the system store, so a valid signature is `low` until you list your CA certificates under `trust_roots` in the context file. It never fetches revocation data.

## Financial data

`core/extract_finance.py` pulls IBANs, BICs, amounts and dates out of text, CSV and XLSX cells, and reads ISO 20022 messages element by element instead of as text.

- `integrity.iban_invalid`: the mod-97 check fails, the length is wrong for the country, or the country has no IBAN. Unlabeled text only counts when it has a known country code and the right length, so VAT numbers and creditor references (`RF…`) don't trigger it.
- `integrity.bic_invalid`: the BIC doesn't follow the ISO 9362 layout or its country code is unknown (`low`). A document with exactly one IBAN and one BIC from different countries is also reported (`low`).
- `integrity.iban_inconsistent`: a PDF or text document gives more than one labeled IBAN, such as one in the header and another in the payment instructions. Statements, CSV exports and payment files list many counterparties, so this rule skips them.
- `integrity.totals_mismatch`: invoice line items plus tax don't add up to the total; opening balance plus signed entries doesn't give the closing balance; in camt.052 and camt.053, `OPBD`/`PRCD` plus the booked `Ntry` amounts doesn't give `CLBD`; in pain.001, pain.008 and pacs.008, `NbOfTxs` or `CtrlSum` doesn't match the transactions, for the group header and for each `PmtInf`.
- `integrity.date_anomaly`: dates that don't exist (31.02.2026); in camt messages, a booking date more than 7 days after the value date, a booking date outside the statement period or after the message was created, or a creation date in the future.
- `integrity.duplicate_ids`: the same `MsgId`, `PmtInfId`, `InstrId`, `EndToEndId`, `TxId`, `NtryRef` or `AcctSvcrRef` more than once at the same place in a message (`medium` in payment files, `low` in statements). `NOTPROVIDED` is ignored.

## Context file

`filevet scan --context context.yaml` adds what you already know:

```yaml
parties:
  Muster Lieferant GmbH:
    ibans: [DE17123456780000000001]
  Beispiel Bank AG:
    producers: [BankCore Statements 4.2]
trust_roots:
  - |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
```

When a document names a party, `integrity.iban_not_allowlisted` reports any valid IBAN next to that name that isn't on record for it, which catches invoice redirection. In a PDF or text file the whole document counts as next to the name, in CSV and XLSX it's the same row, and in ISO 20022 it's the same transaction or entry. `producers` feeds `pdf_producer_mismatch`, and `trust_roots` feeds `pdf_digital_signature`.

The context file is read once by the CLI and handed to the analyzers. It's never logged, and nothing from it goes into the report except the rule that it triggered. Error messages about the file name the problem, never its contents.

## Limits

- A document recreated from scratch, with no revisions, won't trigger the revision, producer-change or added-font checks. Neither will one that was flattened or printed to a new PDF.
- Text extraction understands simple fonts and `ToUnicode` maps. Text in fonts without a `ToUnicode` map, in scanned images or in encrypted PDFs isn't read, and encrypted PDFs skip the text-based checks altogether.
- Only Flate-compressed streams are decoded. Other filters hide content from these checks, as they do for `malware.pdf_active_content`.
- An uncompressed PDF embedded inside another one adds its own `%%EOF` and can be counted as a revision.
- Overlap detection estimates glyph widths, so tightly kerned or very wide text can be missed or, rarely, misreported.
- Invoice and statement totals are found from labels (`Total`, `Subtotal`, `VAT`, `Opening`, `Closing` and their German, Spanish and French counterparts) and from where the amounts sit on each line. Statements are only checked when the entries carry signs, because a separate debit column can't be told apart from a credit one in plain text.
- CII and UBL invoices aren't checked yet, and neither are duplicate invoice numbers across rows of a CSV or XLSX.
- Without trust roots, every signature is untrusted. Revocation isn't checked.
