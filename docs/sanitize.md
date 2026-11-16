# Sanitizing files

`filevet sanitize` writes a copy of a file with its active content taken out, and prints a report of everything it removed. Use it when a file has to be passed on after the scan. The report is printed even when nothing was removed.

```console
$ filevet sanitize invoice.pdf --output invoice.clean.pdf
{
  "input": "invoice.pdf",
  "output": "invoice.clean.pdf",
  "removed": [
    {"rule_id": "sanitize.javascript", "title": "Removed 1 javascript item(s)", "description": "/JS entries"},
    {"rule_id": "sanitize.annotation", "title": "Removed 2 annotation item(s)", "description": "page 1"}
  ]
}
```

From Python:

```python
from filevet import sanitize

clean, removed = sanitize("invoice.pdf")
```

`removed` is a list of `Finding` objects with `sanitize.*` rule IDs and severity `info`.

The parsing happens inside the configured [sandbox](security-model.md), like any analyzer run. If the file can't be parsed, or its type isn't supported, nothing is written and the command exits with code 3.

## What each type loses

| Type | Removed | Kept |
| --- | --- | --- |
| PDF | Open actions, every `/A` and `/AA` action (links, launch, submit-form, JavaScript), JavaScript name trees, embedded files, forms (field values are flattened into the page first) and all annotations | Page content, text, images and fonts |
| CSV | Nothing is deleted. A cell a spreadsheet would run as a formula gets a leading `'`, as [OWASP](https://owasp.org/www-community/attacks/CSV_Injection) recommends. Negative and signed numbers such as `-12.50` are left alone | Every row and cell, and the delimiter |
| XLSX and XLSM | VBA projects and their signatures, XLM macro sheets, external links, the relationships and content types that point at them, and `Auto_Open`-style defined names. The workbook's content type becomes a plain `.xlsx` workbook | Sheets, cell values, formulas, styles |

Rename a sanitized `.xlsm` to `.xlsx`, because it no longer has macros.

## Limits

- The output isn't scanned automatically. Run `filevet scan` on it if it will be trusted further down the line.
- PDF links stop working, because all annotations are removed rather than sorted into safe and unsafe ones.
- XLSX formulas are kept. Only CSV cells get the `'` prefix.
- DOCX, PPTX, OLE files (`.xls`, `.doc`) and archives aren't supported yet.
- There's no rasterize-and-OCR mode. It would turn each page into an image and rebuild the text from it, the way Dangerzone does, but that means rendering the hostile file and needs a renderer and an OCR engine. It's a possible future addition and would need its own ADR.
