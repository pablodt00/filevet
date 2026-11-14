# 10. Parse file formats with a small set of permissive libraries

Date: 2026-11-14

## Status

Accepted

## Context

The format analyzers need to read PDF, OOXML, legacy OLE, CSV, XML and ZIP files, run YARA rules and validate ISO 20022 messages against their XSDs. Every runtime dependency ends up in the Docker image and in every user's install, and each one adds parser code that hostile files can attack. The license gate in `.github/workflows/security.yml` allows only permissive licenses.

Some obvious candidates don't fit:

- `pikepdf` needs `Pillow`, whose MIT-CMU license is not on the allow list, and brings in the native qpdf library. qpdf also repairs broken files silently, which hides the structure we want to report.
- `oletools` depends on `pcodedmp`, which is GPL-3.0.
- `pdfminer.six` extracts text, which v0.1 doesn't need.
- `py7zr` and `rarfile` would add 7z and RAR extraction. The issue asks for that to be optional and off by default, so it isn't built yet.

## Decision

We add these runtime dependencies:

| Package | License | Used for |
| --- | --- | --- |
| `defusedxml` | PSF-2.0 | All XML parsing. DTDs and entities are refused by default |
| `charset-normalizer` | MIT | Guessing the encoding of CSV files that aren't UTF-8 |
| `olefile` | BSD-2-Clause | Reading streams from legacy OLE files (`.doc`, `.xls`, `vbaProject.bin`) |
| `yara-python` | Apache-2.0 | The `malware.yara` analyzer. The wheel bundles libyara (BSD-3-Clause) |
| `xmlschema` | MIT | Validating ISO 20022 messages against their XSD, with network access off |

The rest is the standard library: `zipfile` for ZIP and OOXML, `csv` for CSV, `zlib` for PDF streams. PDFs are scanned as raw objects, the way `pdfid` does it: names are decoded from their hex escapes, Flate streams are inflated within the size limit, and object streams are searched as well. VBA source is decompressed with the MS-OVBA algorithm (about 30 lines in `office_macros.py`) instead of through `oletools`.

## Consequences

The image stays small, and the only native code it gains is libyara. The raw PDF scanner sees exactly what's in the file, including structure a repairing parser would have cleaned up, but it doesn't follow cross-references, so a PDF that hides objects with an encryption or filter trick it doesn't decode can get past it. The VBA reader finds module source by its `Attribute` header instead of reading the `dir` stream, which works for normal Office files but can be fooled by a crafted project. If either becomes a real gap, we can revisit `pikepdf` or `oletools` with an update to the license allow list.
