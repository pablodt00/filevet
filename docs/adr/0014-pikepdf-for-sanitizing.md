# 14. Rebuild sanitized PDFs with pikepdf

Date: 2026-11-16

## Status

Accepted

## Context

`filevet sanitize` writes a copy of a file without its active content. For PDF that means rewriting the object graph: dropping actions, JavaScript, embedded files and forms, flattening form fields into page content and keeping the text. filevet's own reader in `core/pdf.py` is built for inspection and can't write PDFs. pyHanko can write incremental updates, but an incremental update keeps the old objects in the file, so the removed content would still be there.

## Decision

Add `pikepdf` (MPL-2.0) as a runtime dependency. It wraps qpdf (Apache-2.0), rewrites the whole file and drops objects nothing references. It brings `lxml` (BSD-3-Clause), `packaging` (Apache-2.0 or BSD-2-Clause) and `Pillow` (MIT-CMU). MIT-CMU is a permissive, MIT-style license, so it's added to both license allow lists in `.github/workflows/security.yml`, together with the `Apache-2.0 OR BSD-2-Clause` expression `packaging` uses.

CSV and XLSX sanitizing use only the standard library.

Sanitizing runs through the same `Sandbox` as the analyzers, because qpdf parses the hostile file.

## Consequences

The wheel set grows by about 15 MB, most of it qpdf and Pillow. The rasterize-and-OCR mode from the issue isn't part of this decision. It would need a renderer and an OCR engine, and both of them process the hostile file. That needs its own ADR.
