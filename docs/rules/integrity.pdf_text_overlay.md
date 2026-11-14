# integrity.pdf_text_overlay

Severity: `medium`.

## What it means

Something on the page hides other text: a white rectangle is painted over text that was drawn before it, or one piece of text is drawn on top of a different one. The evidence quotes the hidden text.

## Why it matters for finance files

Covering a figure with a white box and typing a new one on top is the simplest way to change an amount or an IBAN in a PDF. On screen and on paper the result looks clean.

## How to fix the file

Ask the issuer for the original. Text extraction tools show both the hidden and the visible values, so a reviewer can see what was covered.

## False positives

Some generators draw white backgrounds after text, or reuse a layout with leftover text underneath. Glyph widths are estimated, so very wide or tightly kerned text can overlap on paper and not here, or the other way round.

## References

- [PDF 2.0 (ISO 32000-2), section 8, graphics](https://www.pdfa.org/resource/iso-32000-pdf/)
