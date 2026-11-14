# integrity.pdf_font_anomaly

Severity: `medium` when digits are set in a second embedded copy of a font already on the page. `low` when a font is used for amounts and nothing else, or when fonts were added in a later revision.

## What it means

The fonts on the page don't fit together. The evidence names the font and the text set in it.

## Why it matters for finance files

When someone retypes a number in an editor, the editor usually embeds a new subset of the font for the new glyphs. The page then has two copies of the same font, and the edited figure is the only text in the second one.

## How to fix the file

Compare the figure with the issuer's records, or ask for a fresh copy.

## False positives

Documents assembled from several sources can embed the same font more than once. Some invoice layouts set the amount column in a font of its own.

## References

- [PDF 2.0 (ISO 32000-2), section 9.6.4, font subsets](https://www.pdfa.org/resource/iso-32000-pdf/)
