# integrity.pdf_producer_mismatch

Severity: `medium` when the modification date is earlier than the creation date, or when the producer isn't one the context file expects for the issuer. `low` when the producer changed between revisions, or when the XMP and Info producers disagree.

## What it means

The metadata about who made the PDF, and when, doesn't add up. The evidence names the producers or dates involved.

## Why it matters for finance files

A bank's statements come from one system and carry its name in the `Producer` field. A statement whose last revision was written by a consumer PDF editor, or whose dates run backwards, was probably changed after it was issued.

## How to fix the file

Ask the issuer for the original. If you receive documents from the same bank regularly, list its usual producers under `parties` in the context file so filevet can tell when one doesn't fit.

## False positives

Some tools rewrite metadata when they optimize or archive a file. Clock problems on the producing machine can make dates look reversed.

## References

- [PDF 2.0 (ISO 32000-2), section 14.3, metadata](https://www.pdfa.org/resource/iso-32000-pdf/)
