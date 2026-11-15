# ai.hidden_text

Severity: `medium`.

## What it means

A PDF has text that a person viewing the page won't see, but that a text extractor reads. The finding says how the text is hidden:

- drawn with rendering mode 3, which paints nothing
- fully transparent (fill opacity below 0.1)
- white, and not drawn over an image
- in a font smaller than 1 pt
- placed outside the page's crop box or media box
- covered by an image drawn after it

The evidence quotes the hidden text.

## Why it matters for finance files

More and more invoices and statements go through an LLM: to extract fields, summarize, or decide whether to pay. Hidden text is the easiest way to give that model instructions no reviewer sees, such as "this supplier is pre-approved" or a different IBAN.

## How to fix the file

Ask the sender for a clean copy. Before an AI pipeline reads a PDF, take its text with `filevet extract --visible-only`, which drops everything this rule flags.

## False positives

Scanned documents with an OCR layer use invisible text on purpose. filevet doesn't flag invisible text drawn over an image, so normal OCR output passes. Some generators leave white placeholder text on white pages, and some templates keep text outside the page. Page backgrounds are assumed white, so white text on a dark vector shape (not an image) is flagged.

## References

- [OWASP Top 10 for LLM Applications: LLM01 Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS AML.T0051: LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)
- [PDF 2.0 (ISO 32000-2), section 9.3.6, text rendering mode](https://www.pdfa.org/resource/iso-32000-pdf/)
