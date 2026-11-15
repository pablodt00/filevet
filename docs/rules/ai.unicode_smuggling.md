# ai.unicode_smuggling

Severity: `high` for Unicode tag characters, `medium` for the rest.

## What it means

The text contains characters that make what a person sees differ from what software reads:

- Unicode tag characters (U+E0000 to U+E007F). They render as nothing but map one to one onto ASCII, so they can carry a whole hidden sentence. The evidence shows the decoded text.
- Bidirectional overrides and isolates (U+202A to U+202E, U+2066 to U+2069), which reorder text on screen, as in Trojan Source.
- Zero-width characters (U+200B, U+200C, U+200D, U+2060, U+FEFF) inside a word.
- A word that mixes Latin letters with Cyrillic or Greek look-alikes, such as a Cyrillic `а` in `PayPal`.

It checks text in PDFs, Office documents, CSV, XML and plain text, including metadata.

## Why it matters for finance files

A payee name with a homoglyph passes a visual check but doesn't match the supplier record. A reference with a bidi override shows different digits from the ones stored. Tag characters hide prompts from reviewers while an LLM reads them.

## How to fix the file

Normalize the text before use: strip zero-width, bidi and tag characters, and compare names in a single script. `filevet extract --visible-only` removes invisible characters from the text it returns.

## False positives

Arabic, Hebrew and Persian text can use bidi controls and zero-width non-joiners legitimately. Some emoji sequences use zero-width joiners, but those aren't between letters and aren't flagged. A few product names mix scripts on purpose.

## References

- [Trojan Source: Invisible Vulnerabilities](https://trojansource.codes/)
- [Unicode Technical Standard #39: Security Mechanisms](https://www.unicode.org/reports/tr39/)
- [OWASP Top 10 for LLM Applications: LLM01 Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
