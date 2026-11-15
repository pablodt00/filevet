# ai.hidden_text_office

Severity: `medium` for hidden runs, white text and very hidden sheets. `low` for hidden sheets, rows and columns and for custom XML parts, which are common in ordinary workbooks and documents.

## What it means

A Word document or Excel workbook holds text that isn't shown when it's opened:

- DOCX runs marked `vanish` (hidden text) or coloured white
- XLSX sheets with state `hidden` or `veryHidden`, hidden rows and hidden columns that contain values
- XLSX cells whose font is white
- custom XML parts (`customXml/item*.xml`) with text in them

Comments and notes are read too, but they only produce a finding through `ai.prompt_injection_patterns`, when their text reads like an instruction.

## Why it matters for finance files

Text extractors and LLM pipelines read every run and every sheet, including the ones a person never sees. A hidden sheet can carry instructions for the model, or different figures from the ones on screen.

## How to fix the file

Unhide the sheets, rows, columns or text and check what they say. For AI pipelines, use `filevet extract --visible-only`, which leaves hidden content out.

## False positives

Hidden lookup sheets, hidden helper columns and SharePoint custom XML are normal, which is why they're `low`. White text is sometimes used as a spacer in templates.

## References

- [OWASP Top 10 for LLM Applications: LLM01 Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [ECMA-376 Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
