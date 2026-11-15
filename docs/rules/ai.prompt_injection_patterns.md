# ai.prompt_injection_patterns

Severity: `high` (confidence 0.9) in hidden text, metadata and comments. `low` (confidence 0.3) in visible text.

## What it means

The text matches a heuristic prompt injection pattern, in English or Spanish:

- telling the model to ignore, disregard or forget earlier instructions
- reassigning its role ("you are now", "act as", "ahora eres")
- chat role markers and template tokens (`system:`, `<|im_start|>`, `[INST]`)
- "new instructions", or telling the model to keep something from the user
- exfiltration: a Markdown image pointing at a URL with a query string, or "send this to" a URL or email address
- tool or function calls
- telling the model to approve, authorize or mark an invoice, payment or document

Invisible characters are removed and the text is NFKC-normalized before matching, so zero-width tricks and full-width letters don't hide a pattern.

## Why it matters for finance files

If an LLM reads invoices or statements to extract data or recommend a payment, any text in the file becomes part of its prompt. An instruction hidden in the file can change what the model reports or does.

## How to fix the file

Find out where the text came from. For AI pipelines, use `filevet extract --visible-only` and keep the model away from metadata and comments.

## False positives

The patterns are heuristics. Visible text gets a low severity because ordinary documents sometimes say "approve the invoice" or quote these phrases. Hidden text that matches is rarely innocent. The `ai-ingestion` policy reviews every match and blocks hidden ones.

`filevet scan --llm-verify NAME` can ask an installed LLM verifier for a second opinion. It only ever raises the confidence of an `ai.*` finding and never removes one. No verifier ships with filevet, and nothing is sent anywhere unless you install and name one.

## References

- [OWASP Top 10 for LLM Applications: LLM01 Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS AML.T0051: LLM Prompt Injection](https://atlas.mitre.org/techniques/AML.T0051)
