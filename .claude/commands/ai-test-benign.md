---
description: Hunt for false positives with realistic legitimate files
argument-hint: [scenario-id|all]
---

Hunt for false positives in: $ARGUMENTS (a `benign-*` scenario ID from `ai-tests/scenarios/`, or `all` for every benign scenario).

Follow `.claude/commands/ai-test.md` with these changes:

- Every variant is a file a bank, supplier or customer could really send, built from fake data: long statements, unusual but valid structure, formulas used for real work, accented or non-Latin names, negative amounts. The plan says for each one why a careless rule might flag it.
- Any variant that doesn't get a `pass` verdict is a false positive. File it with the `false-positive` label.
