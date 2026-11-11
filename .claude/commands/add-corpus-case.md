---
description: Add a synthetic corpus case as a generator plus its expected findings
argument-hint: <threat>
---

Add a synthetic corpus case for: $ARGUMENTS

1. Follow the layout of the existing cases in `tests/corpus/`. If there are none yet, put the generator in `tests/corpus/generators/` and its `expected.yaml` next to the case, as CONTRIBUTING.md describes, and say in the PR that this sets the layout.
2. Write a generator in `tests/corpus/generators/`, in pure Python with the standard library or existing dev dependencies only. It writes its output under `tmp-samples/` at test time. Add a benign twin if the threat has a near-miss look-alike, to catch false positives.
3. Never commit a binary, real malware or real data. Build the EICAR string and any executable bytes from parts at run time. Use fake names and fake IBANs with valid checksums.
4. Write `expected.yaml`: the `rule_id`s the case must trigger and, for benign cases, an empty list.
5. Run the generator with `python -I` and run the corpus tests. Confirm `git status` shows no files under `tmp-samples/`.
