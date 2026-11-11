---
description: Run adversarial AI tests for a scenario and turn misses into regression tests
argument-hint: [scenario-id|all]
---

Run the AI tests for: $ARGUMENTS (a scenario ID from `ai-tests/scenarios/`, or `all` for every scenario there).

Read `ai-tests/README.md` first. Its safety rules apply to every step.

For each scenario:

1. Read the scenario YAML and the source of the analyzers behind its `must_find` rule IDs. If an analyzer doesn't exist yet, say so. Every variant will be a miss, and the report is still worth having.
2. Write a short generation plan: the variants, the technique each one uses, and why it might get past the analyzer. Stay inside `techniques_allowed` and the `budget`.
3. Express each variant as a call to a generator in `tests/corpus/generators/`. If a technique needs something the generators can't build, add a keyword argument to a generator and keep the existing defaults. Payloads stay inert: `=1+1`, `app.alert()`, `example.invalid` URLs, paths that don't exist. Never write a sample file yourself, with Write, Bash or anything else.
4. Save the plan to `ai-tests/plans/<scenario-id>.json` as a list of `{"generator": "<name>", "args": {...}}`.
5. Run `uv run python -I ai-tests/run.py --scenario <scenario-id> --plan ai-tests/plans/<scenario-id>.json` and read the Markdown report whose path it prints.
6. For each miss, false positive, crash or timeout:
   - Minimize it to the smallest generator call that still reproduces it, and run the runner again to confirm.
   - Add that call to `tests/corpus/regressions/cases.yaml` with an `xfail` reason, then check it xfails with `uv run pytest tests/corpus/regressions`.
   - Open or update a GitHub issue labeled `false-negative` or `false-positive`. Search for an existing one first. Crashes and timeouts are `false-negative` issues that say the scanner itself may be open to DoS.
7. Never change an analyzer and its tests in the same step to make a case pass. Fixes go in a separate commit or PR that a human reviews.

End with a summary for the PR or issue: for each scenario, the detection or false-positive rate, the new regression cases and the issues opened or updated.
