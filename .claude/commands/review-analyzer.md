---
description: Review an analyzer against the contracts, the limits and the security rules
argument-hint: <path>
allowed-tools: Read, Grep, Glob, Bash(git diff *), Bash(git log *)
---

Review the analyzer at `$ARGUMENTS`. Read it, its tests, its corpus cases and the contracts in `src/filevet/core/`. Don't change any files.

Check:

- Contract: implements `Analyzer`. `supports()` looks only at the detected type. `analyze()` doesn't write to the artifact. Rule IDs are stable and namespaced under the right family. Evidence is truncated to 256 characters and escaped.
- Errors: no exception can escape `analyze()`. Malformed input produces a finding.
- Limits: every read is bounded. Decompression, recursion and entity expansion have limits. Extracted children respect `max_depth`, `max_children` and `max_total_expanded_bytes`.
- Security rules: everything in the "Security rules" section of CLAUDE.md, plus nothing written outside the temp dir.
- False positives: which benign financial files could trigger each rule, and whether a test covers that.
- Tests: every rule has a positive and a negative unit test, plus at least one benign and one malicious corpus case.

Report the findings by severity, each with file:line and a concrete fix.
