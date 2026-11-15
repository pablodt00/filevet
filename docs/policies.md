# Policies

Analyzers report what they saw. A policy turns those findings into a verdict: `block`, `review`, `pass_with_findings` or `pass`. Changing how strict filevet is means changing the policy, never an analyzer.

## Built-in policies

| Name | For |
| --- | --- |
| `default` | `high` and `critical` block, `medium` needs review, anything lower passes with findings. ISO 20022 schema errors are data quality, so they're allowed |
| `strict` | Bank-grade intake. Any active content (`malware.*`) or parser attack (`parser.*`) blocks whatever its severity, two or more integrity signals block, and every `low` or `medium` finding goes to review |
| `ai-ingestion` | Files that an LLM will read. Hidden text, metadata payloads and Unicode smuggling block, and any prompt injection match goes to review |

```sh
filevet scan invoice.pdf --policy strict
filevet scan invoice.pdf --policy ./our-policy.yaml
```

Library users pass `policy=Policy.load("strict")`. The API uses `FILEVET_POLICY`.

## Format

The format is versioned. Its JSON schema is in [schema/policy.schema.json](schema/policy.schema.json), and `filevet schema policy` prints it.

```yaml
policy_version: 1
name: default
rules:
  - match: { severity: critical }
    action: block
  - match: { rule_id: "malware.*", severity: [high] }
    action: block
  - match: { rule_id: "integrity.*" }
    action: review
    when: { min_count: 2 }          # only when several signals combine
  - match: { rule_id: "format.iso20022_schema" }
    action: allow                    # data quality, not security
overrides:
  - match: { rule_id: "malware.pdf_active_content", evidence_contains: "/URI" }
    severity: low
default_action: pass_with_findings
```

- `match` takes `rule_id` (a glob or a list of globs), `severity` (one or a list) and `evidence_contains`. Every key given must match.
- `overrides` run first and change a finding's severity in the report. The first matching override wins.
- Each finding gets the action of the first rule it matches. A rule with `when.min_count` only counts when at least that many findings match it. Otherwise filevet moves on to the next rule.
- A finding that matches no rule gets `default_action`.
- The verdict is the strictest action across all findings. `allow` counts as `pass`. A file with no findings passes.

The report says which rule set the verdict:

```json
"decision": {
  "policy": "default",
  "verdict": "review",
  "rule": 2,
  "rule_ids": ["integrity.iban_not_allowlisted"],
  "reason": "rule 2 of policy default sets review for integrity.iban_not_allowlisted"
}
```

`rule` is the index in `rules`, or `null` when `default_action` decided.

## Testing a policy

```sh
make corpus                                    # writes the synthetic corpus to tmp-samples/corpus
filevet policy test strict --corpus tmp-samples/corpus
```

`policy test` scans every file in the directory once and shows its verdict under `default` and under the policy you give, with the rule that decided. Use it on your own sample files before rolling a policy out.

## Suppressions

A suppression silences one rule for one file, identified by its SHA-256. Every suppression needs a reason and an expiry date.

```yaml
suppressions:
  - rule_id: parser.csv_formula_injection
    sha256: 3f5a…   # the full 64-character hash of the file
    reason: Supplier export with HYPERLINK formulas, checked by the AP team (ticket FIN-123)
    expires: 2027-03-31
```

```sh
filevet scan export.csv --suppressions suppressions.yaml
```

Suppressed findings move to the report's `suppressed` list and don't count towards the verdict. An expired suppression is ignored and adds a warning to the report and to stderr.
