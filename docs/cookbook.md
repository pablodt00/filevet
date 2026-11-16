# Policy cookbook

Recipes for common needs. Each one is a complete policy file you can pass to `--policy`, to `Policy.load()` or to `FILEVET_POLICY`. The format is described in [Policies](policies.md), and `filevet schema policy` prints its JSON schema.

Try a policy on sample files before rolling it out:

```sh
make corpus
filevet policy test ./our-policy.yaml --corpus tmp-samples/corpus
```

## Start from the default

The built-in `default` policy is short. Copy it and change what you need:

```yaml
policy_version: 1
name: ours
rules:
  - match: { severity: [critical, high] }
    action: block
  - match: { rule_id: format.iso20022_schema }
    action: allow
  - match: { severity: medium }
    action: review
default_action: pass_with_findings
```

Rules are checked in order and the first match wins, so put specific rules above general ones.

## Block a rule whatever its severity

Macros have no place in an invoice. Block every `malware.office_macros` finding, including the medium ones for macros that don't auto-run:

```yaml
policy_version: 1
name: no-macros
rules:
  - match: { rule_id: malware.office_macros }
    action: block
  - match: { severity: [critical, high] }
    action: block
  - match: { severity: medium }
    action: review
default_action: pass_with_findings
```

## Lower the severity of plain links

A PDF with a `/URI` link is common and rarely dangerous. An override changes the severity in the report before the rules run:

```yaml
policy_version: 1
name: links-are-low
overrides:
  - match: { rule_id: malware.pdf_active_content, evidence_contains: "/URI" }
    severity: low
rules:
  - match: { severity: [critical, high] }
    action: block
  - match: { severity: medium }
    action: review
default_action: pass_with_findings
```

## Review only when tampering signals combine

One integrity signal on its own is often innocent: a statement that was saved twice, or a date at the edge of a period. Send a file to review only when two or more appear together:

```yaml
policy_version: 1
name: combined-integrity
rules:
  - match: { severity: [critical, high] }
    action: block
  - match: { rule_id: "integrity.*" }
    action: review
    when: { min_count: 2 }
  - match: { rule_id: "integrity.*" }
    action: pass_with_findings
  - match: { severity: medium }
    action: review
default_action: pass_with_findings
```

The third rule catches the single integrity findings that the second one skipped, so they don't fall through to the medium rule.

## Never pass a file that wasn't fully scanned

When an analyzer crashes or times out, or a recursion limit stops the scan, filevet adds `pipeline.analyzer_error` or `pipeline.limit_exceeded`. Both are `high`, so every policy that blocks `high` already blocks them. If your policy is more lenient, keep a rule for them at the top:

```yaml
policy_version: 1
name: lenient
rules:
  - match: { rule_id: "pipeline.*" }
    action: block
  - match: { severity: critical }
    action: block
  - match: { severity: high }
    action: review
default_action: pass_with_findings
```

## Roll out in review-only mode

While you learn what your traffic looks like, block only `critical` findings and send everything else to review:

```yaml
policy_version: 1
name: shadow
rules:
  - match: { severity: critical }
    action: block
  - match: { severity: [high, medium, low] }
    action: review
default_action: pass_with_findings
```

## Silence one rule for one known file

Use a suppression instead of a policy change when a single file is the problem. It names the file's SHA-256, gives a reason and expires:

```yaml
suppressions:
  - rule_id: parser.csv_formula_injection
    sha256: 50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c
    reason: Supplier export with HYPERLINK formulas, checked by the AP team
    expires: 2027-03-31
```

```sh
filevet scan export.csv --suppressions suppressions.yaml
```
