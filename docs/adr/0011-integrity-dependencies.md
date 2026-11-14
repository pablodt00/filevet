# 11. Verify PDF signatures with pyHanko and read context files with PyYAML

Date: 2026-11-14

## Status

Accepted

## Context

Phase 2 adds integrity checks: PDF tampering, financial data consistency and an optional allow list of expected values. Most of it fits the approach of [ADR 10](0010-format-parsing-dependencies.md). PDF revisions, text, fonts and drawing operations are read from the raw objects with the standard library, and IBANs, BICs, amounts and dates come from a small extractor in `core/extract_finance.py`. IBAN checking is about 15 lines (a length table and mod-97), so `schwifty` isn't needed.

Two things don't fit:

- Verifying a PDF signature means parsing CMS, checking the digest over the signed byte ranges, validating the certificate path and working out what changed after signing. Writing that ourselves would be easy to get subtly wrong, and a wrong answer here tells people a forged document is fine.
- The `--context` file is YAML, as the issue asks. The standard library has no YAML parser.

## Decision

We add two runtime dependencies:

| Package | License | Used for |
| --- | --- | --- |
| `pyhanko` | MIT | `integrity.pdf_digital_signature`: signature, coverage and modification checks |
| `pyyaml` | MIT | Reading the `--context` file with `yaml.safe_load` |

pyHanko brings `pyhanko-certvalidator`, `asn1crypto`, `cryptography`, `cffi`, `lxml`, `oscrypto`, `aiohttp` and their dependencies. Their licenses are MIT, BSD, Apache-2.0, PSF-2.0, MPL-2.0 and MIT-0. We add `MIT-0` (cffi) and the compound expressions `Apache-2.0 AND MIT` (aiohttp) and `Apache-2.0 OR BSD-3-Clause` (cryptography) to the license gate in `.github/workflows/security.yml`.

The analyzer always builds its `ValidationContext` with an explicit, possibly empty list of trust roots and `allow_fetching=False`. It never falls back to the system trust store and never fetches CRLs, OCSP responses or certificates. Trust roots come only from the `trust_roots` list in the context file.

## Consequences

The install and the Docker image grow by roughly the size of `cryptography` and `lxml`. `aiohttp` is installed but never used, because fetching is always off. Without trust roots every signature is reported as untrusted (`low`), so users who want `info` for valid signatures have to supply their CA certificates. Revocation isn't checked. Issue #9 asks for online revocation checks as an opt-in. We leave them out because filevet makes no network calls, and adding them would need its own ADR.
