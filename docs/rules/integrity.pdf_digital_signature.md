# integrity.pdf_digital_signature

Severity: `high` when the signature is invalid or unreadable, or when content was added after signing. `low` when the certificate isn't trusted or has expired, or when only form fields or annotations were added after signing. `info` when the signature is valid, trusted and covers the whole file.

## What it means

The PDF carries a digital signature, and filevet checked it with pyHanko. The evidence names the signer from the certificate.

## Why it matters for finance files

A signature proves that the signed bytes haven't changed since signing. A PDF that still shows a valid signature while carrying content added afterwards is a known way to pass off an edited document as sealed.

## How to fix the file

For `high`, don't trust the document and ask the issuer for a new signed copy. To turn untrusted signatures into `info`, add your CA certificates under `trust_roots` in the context file.

## False positives

filevet trusts no certificates by default, so every valid signature starts as `low`. It never fetches revocation data, so a revoked certificate isn't caught.

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [pyHanko](https://github.com/MatthiasValvekens/pyHanko)
