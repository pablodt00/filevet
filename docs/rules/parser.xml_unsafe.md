# parser.xml_unsafe

Severity: `critical` for external entities or DTDs (`SYSTEM`/`PUBLIC`), parameter entities and entities that expand other entities. `high` for any other DTD in an ISO 20022 message and for XInclude. `medium` for a DTD in other XML and for nesting deeper than 64 levels.

## What it means

The XML contains a document type declaration or other features that make parsers fetch files, call out to the network or blow up in memory.

## Why it matters for finance files

camt.053 statements and pain.001 payment files go straight into treasury and ERP systems. A parser that resolves entities can be made to read local files and send them out (XXE), or to exhaust its memory with a few kilobytes of input. An ISO 20022 message has no legitimate reason to carry a DTD, so any DTD in one is at least `high`.

## How to fix the file

Ask the sender to export the message again from their banking or payment system, without a DTD. Check that your own parsers turn off DTDs and entity resolution.

## False positives

Some older non-payment XML formats still ship with an internal DTD. Outside ISO 20022 that is only `medium`.

## References

- [CWE-611](https://cwe.mitre.org/data/definitions/611.html), [CWE-776](https://cwe.mitre.org/data/definitions/776.html)
- [OWASP: XXE](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing)
