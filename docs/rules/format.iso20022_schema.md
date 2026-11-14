# format.iso20022_schema

Severity: `low`. `format.iso20022_schema_unavailable` is `info`.

## What it means

The ISO 20022 message (camt.052, camt.053, camt.054, pain.001, pain.008 or pacs.008) doesn't validate against the XSD for its message version. The finding gives the XPath and the reason, up to ten per file.

`format.iso20022_schema_unavailable` means no XSD for that message version was found, so the message wasn't validated.

## Why it matters for finance files

A schema violation is a data-quality problem. A message that breaks its schema will be rejected or misread by your treasury system, and an unexpected change in structure can point to a manual edit.

## Setup

filevet looks for `<message>.xsd`, for example `camt.053.001.08.xsd`, in the directory named by `FILEVET_XSD_DIR`, or in `src/filevet/analyzers/format/xsd/` when the variable isn't set. No XSDs ship with filevet yet. Download the XSDs for the versions you receive from the ISO 20022 message catalogue. Schemas are loaded with remote access off, so imports must be local files in the same directory.

## False positives

Banks often use their own variant of a message, with extra elements or tighter rules. Validate against the schema your bank publishes if it differs from the standard one.
