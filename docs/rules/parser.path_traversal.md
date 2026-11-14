# parser.path_traversal

Severity: `high`

## What it means

An archive entry would land outside the folder it is extracted to. The name contains `..`, starts with `/` or `\`, starts with a drive letter like `C:`, or the entry is a symbolic link. Symbolic links are not extracted.

## Why it matters for finance files

Tools that unpack statements or invoice batches automatically can be made to overwrite files elsewhere on the server, such as a cron job or a configuration file.

## How to fix the file

Ask for an archive with plain relative names. Make sure your own extraction code checks names before writing.

## False positives

Archives made by careless tools sometimes store absolute paths. They still need to be fixed before automated processing.

## References

- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
