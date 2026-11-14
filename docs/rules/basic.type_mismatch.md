# basic.type_mismatch

Severity: `critical` when an executable is named like a document, `medium` for other mismatches.

## What it means

The file extension says one type and the content is another. filevet reads the first bytes of the file to find its real type and compares that with the extension.

## Why it matters for finance files

`invoice.pdf` that is really a Windows program is one of the oldest tricks in phishing, and it still works because people trust the extension their mail client shows. A smaller mismatch, such as a CSV that is really HTML, often means the file was exported from the wrong system or edited by hand on the way.

## How to fix the file

Ask the sender for a file saved in the format it claims to be. Don't rename it and open it anyway.

## False positives

Some systems label files carelessly, for example a `.xls` that is really CSV or HTML. Those come out as `medium` and need a quick look, not a block.
