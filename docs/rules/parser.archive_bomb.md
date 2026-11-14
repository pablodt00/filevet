# parser.archive_bomb

Severity: `high`, or `critical` for overlapping entries and archives that contain themselves.

## What it means

The archive is built to expand far beyond its size or to loop. filevet checks before it decompresses anything:

- An entry over 1 MB that is more than 100 times smaller compressed.
- An entry that would expand past the input size limit or the scan's total expansion budget.
- More entries than the child limit (1000 by default).
- Archives nested more than three levels deep.
- Entries whose data overlaps, a trick that lets one small file expand many times.
- An entry that is a copy of the archive itself (a quine).

The entry that trips a check is not extracted.

## Why it matters for finance files

A decompression bomb can take down the intake service or the antivirus scanner behind it, and an archive that can't be fully scanned is a good place to hide something.

## How to fix the file

Ask for the documents without nested archives, or as separate attachments.

## False positives

Very repetitive exports, such as a large CSV with long blank columns, can compress past 100 to 1. Check what the entry is before blocking the sender.
