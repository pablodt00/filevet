# parser.polyglot

Severity: `medium`

## What it means

The file is valid as more than one type, for example a PDF with a ZIP appended, an image with an archive after its end, or a PDF that starts after some other content instead of at byte 0. The hidden part is extracted and scanned as its own file.

## Why it matters for finance files

A PDF viewer and an unzip tool see different files in the same bytes. An attacker uses that to show a reviewer a clean invoice while the system that processes it reads the hidden part.

## How to fix the file

Ask for the document again, exported directly from the source system.

## False positives

Self-extracting archives are polyglots by design. Some scanners and copiers also append data to images.
