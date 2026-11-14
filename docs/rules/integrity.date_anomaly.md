# integrity.date_anomaly

Severity: `medium`.

## What it means

A date can't be right: it doesn't exist (31.02.2026), a camt entry was booked more than 7 days after its value date, it was booked outside the statement period or after the message was created, or the message was created in the future.

## Why it matters for finance files

Edited dates are a common slip in forged statements: the forger changes a day without checking the calendar, or moves an entry into a period it doesn't belong to.

## How to fix the file

Compare the dates with the issuer's records.

## False positives

Back-valued bookings older than a week, and statements built by systems whose clocks are wrong.

## References

- [ISO 20022 message definitions](https://www.iso20022.org/iso-20022-message-definitions)
