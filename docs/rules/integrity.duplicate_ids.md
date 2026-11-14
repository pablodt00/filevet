# integrity.duplicate_ids

Severity: `medium` in payment files (pain, pacs). `low` in statements and notifications (camt).

## What it means

An identifier that should be unique, such as `MsgId`, `PmtInfId`, `InstrId`, `EndToEndId`, `TxId`, `NtryRef` or `AcctSvcrRef`, appears more than once at the same place in an ISO 20022 message. `NOTPROVIDED` is ignored.

## Why it matters for finance files

A copied transaction in a payment file pays the same beneficiary twice. In statements, duplicated references can hide an entry that was copied to change the balance.

## How to fix the file

Rebuild the payment file from its source. Ask the bank about duplicated statement entries.

## False positives

Some systems reuse an end-to-end ID for all transactions of a batch.

## References

- [ISO 20022 message definitions](https://www.iso20022.org/iso-20022-message-definitions)
