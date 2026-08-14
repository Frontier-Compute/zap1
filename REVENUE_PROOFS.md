# Revenue attestation boundaries

Status: design note

ZAP1 records operator claims as Merkle leaves. A valid proof shows that a leaf
is included under a supplied root. It does not prove that revenue was earned,
that a payment settled, or that the amount and counterparty are true.

## Implemented event shapes

| Event | Committed fields | Boundary |
| --- | --- | --- |
| `HOSTING_PAYMENT` (`0x05`) | serial number, month, year | No wallet or amount is committed by this event shape. |
| `STAKING_REWARD` (`0x0C`) | wallet field, amount in zatoshis, epoch | Implemented as an experimental operator claim. It is not Crosslink consensus evidence. |

`POOL_PAYOUT`, `POOL_HASHRATE`, and the `0x20` to `0x2F` mining-pool family are
not assigned in the active registry and are not accepted by the API.

## What a verifier can check

Given a leaf hash, proof path, leaf count, and root, a verifier can recompute
Merkle inclusion. If the operator discloses the complete event preimage, the
verifier can also recompute the leaf. A txid proves that a transaction exists at
a height. It does not reveal or authenticate an encrypted Orchard memo.

The `zap1_export` tool builds operator-selected disclosure packages. It does
not discover missing events, prove completeness, validate invoices, or prove
the off-chain truth of disclosed fields.

## Current ruling

ZAP1 can support a payment or revenue claim when the claimant also supplies the
complete preimage and independent settlement evidence. ZAP1 alone is not proof
of income, payment, reserves, tax status, or receivables. No grant payment or
commercial revenue is evidenced by this document.
