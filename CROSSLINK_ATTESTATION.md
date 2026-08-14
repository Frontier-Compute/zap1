# Crosslink attestation design note

Status: experimental application layer

ZAP1 implements three legacy staking claim shapes:

| Type | Name | Committed fields |
| --- | --- | --- |
| `0x0A` | `STAKING_DEPOSIT` | wallet field, amount in zatoshis, validator ID |
| `0x0B` | `STAKING_WITHDRAW` | wallet field, amount in zatoshis, validator ID |
| `0x0C` | `STAKING_REWARD` | wallet field, amount in zatoshis, epoch |

These are operator-issued claims. They do not read Crosslink consensus state,
validate a stake transaction, prove validator performance, or affect finality.
Their current byte layouts are fixed by the implementation and test vectors,
but their higher-level Crosslink meaning remains experimental.

Bytes `0x30` to `0x3F` are unassigned. Earlier drafts proposed validator
registration, exit, slashing, delegation, checkpoint, uptime, and epoch-summary
events in that range. None is active or reserved. Allocation requires a
versioned registry update after the relevant consensus objects and encodings
are stable.

The useful boundary is narrow: an operator can commit a private application
record, disclose its preimage later, and let a verifier recompute inclusion in
a supplied ZAP1 root. That is not a consensus attestation.
