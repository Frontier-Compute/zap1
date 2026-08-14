# Zcash agent commitments

Status: active base types, wider architecture is a proposal

ZAP1 can commit an operator's claims about an agent without putting action
preimages in a Zcash memo. The active registry has three agent types:

| Type | Name | Committed fields |
| --- | --- | --- |
| `0x40` | `AGENT_REGISTER` | agent ID, public-key hash, model hash, policy hash |
| `0x41` | `AGENT_POLICY` | agent ID, policy version, rules hash |
| `0x42` | `AGENT_ACTION` | agent ID, action type, input hash, output hash |

The write API accepts these three types. Bytes `0x43` through `0x4F` are
unassigned. Names such as `AGENT_PAYMENT`, `AGENT_DECISION`, and
`AGENT_DELEGATE` are design sketches, not registry entries.

## What the receipt says

A disclosed preimage can be recomputed to a leaf. A Merkle proof can then show
that the leaf is consistent with a supplied root. The operator records a Zcash
transaction reference for that root.

That chain establishes commitment consistency. It does not establish:

- that the named model actually ran
- that a key belongs to an agent
- that an action happened
- that an action was authorized or policy-compliant
- that all actions were recorded
- that a payment occurred
- that an encrypted Orchard memo contains the supplied root

Those claims need their own signed runtime receipts, complete logging boundary,
transaction evidence, or safe memo opening. ZAP1 does not manufacture them.

## Hash inputs

The active formulas are in `ONCHAIN_PROTOCOL.md` and
`docs/EVENT_SCHEMA.md`. Every variable-length UTF-8 field is prefixed by its
two-byte big-endian byte length. Integers are big-endian.

The fields named `model_hash`, `policy_hash`, `input_hash`, and
`output_hash` are operator-submitted strings in the current API. Their names
do not make them independently authenticated measurements.

## Intended stack

An operator can place ZAP1 beside an agent runtime and an Orchard wallet:

```text
agent runtime
  -> operator issues AGENT_REGISTER, AGENT_POLICY, or AGENT_ACTION
  -> ZAP1 commits the submitted fields to its Merkle tree
  -> verifier checks a disclosed preimage and inclusion proof

Orchard wallet
  -> handles value separately
```

The separation matters. A ZAP1 receipt does not inspect wallet state or inherit
wallet authorization. Orchard shields the transaction graph, while any
disclosed ZAP1 preimages remain visible to the recipient.

## Integration state

- active ZAP1 agent types: `0x40` to `0x42`
- wider agent family: unassigned proposal
- OpenClaw wiring: separate integration work, not proof of adoption
- Zodl Android PR 2173: closed unmerged on 2026-07-29
- Zodl iOS PR 1680: closed unmerged on 2026-07-29
- iOS issue 1670: open at the 2026-08-13 cutoff

This document is an architecture boundary, not evidence that an external agent
runtime, wallet, DAO, or Zcash application adopted the design.
