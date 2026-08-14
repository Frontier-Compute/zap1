# Sovereign agent commitments

Status: `0x40` to `0x42` implemented; `0x43` to `0x4F` unassigned

ZAP1 can commit operator-issued claims about an agent. The commitment is useful
when the operator later discloses the exact fields, but it is not an oracle for
model identity, execution, authorization, policy compliance, payments, or
completeness.

## Active registry

| Type | Name | Meaning of the submitted claim |
| --- | --- | --- |
| `0x40` | `AGENT_REGISTER` | operator associated an agent ID with key, model, and policy strings |
| `0x41` | `AGENT_POLICY` | operator associated an agent ID and version with a rules string |
| `0x42` | `AGENT_ACTION` | operator associated an agent ID and action type with input and output strings |

These are the only active agent event types. The API rejects `0x43` through
`0x4F`.

## Exact active hash construction

All variable-length values below are UTF-8 bytes prefixed by a two-byte
big-endian byte length. `policy_version_be` is a four-byte big-endian integer.
The event type byte is included before the fields. BLAKE2b-256 uses the
16-byte personalization `NordicShield_` padded with zero bytes.

```text
AGENT_REGISTER =
  BLAKE2b_32(
    0x40 ||
    len(agent_id) || agent_id ||
    len(pubkey_hash) || pubkey_hash ||
    len(model_hash) || model_hash ||
    len(policy_hash) || policy_hash
  )

AGENT_POLICY =
  BLAKE2b_32(
    0x41 ||
    len(agent_id) || agent_id ||
    policy_version_be ||
    len(rules_hash) || rules_hash
  )

AGENT_ACTION =
  BLAKE2b_32(
    0x42 ||
    len(agent_id) || agent_id ||
    len(action_type) || action_type ||
    len(input_hash) || input_hash ||
    len(output_hash) || output_hash
  )
```

The `*_hash` names are historical API names. The current implementation
length-prefixes the submitted UTF-8 strings. It does not require them to decode
to 32 bytes and does not independently derive them.

## Verification boundary

Given the disclosed fields, a verifier can:

1. recompute the leaf hash
2. verify the Merkle path under the declared scheme and leaf count
3. confirm that the result equals the supplied root
4. confirm that the recorded txid exists at the recorded height

The public txid does not reveal an encrypted Orchard memo. A separate safe
opening is required to bind the supplied root to that memo.

Even with that opening, the receipt proves only that the operator committed the
fields. It does not prove:

- the named model or key controlled the runtime
- the claimed tool call or output occurred
- the action complied with the disclosed policy
- the event preceded or followed an off-system event
- every relevant action was captured
- a payment was sent, received, or settled
- a legal, audit, or regulatory conclusion

Signed runtime receipts, authenticated measurements, complete log admission,
and payment-source evidence remain separate layers.

## Policy use

An operator can commit a policy hash before submitting action claims. Later
disclosure can show that a policy preimage and selected action preimages match
their leaves. That can support review of those disclosed records.

It cannot prove that the runtime enforced the policy, that omitted actions do
not exist, or that the policy was the only policy in force. ZAP1 currently has
inclusion proofs, not a completeness or non-inclusion system.

## Privacy boundary

Orchard can shield wallet transactions. ZAP1 stores event fields off-chain and
commits hashes to its Merkle tree. Public event feeds and proof bundles withhold
stored subject preimages in the hardened implementation. The
`/miner/{wallet_hash}` route family, `/lifecycle/{wallet_hash}`, and full
`GET /invoice/{id}` JSON route require operator bearer authentication. Payment
pages use UUID invoice URLs as bearer capabilities and can disclose a payment
request to anyone who obtains the URL.

Hashing low-entropy identifiers does not make them anonymous. Integrators must
derive domain-separated pseudonyms before submission. Authentication does not
make a low-entropy identifier anonymous. A disclosed preimage is visible to its
recipient.

## Proposed extensions

The following names are design slots only. They are not allocated registry
entries, accepted API types, deployed semantics, or evidence of adoption.

| Proposed byte | Proposed name | Intended claim |
| --- | --- | --- |
| `0x43` | `AGENT_PAYMENT` | payment metadata commitment |
| `0x44` | `AGENT_DECISION` | context and decision commitment |
| `0x45` | `AGENT_CHECKPOINT` | state checkpoint commitment |
| `0x46` | `AGENT_DELEGATE` | delegation scope commitment |
| `0x47` | `AGENT_REVOKE` | revocation record commitment |
| `0x48` | `AGENT_INFERENCE` | inference and external-proof commitment |
| `0x49` | `AGENT_AUDIT` | audit-root commitment |

Bytes `0x4A` through `0x4F` are also unassigned. Allocating any extension
requires a versioned registry change, exact length-prefixed formulas, test
vectors, API support, and verifier policy. A proposed payment leaf would still
need primary transaction evidence. A proposed inference proof commitment would
still need the external proof and its verifier.

## Cross-chain boundary

A type-agnostic Solidity Merkle verifier can check a path against a root that
its own registry accepts. That does not authenticate the root as Zcash state,
interpret an agent event, prove a payment, or prove policy compliance. Those
bridges and policies are separate trust boundaries.

## Adoption boundary

The active code and vectors demonstrate a ZAP1 implementation profile. This
document does not establish independent production use by an agent framework,
wallet, DAO, auditor, or counterparty.
