# FROST Threshold Signing for ZAP1 Anchors

## Problem

Single-key anchor broadcasting is a concentration risk. If the key is lost or compromised, anchor operations stop or become attacker-controlled. For a protocol that targets multiple independent operators, single-key control is a hard dependency on one party.

## Design: 2-of-3 Threshold Signing

### Threat model

- Key compromise: attacker gets one share, cannot sign alone
- Key loss: one share destroyed, remaining two can still anchor
- Operator unavailability: any two of three participants can anchor without the third
- Collusion: two participants can anchor without the third's consent (this is the 2-of-3 tradeoff - document it honestly)

### Key ceremony

- Use FROST (Flexible Round-Optimized Schnorr Threshold) per the FROST Internet-Draft (draft-irtf-cfrg-frost) and the Zcash FROST implementation in the frost-zcash crate
- Trusted dealer generation for initial setup (simpler than DKG for 3 participants)
- Each participant receives their share via an authenticated out-of-band channel
- Verification: each participant can verify their share against the group public key
- The group public key maps to a single Zcash unified address used as ANCHOR_TO_ADDRESS

### Signing flow

1. Initiator (any participant) proposes an anchor transaction: root hash, leaf count, target address
2. Two participants commit (FROST round 1): generate nonces, share commitments
3. Two participants sign (FROST round 2): produce signature shares
4. Coordinator aggregates shares into a valid Schnorr signature
5. Transaction broadcast via existing zingo-cli or future embedded tx builder
6. The signed transaction is indistinguishable from a single-signer Orchard transaction on-chain

### Coordinator role

- The coordinator is stateless - any participant can coordinate
- No trust required: the coordinator sees signature shares but cannot forge signatures without a valid share
- In practice: the host running auto_anchor.sh becomes the default coordinator, but any node with API access can initiate

### Recovery

- Lost share: the remaining two participants can still sign. Generate a new 2-of-3 setup with a fresh group key. Migrate ANCHOR_TO_ADDRESS.
- Compromised share: same as lost - rotate to a new group key. The old address remains valid for verification of historical anchors but stops receiving new ones.
- All shares lost: protocol halt. This is the catastrophic case. Mitigation: encrypted share backups in geographically separate locations.

### Migration path

1. Generate FROST key shares (3 participants, threshold 2)
2. Derive the group unified address
3. Update ANCHOR_TO_ADDRESS in config
4. Existing anchors remain valid - they reference Merkle roots, not signing keys
5. New anchors use the threshold address
6. No protocol version bump needed - the anchor memo format is unchanged
7. Operators verify the new address appears in anchor transactions

### What this does NOT cover

- DKG (distributed key generation) - overkill for 3 known participants, adds complexity without proportional benefit at this scale
- Re-sharing (changing the threshold or participant set without rotating the group key) - future work if the operator set grows
- Hardware security modules - nice to have, not blocking

## Dependencies

- frost-zcash crate (or frost-ed25519 with Zcash binding)
- Orchard spending key derivation from FROST group key
- zingo-cli or zcash-cli support for external signing (currently zingo-cli does not support FROST natively - this may require a custom tx builder)

## Open questions

1. Does zingo-cli support importing a FROST group spending key, or do we need a custom Orchard transaction builder?
2. Should the coordinator be a separate binary or integrated into zec-pay?
3. What is the minimum viable participant set for the first deployment? (Likely: operator + backup operator + cold storage)

## References

- FROST Internet-Draft: https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/
- Zcash FROST: https://github.com/ZcashFoundation/frost
- ZAP1 anchor format: ONCHAIN_PROTOCOL.md Section 11 (MERKLE_ROOT memo)
- Current anchor automation: auto_anchor.sh (host cron) and src/anchor.rs (in-container, currently disabled)
