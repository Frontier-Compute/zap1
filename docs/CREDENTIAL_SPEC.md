# ZAP1 Credential Derivation Spec v0.1 (draft)

Credentials are privacy-preserving claims derived from ZAP1 attestation history. A credential proves a fact about a participant without revealing their identity or full history.

## Model

A credential is a tuple:

```
(claim_type, claim_value, proof_bundle, anchor_txid, anchor_height)
```

The proof bundle contains the Merkle proof(s) that back the claim. The anchor txid links the proof to a specific on-chain commitment. The verifier checks the proof against the anchored root without learning anything else about the participant.

## Credential types

### good_standing_90d

Claim: "This wallet has been an active participant for at least 90 days with no gaps in hosting payments."

Derivation:
1. Find the PROGRAM_ENTRY leaf for the wallet hash
2. Find HOSTING_PAYMENT leaves covering at least 3 consecutive months
3. Verify no EXIT leaf exists for this wallet
4. Bundle the Merkle proofs for all referenced leaves

Proof structure:
```json
{
  "credential": "good_standing_90d",
  "wallet_hash": "...",
  "entry_leaf": "...",
  "payment_leaves": ["...", "...", "..."],
  "proofs": [...],
  "anchor_txid": "...",
  "anchor_height": 3288022
}
```

Verifier checks:
- Each leaf hash is in the Merkle tree under the anchored root
- Entry leaf predates the first payment leaf by at least 90 days
- Payment leaves cover consecutive months

Limitation: current proof system provides inclusion proofs only. "No EXIT leaf exists" cannot be proven cryptographically today. The verifier must either trust the operator's API for non-inclusion, or a future non-inclusion proof mechanism must be added. This is an open design problem.

### deployed_asset_verified

Claim: "Hardware serial X is deployed at a facility and owned by this wallet."

Derivation:
1. Find the OWNERSHIP_ATTEST leaf linking wallet hash to serial
2. Find the DEPLOYMENT leaf for the serial
3. Bundle both Merkle proofs

Proof structure:
```json
{
  "credential": "deployed_asset_verified",
  "wallet_hash": "...",
  "serial_hash": "...",
  "ownership_leaf": "...",
  "deployment_leaf": "...",
  "proofs": [...],
  "anchor_txid": "...",
  "anchor_height": 3288022
}
```

Verifier checks:
- Both leaves are in the tree under the anchored root
- The serial hash matches across both leaves

Limitation: "no TRANSFER or EXIT after deployment" requires non-inclusion proofs, which are not implemented. Same constraint as good_standing_90d. Verifier must trust API for negative claims until a non-inclusion mechanism ships.

### payments_current

Claim: "This participant's hosting payments are current as of the latest anchor."

Derivation:
1. Find the most recent HOSTING_PAYMENT leaf for the serial
2. Verify the month/year matches the current or previous calendar month
3. Bundle the Merkle proof

Proof structure:
```json
{
  "credential": "payments_current",
  "serial_hash": "...",
  "payment_leaf": "...",
  "month": 3,
  "year": 2026,
  "proof": [...],
  "anchor_txid": "...",
  "anchor_height": 3288022
}
```

Verifier checks:
- Payment leaf is in the tree under the anchored root

Limitation: month/year are hashed into the leaf payload but not persisted separately in the current DB schema or proof bundle. The verifier cannot extract month/year from the leaf hash alone. This requires either: (a) extending proof bundles to include plaintext witness data alongside the hash, or (b) the prover supplies the preimage fields and the verifier recomputes the hash. Option (b) is the cleaner path and will be implemented in zap1-schema.
- The anchor is recent enough to be meaningful (configurable staleness threshold)

## Privacy properties

- Credential proofs reveal only the specific leaves needed for the claim
- The wallet hash is a derived value, not the address itself
- The verifier learns the claim is true but not the full participant history
- Other leaves in the tree remain hidden
- The Merkle proof path reveals sibling hashes, which are opaque without context

## Threat model

- **Replay:** A credential is bound to a specific anchor. Verifiers should check anchor freshness.
- **Stale claims:** A participant could present an old credential after exiting. Verifiers should require recent anchors.
- **False negatives:** If a leaf is not yet anchored, the credential cannot be derived. Anchor frequency bounds the latency.
- **Selective reveal:** A participant with multiple assets can choose which ones to prove. This is a feature, not a bug.

## Implementation status

This spec is a design document. The derivation rules and proof structures are defined but not yet implemented in zap1-verify or zap1-js. Implementation is a Phase 2 deliverable.

## Relationship to selective disclosure

Credentials are one-directional proofs: the participant proves a fact to a counterparty. Selective disclosure (viewing key export, audit packages) is a separate workflow where the participant grants read access to a subset of their encrypted history. Both are useful. Credentials are simpler and require no key sharing.
