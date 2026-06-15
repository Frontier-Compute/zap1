# ZAP1 Crosslink Integration

How ZAP1 attestation works with Crosslink proof-of-stake validators.

## Background

Crosslink introduces proof-of-stake to Zcash. Validators lock ZEC as collateral, produce blocks, and earn rewards. Three lifecycle events need attestation:

1. A validator deposits stake
2. A validator withdraws stake
3. A validator receives a reward

ZAP1 already has event types for these: STAKING_DEPOSIT (0x0A), STAKING_WITHDRAW (0x0B), STAKING_REWARD (0x0C). They're reserved in the spec and implemented in the API as of v3.0.0.

## Event types

### STAKING_DEPOSIT (0x0A)

Records a stake lock. Hash construction:

```
leaf = BLAKE2b-256(
  personalization: "NordicShield_",
  input: 0x0A || len(wallet_hash) || wallet_hash || amount_zat(8 bytes) || len(validator_id) || validator_id
)
```

API:
```json
POST /event
{
  "event_type": "STAKING_DEPOSIT",
  "wallet_hash": "validator_public_key_hash",
  "amount_zat": 100000000,
  "validator_id": "crosslink-validator-001"
}
```

### STAKING_WITHDRAW (0x0B)

Records a stake unlock. Same hash construction as deposit with type byte 0x0B.

API:
```json
POST /event
{
  "event_type": "STAKING_WITHDRAW",
  "wallet_hash": "validator_public_key_hash",
  "amount_zat": 100000000,
  "validator_id": "crosslink-validator-001"
}
```

### STAKING_REWARD (0x0C)

Records a block reward. Hash construction:

```
leaf = BLAKE2b-256(
  personalization: "NordicShield_",
  input: 0x0C || len(wallet_hash) || wallet_hash || amount_zat(8 bytes) || epoch(4 bytes)
)
```

API:
```json
POST /event
{
  "event_type": "STAKING_REWARD",
  "wallet_hash": "validator_public_key_hash",
  "amount_zat": 312500,
  "epoch": 1
}
```

## Why attestation matters for validators

Staking creates accountability. A validator that deposits 10 ZEC, runs for 6 months, and earns rewards has a provable track record. The Merkle tree records:

- When they deposited (timestamp in leaf)
- How much they deposited (amount in hash)
- Every reward they earned (one leaf per epoch)
- When they withdrew (if ever)

This history is anchored to Zcash mainnet. Anyone with the leaf hashes can verify the full timeline without trusting the validator or any operator.

## Integration pattern

A Crosslink validator runs a ZAP1 instance alongside their validator node. On each lifecycle event:

1. Validator software calls `POST /event` with the event type and parameters
2. ZAP1 hashes the event and adds a leaf to the Merkle tree
3. When the threshold is reached, the tree root is anchored on-chain
4. The validator publishes their leaf hashes as proof of their staking history

This is the same pattern used for mining deployments today. The event types change, the protocol stays the same.

## Verification

```bash
# Check a staking deposit proof
curl -s https://your-zap1-instance/verify/LEAF_HASH/check

# Get the full Merkle proof bundle
curl -s https://your-zap1-instance/verify/LEAF_HASH/proof.json

# Verify locally with the SDK
cargo add zap1-verify
```

The `zap1-verify` crate walks the Merkle proof path from leaf to root and confirms the root matches an on-chain anchor. Works in Rust, WASM (browser), and via the REST API.

## What this does NOT do

- Does not interact with Crosslink consensus. ZAP1 is application-layer, not consensus-layer.
- Does not validate that a staking deposit actually happened on-chain. It attests that the operator recorded it. Trust in the attestation depends on trust in the operator.
- Does not replace slashing. Crosslink will have its own slashing mechanism. ZAP1 provides an independent audit trail alongside it.

## Timeline

The staking event types are implemented and available in the API now. They can be tested against the live stack at api.frontiercompute.cash. When Crosslink launches, validators can start attesting immediately - no protocol changes needed.
