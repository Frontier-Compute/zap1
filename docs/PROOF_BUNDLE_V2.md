# Proof Bundle v2 Format

Canonical envelope for ZAP1 attestation proofs. Used by zap1_audit, zap1_export, and consumer applications.

## Single proof bundle

Returned by `/verify/{hash}/proof.json` and consumed by `zap1_audit --bundle`.

```json
{
  "protocol": "ZAP1",
  "version": "2",
  "leaf": {
    "hash": "075b00df...",
    "event_type": "PROGRAM_ENTRY",
    "wallet_hash": "e2e_wallet_20260327",
    "serial_number": null,
    "created_at": "2026-03-27 03:28:57"
  },
  "proof": [
    { "hash": "de62554a...", "position": "right" }
  ],
  "root": {
    "hash": "024e3651...",
    "leaf_count": 2,
    "created_at": "2026-03-27T03:29:26Z"
  },
  "anchor": {
    "txid": "98e1d6a0...",
    "height": 3286631
  }
}
```

## Export package

Returned by `zap1_export` and consumed by `zap1_audit --export`.

```json
{
  "protocol": "ZAP1",
  "generated_at": "2026-03-30T22:53:11Z",
  "scope": "wallet=e2e_wallet_2",
  "proofs": [
    {
      "leaf_hash": "075b00df...",
      "event_type": "PROGRAM_ENTRY",
      "wallet_hash": "e2e_wallet_20260327",
      "serial_number": null,
      "created_at": "2026-03-27 03:28:57",
      "proof_steps": [ { "hash": "...", "position": "right" } ],
      "root": "024e3651...",
      "anchor_txid": "98e1d6a0...",
      "anchor_height": 3286631,
      "witness": {
        "wallet_hash_preimage": "e2e_wallet_20260327",
        "serial_number": null,
        "hash_function": "BLAKE2b-256",
        "personalization": "NordicShield_",
        "recompute": "hash(type_byte || length_prefixed_fields) with NordicShield_ personalization"
      }
    }
  ],
  "verification": {
    "sdk": "zap1-verify",
    "crate_url": "https://crates.io/crates/zap1-verify",
    "memo_decoder": "https://crates.io/crates/zcash-memo-decode",
    "procedure": [
      "for each proof entry, verify the Merkle proof from leaf_hash to root",
      "use BLAKE2b-256 with NordicShield_MRK personalization for tree nodes",
      "confirm the root matches the anchor_txid on Zcash mainnet",
      "confirm the anchor_txid is mined at anchor_height",
      "optionally use zap1_schema --emit-witness to verify preimage fields"
    ]
  }
}
```

## Profiles

`zap1_export --profile <name>` selects event types to include:

| Profile | Events included |
|---|---|
| auditor | PROGRAM_ENTRY, OWNERSHIP_ATTEST, HOSTING_PAYMENT, SHIELD_RENEWAL, CONTRACT_ANCHOR, EXIT |
| counterparty | PROGRAM_ENTRY, OWNERSHIP_ATTEST, DEPLOYMENT |
| member | PROGRAM_ENTRY, OWNERSHIP_ATTEST, HOSTING_PAYMENT, SHIELD_RENEWAL |
| regulator | All lifecycle events |

## Verification tools

| Tool | Input | Command |
|---|---|---|
| zap1_audit | single proof bundle | `zap1_audit --bundle proof.json` |
| zap1_audit | export package | `zap1_audit --export package.json` |
| zap1_audit | proof URL | `zap1_audit --bundle-url https://...` |
| zap1_schema | witness validation | `zap1_schema --witness events.json --emit-witness` |
| check.sh | full stack check | `bash scripts/check.sh` |

## Compatibility

v1 proof bundles (missing `version` field) are accepted by all tools. The version field distinguishes formats when both are in circulation.
