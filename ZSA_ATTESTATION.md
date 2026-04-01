# ZSA Attestation Event Types

Status: Draft  
Date: 2026-04-01  
Depends on: Zcash Shielded Assets (ZSA) protocol activation

## Overview

When Zcash Shielded Assets ship, asset issuers will need a way to attest properties of their assets on-chain without revealing holder identities or transaction details. ZAP1 provides this layer: structured attestation events committed to a Merkle tree and anchored to Zcash via shielded memos.

This document defines ZAP1 event types for the ZSA lifecycle, extending the registry into the `0x10`-`0x1F` range. These types are reserved and will activate when the ZSA protocol is deployed on mainnet.

## Proposed Event Types

| Type | Name | Trigger | Status |
|------|------|---------|--------|
| `0x10` | `ASSET_ISSUE` | New asset type created by an issuer | Reserved |
| `0x11` | `ASSET_MINT` | New units minted for an existing asset | Reserved |
| `0x12` | `ASSET_BURN` | Units permanently removed from circulation | Reserved |
| `0x13` | `ASSET_FREEZE` | Asset transfers suspended by issuer | Reserved |
| `0x14` | `ASSET_UNFREEZE` | Asset transfers resumed | Reserved |
| `0x15` | `ASSET_METADATA` | Metadata commitment updated (name, symbol, URI) | Reserved |
| `0x16` | `ASSET_COMPLIANCE` | Compliance attestation (KYC/AML status, jurisdiction) | Reserved |
| `0x17` | `ASSET_AUDIT` | Third-party audit result committed | Reserved |
| `0x18` | `ASSET_TRANSFER_POLICY` | Transfer policy rule committed (whitelist, limits) | Reserved |

Types `0x19`-`0x1F` are held in reserve for future ZSA operations.

## Hash Constructions

All hashes use BLAKE2b-256 with `NordicShield_` personalization, consistent with the base profile.

```text
ASSET_ISSUE       = BLAKE2b_32(0x10 || len(issuer_id) || issuer_id || len(asset_id) || asset_id || asset_desc_hash)
ASSET_MINT        = BLAKE2b_32(0x11 || len(issuer_id) || issuer_id || len(asset_id) || asset_id || amount_be)
ASSET_BURN        = BLAKE2b_32(0x12 || len(issuer_id) || issuer_id || len(asset_id) || asset_id || amount_be || burn_proof_hash)
ASSET_FREEZE      = BLAKE2b_32(0x13 || len(issuer_id) || issuer_id || len(asset_id) || asset_id || reason_hash)
ASSET_UNFREEZE    = BLAKE2b_32(0x14 || len(issuer_id) || issuer_id || len(asset_id) || asset_id)
ASSET_METADATA    = BLAKE2b_32(0x15 || len(asset_id) || asset_id || metadata_hash)
ASSET_COMPLIANCE  = BLAKE2b_32(0x16 || len(asset_id) || asset_id || len(attestor_id) || attestor_id || compliance_hash)
ASSET_AUDIT       = BLAKE2b_32(0x17 || len(asset_id) || asset_id || len(auditor_id) || auditor_id || audit_hash)
ASSET_TRANSFER_POLICY = BLAKE2b_32(0x18 || len(asset_id) || asset_id || policy_hash)
```

Fields:
- `issuer_id` - operator-generated identifier for the asset issuer
- `asset_id` - the ZSA asset identifier (derived from the issuance key)
- `asset_desc_hash` - BLAKE2b-256 of the asset description (name, symbol, decimals, URI)
- `amount_be` - 8-byte big-endian amount in base units
- `burn_proof_hash` - hash of the burn proof or nullifier set
- `reason_hash` - hash of the freeze reason (human-readable text or structured data)
- `metadata_hash` - BLAKE2b-256 of the updated metadata blob
- `compliance_hash` - hash of the compliance attestation payload
- `audit_hash` - hash of the audit report or finding summary
- `policy_hash` - hash of the transfer policy rules

## Use Cases

### Asset Issuance Audit Trail

An institutional issuer creates a ZSA and wants an auditable record of every mint and burn. Each ASSET_MINT and ASSET_BURN event is committed to the Merkle tree. The root is anchored to Zcash. A regulator or auditor can verify the full issuance history from the proof path without seeing individual holder balances.

### Compliance Without Exposure

An asset requires KYC attestation for holders. The issuer commits ASSET_COMPLIANCE events for verified holders (using hashed identifiers, not names). The compliance status is provable from the Merkle tree without revealing who holds what.

### Cross-Chain Asset Proof

Using the Solidity verifier (`zap1-verify-sol`), an EVM smart contract can verify that a ZSA was issued, that it passed a compliance check, or that an audit was completed - all without a bridge, a custodian, or exposing the underlying Zcash transaction graph.

## Relationship to ZSA Protocol

ZAP1 ZSA events are application-layer attestations, not consensus-layer operations. They do not modify the ZSA issuance or transfer mechanics. They sit above the asset protocol and provide a verifiable audit surface.

The ZSA protocol handles: issuance, transfer, burn at the consensus layer.  
ZAP1 handles: attestation, compliance, audit, metadata at the application layer.

These layers are complementary. An asset issuer can use ZSA for the asset operations and ZAP1 for the attestation trail.

## Activation

These event types will activate when:
1. ZSA protocol is deployed on Zcash mainnet
2. The `asset_id` format is finalized in the ZSA specification
3. Hash constructions are validated against the ZSA issuance key derivation

Until then, types `0x10`-`0x1F` are reserved in the ZAP1 registry. The API will reject events in this range. Test vectors will be published when the ZSA protocol finalizes.
