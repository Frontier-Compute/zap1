# Proof Bundle v2 Format

Current reference envelope for ZAP1 Merkle receipts. Used by `zap1_audit`,
`zap1_export`, and consumer applications.

## Single proof bundle

Returned by `/verify/{hash}/proof.json` and consumed by `zap1_audit --bundle`.

```json
{
  "protocol": "ZAP1",
  "version": "2",
  "leaf": {
    "hash": "075b00df...",
    "event_type": "PROGRAM_ENTRY",
    "created_at": "2026-03-27 03:28:57",
    "preimage_disclosure": "withheld from the public proof bundle",
    "event_type_authentication": "unverified_server_metadata_without_disclosed_witness"
  },
  "proof": [
    { "hash": "de62554a...", "position": "right" }
  ],
  "root": {
    "hash": "024e3651...",
    "leaf_count": 2,
    "created_at": "2026-03-27T03:29:26Z",
    "scheme": "ZAP1_LEGACY_DUPLICATE_ODD",
    "legacy_allowed": true,
    "legacy_max_anchor_height": 3317133
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
      "treat the txid and height as a transaction reference unless a separate safe opening binds the encrypted memo to the root",
      "confirm the anchor_txid is mined at anchor_height",
      "optionally use zap1_schema --emit-witness to verify preimage fields"
    ]
  }
}
```

The public proof endpoint withholds stored wallet and serial preimages. Its
event type is claimed server metadata until a separately disclosed typed
witness is recomputed against the leaf hash.
`zap1_export` adds optional witness fields from the operator-controlled
participant path and explicit command input. Those fields are disclosures, not
facts authenticated by the Merkle proof.

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
| check.sh | deterministic local checks | `bash scripts/check.sh --local` |

The published `zap1-verify` crate remains `0.2.1`. The count-bound
`0.3.0` candidate in this repository is not published at this cutoff. The
published `zcash-memo-decode` crate remains `0.1.1`; the `0.1.2`
candidate is also repository-only. Evaluate the vendored code when testing the
current bundle rules. Do not cite the unpublished versions as registry releases.

Merkle verification proves consistency under the supplied root. After a
separate node lookup, a recorded txid and height can establish that the
referenced transaction exists. They do not prove the event preimage, the truth
or completeness of the operator claim, the contents of an encrypted memo, or
that the supplied root is bound to that transaction. Canonical root and txid
language refers only to the required encoding of values recorded by the
service.

## Compatibility

The reference auditor retains a gated path for historical v1 bundles. Consumers
must not infer legacy eligibility merely because the `version` field is
missing. Apply the historical height cutoff and declared Merkle scheme. The
auditor applies the cutoff to anchor metadata supplied by the bundle. Until a
separate chain-binding check ties that metadata to a mined transaction and a
safe memo opening, the cutoff gates the declared legacy envelope only.
