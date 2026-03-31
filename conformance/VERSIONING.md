# ZAP1 Versioning Policy

## Current version: 2.2.0

## What is stable

These interfaces will not change without a version bump:

- memo wire format: `ZAP1:{type}:{hash}` (73 bytes)
- hash construction: BLAKE2b-256 with 16-byte personalization
- event type byte assignments: 0x01-0x0C
- Merkle tree construction: BLAKE2b-256 with NordicShield_MRK personalization
- proof bundle format: leaf, proof, root, anchor fields
- export package format: proofs array with witness data
- API endpoints: /protocol/info, /stats, /health, /events, /anchor/history, /anchor/status, /verify/{hash}/check, /verify/{hash}/proof.json, /memo/decode

## What can change in a minor version (2.x.0)

- new event types added (0x0D+)
- new fields added to API responses (additive only)
- new endpoints added
- new export profiles

## What requires a major version (3.0.0)

- changes to hash construction or personalization strings
- changes to the memo wire format prefix
- removal or rename of existing API fields
- changes to proof bundle structure
- changes to Merkle tree node construction

## Backward compatibility

- legacy `NSM1:` memo prefix is accepted during decode indefinitely
- proof bundles without a `version` field are treated as v1
- API consumers should ignore unknown fields (forward compatible)

## Conformance

Run `python3 conformance/check.py` and `python3 conformance/check_api.py` to verify an implementation meets the v2.2.0 contract.
