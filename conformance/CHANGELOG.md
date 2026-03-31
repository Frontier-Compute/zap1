# Conformance Changelog

Changes to the ZAP1 protocol contract, API schemas, and conformance fixtures.

## 2026-03-30

### Added
- Initial conformance kit with 14 protocol checks
- API schema validation with 21 checks against live endpoints
- OpenAPI 3.0 spec for all read-only surfaces
- Reference clients: Python and TypeScript
- Consumer contracts: wallet, explorer, indexer, operator
- Versioning policy: stable surfaces defined for v2.2.0
- Compatibility test vectors: 5 hash vectors + 1 tree vector from mainnet
- Memo wire format vectors: 6 encode/decode cases
- Proof bundle fixtures: valid + invalid
- Export package fixture from mainnet

### Protocol
- Protocol marker: ZAP1 (legacy NSM1 accepted on decode)
- Hash function: BLAKE2b-256 with NordicShield_ personalization
- Wire format: ZAP1:{type}:{hash} (73 bytes)
- Proof bundle version: 2

### Stability
- All surfaces listed in VERSIONING.md are frozen
- Breaking changes require major version bump (3.0.0)
- Additive changes allowed in minor versions (2.x.0)
