# ZAP1 Evaluator Quickstart

This is the fastest path to validate the protocol's technical claims in under 10 minutes.

## 1. Protocol metadata

Open:

`https://pay.frontiercompute.io/protocol/info`

Confirms:

- protocol name: `ZAP1`
- version metadata
- event type counts: 12 defined, 9 deployed, 3 reserved
- verification SDK reference
- FROST and ZIP status

## 2. Live network state

Open:

`https://pay.frontiercompute.io/stats`

Confirms:

- network: `MainNetwork`
- total anchors and total leaves (live counts from the API)
- anchors and leaves should both be nonzero
- current event type registry as exposed by the live API

## 3. Anchor history

Open:

`https://pay.frontiercompute.io/anchor/history`

Human-readable view:

`https://frontiercompute.io/anchors.html`

Confirms:

- all anchored Merkle roots
- txids
- block heights
- leaf-count growth over time

## 4. Live proof page

Open:

`https://pay.frontiercompute.io/verify/075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b`

Confirms:

- leaf hash
- proof path
- root
- anchor txid
- block height

## 5. Server-side verification

Open:

`https://pay.frontiercompute.io/verify/075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b/check`

Confirms:

- `valid: true`
- proof can be verified independently by the server
- verification is performed with `zap1-verify`

## 6. Proof bundle download

Open:

`https://pay.frontiercompute.io/verify/075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b/proof.json`

Confirms:

- bundle format is downloadable
- proof data can be reused outside the hosted site

## 7. Reference implementation

Repo:

`https://github.com/Frontier-Compute/zap1`

Confirms:

- MIT-licensed implementation
- protocol docs
- verifier script
- public API implementation
- FROST and Zaino integration docs

## 8. Verification SDK

Repo:

`https://github.com/Frontier-Compute/zap1-verify`

crate:

`https://crates.io/crates/zap1-verify`

WASM verifier:

`https://frontiercompute.io/verify.html`

Confirms:

- standalone verifier exists outside the reference implementation
- Rust crate and WASM path are both shipped
- browser verification does not depend on a backend round-trip

## 9. Test vectors

Open:

`https://github.com/Frontier-Compute/zap1/blob/main/TEST_VECTORS.md`

Confirms:

- deterministic vectors exist for all 9 deployed ZAP1 event types

## 10. Clone and run tests

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
cargo test --release --test memo_merkle_test
```

## 11. Zaino gRPC validation

Details:

`https://github.com/Frontier-Compute/zap1/blob/main/ZAINO_VALIDATION.md`

Confirms:

- Zaino 0.2.0 gRPC serving on the same infrastructure as the production scanner
- GetBlock, GetBlockRange, GetTransaction, GetLatestTreeState all tested
- Our anchor transactions are retrievable via both Zebra RPC and Zaino gRPC
- NodeBackend trait abstracts both backends

## 12. ZIP draft

PR:

`https://github.com/zcash/zips/pull/1243`

Confirms:

- the protocol has been pushed into the Zcash standards process
- scope is application-layer attestation, not wallet transport
- ZIP 302 relationship documented
