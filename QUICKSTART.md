# ZAP1 Quickstart

## Fastest path

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
bash scripts/check.sh
```

14 checks. Live API, crates.io, tests, proof bundles, schema validation, memo decode, all surfaces. Takes about 2 minutes with Rust installed.

## Step by step

## 1. Protocol metadata

Open:

`https://api.frontiercompute.cash/protocol/info`

Confirms:

- protocol name: `ZAP1`
- version metadata
- event type counts: 15 defined, 15 deployed
- verification SDK reference
- FROST and ZIP status

## 2. Live network state

Open:

`https://api.frontiercompute.cash/stats`

Confirms:

- network: `MainNetwork`
- total anchors and total leaves (live counts from the API)
- anchors and leaves should both be nonzero
- current event type registry as exposed by the live API

## 3. Anchor history

Open:

`https://api.frontiercompute.cash/anchor/history`

Human-readable view:

`https://frontiercompute.io/anchors.html`

Confirms:

- all anchored Merkle roots
- txids
- block heights
- leaf-count growth over time

## 4. Offline proof verification

Run:

```bash
python3 examples/verify_proof.py examples/proof_bundle_example.json
```

Confirms:

- leaf hash
- proof path
- root
- bundled anchor reference, if present
- no hosted `/verify` endpoint is required

## 5. Optional live proof fetch

If the live deployment exposes a proof bundle for a current leaf, fetch it
explicitly:

```bash
LEAF=$(curl -sf https://api.frontiercompute.cash/events?limit=1 | python3 -c "import json,sys; print(json.load(sys.stdin)['events'][0]['leaf_hash'])")
python3 examples/verify_proof.py "$LEAF" --api-base https://api.frontiercompute.cash
```

Confirms:

- current proof route is exposed for that leaf
- the fetched bundle still verifies offline after download

## 6. Optional on-chain memo check

With a local Zebra RPC, check the anchor transaction memo when the proof bundle
has a txid:

```bash
python3 examples/verify_onchain.py examples/proof_bundle_example.json --rpc http://127.0.0.1:8232
```

Confirms:

- Merkle proof resolves to the claimed root
- anchor memo matches when the local chain reader can decrypt/extract it

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

- deterministic vectors exist for all 15 deployed ZAP1 event types

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

## 12. Operator tooling

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
cargo run --bin zap1_ops -- --base-url https://api.frontiercompute.cash --json
cargo run --bin zap1_schema -- --witness examples/schema_witness.json
cargo run --bin zaino_adapter -- --zaino-url http://127.0.0.1:8137 --api-url https://api.frontiercompute.cash
```

Confirms:

- operator status rollup works against live stack
- event witness data recomputes to the anchored leaf hash
- Zaino compact block path retrieves all anchor transactions

Operator runbook: `https://github.com/Frontier-Compute/zap1/blob/main/docs/OPERATOR_RUNBOOK.md`

## 13. Conformance kit

```bash
python3 conformance/check.py        # protocol fixture checks
python3 conformance/check_api.py     # live API schema checks
python3 scripts/check_compatibility.py  # 6 hash vectors
```

Confirms:

- hash vectors match across implementations
- API responses match frozen JSON schemas
- valid proof bundles verify, invalid bundles fail
- export packages verify offline

Consumer contracts: `conformance/contracts/` (wallet, explorer, indexer, operator)
OpenAPI spec: `conformance/openapi.yaml`
Reference clients: `conformance/clients/` (Python, TypeScript)

## 14. ZIP draft

PR:

`https://github.com/zcash/zips/pull/1243`

Confirms:

- the protocol has been pushed into the Zcash standards process
- scope is application-layer attestation, not wallet transport
- ZIP 302 relationship documented
