# ZAP1 Quickstart

## Fastest path

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
bash scripts/check.sh --local
```

Runs deterministic repository checks, locked Rust tests, proof fixtures,
schema validation, compatibility vectors, and cross-language corpus checks.
Run the live gate from the exact clean deployment commit with the image ID from
the build and deployment receipt:

```bash
ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID=sha256:... bash scripts/check.sh --live
```

## Step by step

## 1. Protocol metadata

Open:

`https://api.frontiercompute.cash/protocol/info`

Shows the API's recorded mapping:

- protocol name: `ZAP1`
- version metadata
- event registry: 18 defined, 15 accepted by `POST /event`, 3 system-managed
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

- historical Merkle roots
- recorded transaction IDs and block heights
- leaf-count growth over time

Transaction existence is independently checkable. Because shielded memo
contents are encrypted, this surface alone does not independently prove that a
listed transaction memo contains the listed root.

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

## 6. Optional transaction-existence check

With a local Zebra RPC, check the anchor transaction memo when the proof bundle
has a txid:

```bash
python3 examples/verify_onchain.py examples/proof_bundle_example.json --rpc http://127.0.0.1:8232
```

Checks:

- Merkle proof resolves to the claimed root
- the referenced transaction exists when the RPC can return it
- exits incomplete because encrypted Orchard memo contents are not opened

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

Bounds:

- the public repository and crates.io package are legacy 0.2.1 surfaces
- the count-bound 0.3.0 Rust and WASM candidate is in this repository and is
  not published
- local browser verification does not need a backend after a bundle is
  obtained, but it does not authenticate root publication

## 9. Test vectors

Open:

`https://github.com/Frontier-Compute/zap1/blob/main/TEST_VECTORS.md`

Confirms:

- fixed vectors exist for all 18 defined ZAP1 event types

## 10. Clone and run tests

```bash
git clone https://github.com/Frontier-Compute/zap1.git
cd zap1
cargo test --release --locked --test memo_merkle_test
```

For deployment, follow [OPERATOR_GUIDE.md](OPERATOR_GUIDE.md). Build from a
clean Git archive with `scripts/build_image.sh`, preserve its checksummed
receipt, run `scripts/operator-setup.sh` against that receipt, and start only
the exact image ID.

## 11. Historical Zaino gRPC exercise

Details:

`https://github.com/Frontier-Compute/zap1/blob/main/ZAINO_VALIDATION.md`

Records an application-operated historical exercise:

- Zaino 0.2.0 gRPC ran on infrastructure controlled by the application operator
- GetBlock, GetBlockRange, GetTransaction, and GetLatestTreeState were exercised
- the checked historical transaction set was retrieved through Zebra RPC and
  Zaino gRPC at that cutoff
- this is not independent validation, current service status, or proof that
  every anchor transaction is retrievable now

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
- event witness data recomputes to the supplied leaf hash
- Zaino adapter can be run against an operator-selected endpoint; results are
  endpoint-specific and current retrieval is not assumed

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

## 14. Research wire-format draft

PR:

`https://github.com/zcash/zips/pull/1243`

Status:

- open and draft
- not a canonical wire format
- byte-level and registry reconciliation remains pending
