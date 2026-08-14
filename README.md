# zap1

[![ci](https://github.com/Frontier-Compute/zap1/actions/workflows/ci.yml/badge.svg)](https://github.com/Frontier-Compute/zap1/actions/workflows/ci.yml)

Open-source attestation protocol for Zcash. Commits typed lifecycle events to a
BLAKE2b Merkle tree and records Zcash transaction references for roots sent in
shielded memos. Public root-to-memo binding requires separate disclosure
material because Orchard memo contents are encrypted.

MIT licensed. Live deployment state changes over time; verify current counts,
scanner state, and anchor posture through the public API:
https://api.frontiercompute.cash/stats

[Research wire-format draft PR #1243](https://github.com/zcash/zips/pull/1243) | [QUICKSTART](QUICKSTART.md) | [crates.io](https://crates.io/crates/zap1-verify) | [zcash-memo-decode](https://crates.io/crates/zcash-memo-decode)

## Verify in one command

`bash`, Python 3, Node, Rust, and `protoc` are required.

```bash
git clone https://github.com/Frontier-Compute/zap1.git && cd zap1 && bash scripts/check.sh --local
```

That command is the Linux/macOS path. Windows needs Git Bash and an x64 Visual
Studio developer environment; see [EVALUATOR_QUICKSTART.md](EVALUATOR_QUICKSTART.md).

## Check a proof bundle

Pull a proof bundle from the live API and re-walk it locally. No API key is
needed. The API supplies the leaf, path, and root; the local check does not
authenticate root publication.

```bash
curl -s https://api.frontiercompute.cash/verify/41792a315c4942da8901d1fd9c12e2598c47ec0e40f3086e2c883ee9c70ead17/proof.json -o proof.json
python3 examples/verify_proof.py proof.json
# MERKLE MATCH: supplied leaf hash is included under the supplied root.
```

The endpoint selects a covering root and reports its scheme and anchor fields;
inspect them on every fetch. The local verifier checks only that the downloaded
leaf and proof path are internally consistent with the supplied root. Check
`/anchor/status` for current publication state. This does not prove the
server's root-to-transaction mapping or the underlying event claim.

## What it does

- **Structured claims**: operator-supplied lifecycle events (entry, ownership, deployment, payment, transfer, exit) and agent events (register, policy, action) committed to a BLAKE2b Merkle tree with configurable domain separation. A commitment does not prove the claim is true.
- **Shielded anchoring**: Merkle roots can be broadcast to Zcash mainnet via
  Orchard shielded memos. Public feeds and proof bundles withhold stored wallet
  and serial preimages. The service still stores submitted strings, and
  authenticated participant and lifecycle routes disclose records to the
  operator. Transaction IDs establish existence; encrypted memo-to-root
  binding requires disclosure material. Current anchor freshness is reported
  by `/anchor/status`.
- **Verification**: the published `zap1-verify` 0.2.1 crate is the legacy verifier. The repository contains the unpublished count-bound 0.3.0 candidate, local browser tooling, and audit scripts. They recompute Merkle inclusion against a supplied root. They do not authenticate root publication or event truth.
- **Ecosystem tooling**: the published `zcash-memo-decode` 0.1.1 crate is legacy. The repository contains the unpublished 0.1.2 candidate, plus the [ZIP 302 TVLV reference](src/bin/zip302_tvlv.rs), Zaino compact block [adapter](src/bin/zaino_adapter.rs), and [selective disclosure export](src/bin/zap1_export.rs).

An older service deployment is reachable and reports Mainnet. It is not
evidence that the hardened repository candidate is deployed. Exact source,
build, image, health, and anchor posture must pass the live gate separately.
The protocol is application-agnostic.

## Protocol

ZAP1 defines 18 event types. The write API accepts 15; PROGRAM_ENTRY,
OWNERSHIP_ATTEST, and MERKLE_ROOT are system-managed.

| Type | Name | Trigger |
|------|------|---------|
| `0x01` | `PROGRAM_ENTRY` | Starter pack or initial program invoice confirmed |
| `0x02` | `OWNERSHIP_ATTEST` | Machine serial assigned to wallet |
| `0x03` | `CONTRACT_ANCHOR` | Hosting contract artifact committed by hash |
| `0x04` | `DEPLOYMENT` | Miner installed and activated at facility |
| `0x05` | `HOSTING_PAYMENT` | Monthly hosting invoice paid |
| `0x06` | `SHIELD_RENEWAL` | Annual privacy shield renewal paid |
| `0x07` | `TRANSFER` | Ownership transferred to a new wallet hash |
| `0x08` | `EXIT` | Participant exit or hardware release recorded |
| `0x09` | `MERKLE_ROOT` | Current Merkle root commitment payload |
| `0x0A` | `STAKING_DEPOSIT` | Experimental/legacy staking deposit record |
| `0x0B` | `STAKING_WITHDRAW` | Experimental/legacy staking withdrawal record |
| `0x0C` | `STAKING_REWARD` | Experimental/legacy staking reward record |
| `0x0D` | `GOVERNANCE_PROPOSAL` | Experimental/legacy governance proposal |
| `0x0E` | `GOVERNANCE_VOTE` | Experimental/legacy governance vote |
| `0x0F` | `GOVERNANCE_RESULT` | Experimental/legacy governance result |
| `0x40` | `AGENT_REGISTER` | Agent identity, model, and policy hashes committed |
| `0x41` | `AGENT_POLICY` | Agent policy version and rules hash committed |
| `0x42` | `AGENT_ACTION` | Agent action with input and output hashes committed |

The CI-gated [equivalence corpus](equivalence/) checks that Python, Rust, and
TypeScript produce the same outputs on the admitted frozen corpus. It is not a
claim that the implementations are byte-identical or equivalent outside that
corpus. Typed field reconstruction coverage differs by implementation.

All hashes use BLAKE2b-256 with `NordicShield_` personalization. Merkle nodes use `NordicShield_MRK`. Full spec: [ONCHAIN_PROTOCOL.md](ONCHAIN_PROTOCOL.md).

## Mainnet Transaction-Reference History

The live deployment has historical root-to-transaction records. Do not rely on this
README for current counts, latest root, or freshness; use the API:

- Anchor status: https://api.frontiercompute.cash/anchor/status
- Anchor history: https://api.frontiercompute.cash/anchor/history
- Live stats: https://api.frontiercompute.cash/stats

Historical proof material is documented in [E2E_PROOF_20260327.md](E2E_PROOF_20260327.md).

## Stack

- **Rust** (axum, rusqlite, zcash_client_backend, blake2b_simd, qrcode)
- **Zebra RPC** for chain reads (getblock, getrawtransaction, getrawmempool)
- **SQLite** for invoices, Merkle leaves, Merkle roots, payment records
- **Docker** for deployment

## Immutable image setup

```bash
test -z "$(git status --porcelain)"
REV=$(git rev-parse HEAD)
bash scripts/build_image.sh "zap1:$REV"
# Copy receipt_path from the output. Keep it with its .sha256 sidecar.
export ZAP1_OPERATOR_UFVK='uview1...from-a-wallet-you-control'
export ZAP1_ANCHOR_TO_ADDRESS='u1...from-the-same-wallet'
export ZAP1_SCAN_FROM_HEIGHT='<wallet-birthday-height>'
bash scripts/operator-setup.sh myoperator 3081 /absolute/path/to/build-receipt.env
cd operators/myoperator
./run.sh
```

The build driver uses a clean Git archive, emits the exact image ID, source
revision, tree, source manifest, Dockerfile hash, embedded `BUILD_INFO`, and a
checksummed receipt. The setup script verifies all of them before generating a
compose file pinned to the image ID and an evaluator directory containing the
exact archived API checker and schema. The generated run script verifies those
evaluator bytes before Compose starts, binds `/build/info` to the receipt,
waits for RPC-backed scanner readiness within a bounded deadline, and runs the
final strict API check from the pinned evaluator. Bit-for-bit reproducibility
is not asserted.

## Examples

Runnable scripts in `examples/`. Requirements vary by example and are stated
at the top of each script.

```bash
python3 examples/verify_proof.py                # local Merkle-bundle consistency check
python3 examples/verify_onchain.py              # fail-closed Merkle + transaction-existence check
bash examples/quickstart.sh                     # protocol tour with local proof verification
ZAP1_API_BASE=http://127.0.0.1:3080 bash examples/governance_demo.sh YOUR_API_KEY  # synthetic governance claims
python3 conformance/check_api.py URL             # strict read-only API contract check
bash examples/validate_instance.sh URL           # strict read-only API contract check
ZAP1_API_BASE=http://127.0.0.1:3080 bash examples/create_event.sh YOUR_API_KEY     # synthetic event claim
python3 examples/decode_memo.py HEX              # decode any Zcash memo
bash examples/check_anchor.sh TXID_PREFIX        # query the API's recorded anchor mapping
node examples/memo_decode.js HEX                 # zero-dep JS memo parser
```

## Verification SDK

The public `Frontier-Compute/zap1-verify` repository and crates.io package are
legacy 0.2.1 surfaces. This repository contains the unpublished count-bound
0.3.0 Rust and WASM candidate. It implements ZAP1 leaf hashing, Merkle proof
walking, and browser-friendly primitives. After a bundle is obtained, the math
runs locally; root publication remains a separate verification layer.

## Operator tools

```bash
cargo run --bin zap1_audit -- --bundle examples/live_ownership_attest_proof.json
cargo run --bin zap1_schema -- --witness examples/schema_witness.json
cargo run --bin zap1_ops -- --from-dir examples/zap1_ops_fixture --json
cargo run --bin zaino_adapter -- --zaino-url http://127.0.0.1:8137
cargo run --bin memo_scan -- --ufvk $UFVK --start 3286630 --end 3286632 --json
cargo run --bin zip302_tvlv -- encode examples/zip302_parts_example.json
python3 scripts/check_anchor_liveness.py
```

- `zap1_audit`: verify supplied leaf-hash inclusion under the supplied Merkle root, then print bundle-claimed metadata and recorded anchor references
- `zap1_schema`: validate event witness data, recompute hashes, emit witness bundles (`--emit-witness`)
- `zap1_export`: selective disclosure - produce self-contained audit packages for counterparties
- `zap1_ops`: operator status rollup for scanner lag, anchor freshness, queue depth
- `zaino_adapter`: check recorded transactions through the Zaino compact-block path
- `memo_scan`: scan block ranges via Zaino, decrypt and classify all shielded memos
- `zip302_tvlv`: reference ZIP 302 TVLV encoder/decoder
- `check_anchor_liveness.py`: nightly anchor freshness and consistency check

Export profiles: `zap1_export --profile auditor|counterparty|member|regulator`
Offline verify: `zap1_audit --export package.json`

Consumer examples in `examples/`: wallet (Python), explorer (Python), indexer (bash).

## Public read API

| Endpoint | Method | Purpose |
|---|---|---|
| /protocol/info | GET | protocol metadata |
| /events?limit=N | GET | recent operator-issued event claims |
| /stats | GET | recorded-transaction and leaf counts |
| /health | GET | scanner and node status |
| /anchor/history | GET | API-recorded root, txid, and height mappings |
| /anchor/status | GET | current tree state |
| /verify/{hash}/check | GET | deployment server-side verification, when exposed for that leaf |
| /verify/{hash}/proof.json | GET | downloadable proof bundle, when exposed for that leaf |
| /memo/decode | POST | universal memo classifier |
| /lifecycle/{wallet_hash} | GET | operator-authenticated events for a subject identifier |

Interactive docs: [frontiercompute.cash/api.html](https://frontiercompute.cash/api.html)
OpenAPI spec: [conformance/openapi.yaml](conformance/openapi.yaml)
Reference clients: [Python](conformance/clients/zap1_client.py) | [TypeScript](conformance/clients/zap1_client.ts)

Offline proof verification does not require a hosted `/verify` endpoint:
`python3 examples/verify_proof.py examples/proof_bundle_example.json`.

## Conformance

```bash
python3 conformance/check.py        # protocol fixture checks
python3 conformance/check_api.py     # live API schema checks
python3 scripts/check_compatibility.py  # 6 hash vectors
bash scripts/check.sh --local     # deterministic repository evaluator
ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID=sha256:... bash scripts/check.sh --live
```

See [conformance/](conformance/) for fixtures, schemas, versioning policy, and consumer contracts.

## Ecosystem

- **Verification SDK (Rust + WASM):** published legacy crate 0.2.1; repository candidate 0.3.0 is unpublished
- **JS/TS SDK:** [Frontier-Compute/zap1-js](https://github.com/Frontier-Compute/zap1-js) - 19 tests
- **Public API:** [api.frontiercompute.cash](https://api.frontiercompute.cash/protocol/info)
- **Browser verifier:** [frontiercompute.cash/verify.html](https://frontiercompute.cash/verify.html)
- **Universal memo decoder:** published legacy crate 0.1.1; repository candidate 0.1.2 is unpublished
- **Browser memo decoder:** [frontiercompute.cash/memo.html](https://frontiercompute.cash/memo.html)
- **Zaino gRPC:** historical application-operated mainnet exercise, not an
  independent validation or current deployment attestation. See
  [ZAINO_VALIDATION.md](ZAINO_VALIDATION.md).

## FROST Threshold Signing

The repository includes an experimental 2-of-3 Pallas signing path and a
sanitized signing-round reference. The current runtime loads `ANCHOR_SEED` and
two long-term FROST shares into one process. It proves signature compatibility,
but it does not provide independent threshold custody and is not production
ready. Runtime use fails closed unless
`EXPERIMENTAL_COLOCATED_FROST_ENABLED=true` is set with `SIGNING_MODE=frost`
and `NETWORK=Testnet`. Mainnet activation is rejected.

See [FROST_THREAT_MODEL.md](FROST_THREAT_MODEL.md) and
[docs/FROST_SIGNING_PROTOCOL.rs](docs/FROST_SIGNING_PROTOCOL.rs).

## ZIP Proposal

A draft ZIP for the ZAP1 attestation format is open at [zcash/zips PR #1243](https://github.com/zcash/zips/pull/1243). It describes an event registry, hash construction, Merkle aggregation, and verification procedure. It remains draft, unmerged, and unreconciled with the repository's canonical implementation profile. No ZIP assignment, acceptance, or adoption is claimed.

## Run tests

```bash
cargo test --release --test memo_merkle_test
```

23 tests in this file covering memo encode/decode, hash determinism, Merkle tree computation, proof generation, and proof verification.

## License

MIT

