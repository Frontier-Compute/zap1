# zap1

[![ci](https://github.com/Frontier-Compute/zap1/actions/workflows/ci.yml/badge.svg)](https://github.com/Frontier-Compute/zap1/actions/workflows/ci.yml)

Open-source attestation protocol for Zcash. Commits typed lifecycle events to a BLAKE2b Merkle tree and anchors roots on-chain via shielded memos. Any Zcash-native operator can use it.

1 mainnet anchor. 12 leaves. 9 event types tracked. 118 tests. 60 automated checks. MIT licensed. Live stats: https://api.frontiercompute.cash/stats

[ZIP draft PR #1243](https://github.com/zcash/zips/pull/1243) | [QUICKSTART](QUICKSTART.md) | [crates.io](https://crates.io/crates/zap1-verify) | [zcash-memo-decode](https://crates.io/crates/zcash-memo-decode)

## Verify in one command

```bash
git clone https://github.com/Frontier-Compute/zap1.git && cd zap1 && bash scripts/check.sh
```

## What it does

- **Structured attestation**: typed lifecycle events (entry, ownership, deployment, payment, transfer, exit) committed to a BLAKE2b Merkle tree with configurable domain separation
- **Shielded anchoring**: Merkle roots broadcast to Zcash mainnet via Orchard shielded memos. Proofs are publicly verifiable, event data stays private.
- **Verification**: standalone SDK on [crates.io](https://crates.io/crates/zap1-verify), browser verifier, offline audit tools. No server trust required.
- **Ecosystem tooling**: universal [memo decoder](https://crates.io/crates/zcash-memo-decode), [ZIP 302 TVLV reference](src/bin/zip302_tvlv.rs), Zaino compact block [adapter](src/bin/zaino_adapter.rs), [selective disclosure export](src/bin/zap1_export.rs)

One production deployment is live on mainnet. The protocol is application-agnostic.

## Protocol

Nine event types are tracked in ZAP1:

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
| `0x09` | `MERKLE_ROOT` | Current Merkle root anchored to Zcash |
| `0x0A` | `STAKING_DEPOSIT` | Validator stake locked |
| `0x0B` | `STAKING_WITHDRAW` | Validator stake unlocked |
| `0x0C` | `STAKING_REWARD` | Block reward recorded |
| `0x0D` | `GOVERNANCE_PROPOSAL` | Governance proposal submitted |
| `0x0E` | `GOVERNANCE_VOTE` | Vote commitment recorded |
| `0x0F` | `GOVERNANCE_RESULT` | Tally result anchored |

All hashes use BLAKE2b-256 with `NordicShield_` personalization. Merkle nodes use `NordicShield_MRK`. Full spec: [ONCHAIN_PROTOCOL.md](ONCHAIN_PROTOCOL.md).

## Mainnet proof anchor

Anchored on Zcash mainnet block **3,286,631** on March 27, 2026.

- Anchor txid: `98e1d6a01614c464c237f982d9dc2138c5f8aa08342f67b867a18a4ce998af9a`
- Root: `024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a`
- Details: [E2E_PROOF_20260327.md](E2E_PROOF_20260327.md)

## Stack

- **Rust** (axum, rusqlite, zcash_client_backend, blake2b_simd, qrcode)
- **Zebra 4.3.0** for RPC (getblock, getrawtransaction, getrawmempool)
- **SQLite** for invoices, Merkle leaves, Merkle roots, payment records
- **Docker** for deployment

## Setup

```bash
cp .env.example .env.mainnet
# Edit .env.mainnet with your UFVK, API_KEY, etc.
docker compose -f docker-compose.mainnet.yml build
docker compose -f docker-compose.mainnet.yml up -d
```

## Examples

Runnable scripts in `examples/`. No install needed beyond curl + python3.

```bash
bash examples/quickstart.sh                     # protocol tour in 60 seconds
bash examples/governance_demo.sh YOUR_API_KEY    # full governance cycle
python3 examples/verify_proof.py LEAF_HASH       # fetch and display a proof
python3 examples/verify_onchain.py proof.json    # independent Merkle + chain verification
python3 examples/conformance_check.py URL        # validate any ZAP1 instance (19 checks)
bash examples/validate_instance.sh URL           # instance health check (10 checks)
bash examples/create_event.sh YOUR_API_KEY       # create an event
python3 examples/decode_memo.py HEX              # decode any Zcash memo
bash examples/check_anchor.sh TXID_PREFIX        # verify an anchor on-chain
node examples/memo_decode.js HEX                 # zero-dep JS memo parser
```

## Verification SDK

The standalone Rust + WASM verifier is available at
[`Frontier-Compute/zap1-verify`](https://github.com/Frontier-Compute/zap1-verify).
It implements ZAP1 leaf hashing, Merkle proof walking, and browser-friendly
verification primitives without depending on the reference implementation server.

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

- `zap1_audit`: verify a proof bundle against the Merkle tree and print anchor facts
- `zap1_schema`: validate event witness data, recompute hashes, emit witness bundles (`--emit-witness`)
- `zap1_export`: selective disclosure - produce self-contained audit packages for counterparties
- `zap1_ops`: operator status rollup for scanner lag, anchor freshness, queue depth
- `zaino_adapter`: verify all anchors via Zaino gRPC compact block path
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
| /events?limit=N | GET | recent attestation feed |
| /stats | GET | anchor and leaf counts |
| /health | GET | scanner and node status |
| /anchor/history | GET | all anchored roots |
| /anchor/status | GET | current tree state |
| /verify/{hash} | GET | proof page |
| /verify/{hash}/check | GET | server-side verification |
| /verify/{hash}/proof.json | GET | downloadable proof bundle |
| /memo/decode | POST | universal memo classifier |
| /lifecycle/{wallet_hash} | GET | events for a wallet |

Interactive docs: [frontiercompute.cash/api.html](https://frontiercompute.cash/api.html)
OpenAPI spec: [conformance/openapi.yaml](conformance/openapi.yaml)
Reference clients: [Python](conformance/clients/zap1_client.py) | [TypeScript](conformance/clients/zap1_client.ts)

## Conformance

```bash
python3 conformance/check.py        # 14 protocol checks
python3 conformance/check_api.py     # 21 API schema checks
python3 scripts/check_compatibility.py  # 6 hash vectors
bash scripts/check.sh             # 14 end-to-end checks
```

See [conformance/](conformance/) for fixtures, schemas, versioning policy, and consumer contracts.

## Ecosystem

- **Verification SDK (Rust + WASM):** [Frontier-Compute/zap1-verify](https://github.com/Frontier-Compute/zap1-verify) - 22 tests
- **JS/TS SDK:** [Frontier-Compute/zap1-js](https://github.com/Frontier-Compute/zap1-js) - 19 tests
- **Attestation explorer:** [explorer.frontiercompute.cash](https://explorer.frontiercompute.cash)
- **Lifecycle simulator:** [simulator.frontiercompute.cash](https://simulator.frontiercompute.cash)
- **Browser verifier:** [frontiercompute.cash/verify.html](https://frontiercompute.cash/verify.html)
- **Universal memo decoder:** [zcash-memo-decode](https://crates.io/crates/zcash-memo-decode) - 23 tests, zero deps
- **Browser memo decoder:** [frontiercompute.cash/memo.html](https://frontiercompute.cash/memo.html)
- **Zaino gRPC:** validated on mainnet - [ZAINO_VALIDATION.md](ZAINO_VALIDATION.md)

## FROST Threshold Signing

The current FROST design package is documented in
[FROST_THREAT_MODEL.md](FROST_THREAT_MODEL.md). A sanitized reference
implementation of the 2-of-3 Pallas signing round is published in
[docs/FROST_SIGNING_PROTOCOL.rs](docs/FROST_SIGNING_PROTOCOL.rs).

## ZIP Proposal

A draft ZIP for the ZAP1 attestation format is open at [zcash/zips PR #1243](https://github.com/zcash/zips/pull/1243). It defines the event type registry, hash construction rules, Merkle tree aggregation, and verification procedure. The memo container relationship to ZIP 302 (Structured Memos) is documented in the draft.

## Run tests

```bash
cargo test --release --test memo_merkle_test
```

23 tests in this file covering memo encode/decode, hash determinism, Merkle tree computation, proof generation, and proof verification.

## License

MIT
# updated 2026-03-27T23:30:24Z
