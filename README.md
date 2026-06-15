# zap1

[![ci](https://github.com/Frontier-Compute/zap1/actions/workflows/ci.yml/badge.svg)](https://github.com/Frontier-Compute/zap1/actions/workflows/ci.yml)

Open-source attestation protocol for Zcash. Commits typed lifecycle events to a BLAKE2b Merkle tree and anchors roots on-chain via shielded memos. Any Zcash-native operator can use it.

MIT licensed. Live deployment state changes over time; verify current counts,
scanner state, and anchor posture through the public API:
https://api.frontiercompute.cash/stats

[ZIP draft PR #1243](https://github.com/zcash/zips/pull/1243) | [QUICKSTART](QUICKSTART.md) | [crates.io](https://crates.io/crates/zap1-verify) | [zcash-memo-decode](https://crates.io/crates/zcash-memo-decode)

## Verify in one command

```bash
git clone https://github.com/Frontier-Compute/zap1.git && cd zap1 && bash scripts/check.sh
```

## What it does

- **Structured attestation**: typed lifecycle events (entry, ownership, deployment, payment, transfer, exit) committed to a BLAKE2b Merkle tree with configurable domain separation
- **Shielded anchoring**: Merkle roots can be broadcast to Zcash mainnet via
  Orchard shielded memos. Proofs are publicly verifiable, event data stays
  private. Current anchor freshness is reported by `/anchor/status`.
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
| `0x0A` | `STAKING_DEPOSIT` | Validator stake locked (reserved, not yet tracked) |
| `0x0B` | `STAKING_WITHDRAW` | Validator stake unlocked (reserved) |
| `0x0C` | `STAKING_REWARD` | Block reward recorded (reserved) |
| `0x0D` | `GOVERNANCE_PROPOSAL` | Governance proposal submitted (reserved) |
| `0x0E` | `GOVERNANCE_VOTE` | Vote commitment recorded (reserved) |
| `0x0F` | `GOVERNANCE_RESULT` | Tally result anchored (reserved) |

All hashes use BLAKE2b-256 with `NordicShield_` personalization. Merkle nodes use `NordicShield_MRK`. Full spec: [ONCHAIN_PROTOCOL.md](ONCHAIN_PROTOCOL.md).

## Mainnet Anchor History

The live deployment has historical Zcash mainnet anchors. Do not rely on this
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
python3 examples/verify_proof.py                # offline proof verification, no server trust
python3 examples/verify_onchain.py              # offline Merkle check + optional Zebra memo check
bash examples/quickstart.sh                     # protocol tour with local proof verification
bash examples/governance_demo.sh YOUR_API_KEY    # full governance cycle
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
| /verify/{hash}/check | GET | deployment server-side verification, when exposed for that leaf |
| /verify/{hash}/proof.json | GET | downloadable proof bundle, when exposed for that leaf |
| /memo/decode | POST | universal memo classifier |
| /lifecycle/{wallet_hash} | GET | events for a wallet |

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
bash scripts/check.sh             # 14 end-to-end checks
```

See [conformance/](conformance/) for fixtures, schemas, versioning policy, and consumer contracts.

## Ecosystem

- **Verification SDK (Rust + WASM):** [Frontier-Compute/zap1-verify](https://github.com/Frontier-Compute/zap1-verify) - 22 tests
- **JS/TS SDK:** [Frontier-Compute/zap1-js](https://github.com/Frontier-Compute/zap1-js) - 19 tests
- **Public API:** [api.frontiercompute.cash](https://api.frontiercompute.cash/protocol/info)
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

