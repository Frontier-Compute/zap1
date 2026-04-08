# Zaino Integration Guide

> ZCG Milestone 3 deliverable -- Zaino compact-block backend for ZAP1.

## Overview

ZAP1 supports two chain data backends: direct Zebra JSON-RPC and Zaino gRPC compact-block streaming. Switching between them requires changing a single environment variable. The scanner logic, payment detection, trial decryption, and anchor verification remain identical regardless of which backend is active.

This document covers the architecture, protocol details, deployment, validation results, and migration path.

---

## 1. How ZAP1 Connects to Zaino

ZAP1 reads the `ZAINO_GRPC_URL` environment variable at startup. If set, the scanner uses the Zaino gRPC backend. If unset, it falls back to Zebra JSON-RPC via `ZEBRA_RPC_URL`.

```bash
# Enable Zaino backend (one env var)
export ZAINO_GRPC_URL=http://127.0.0.1:8137

# Or stay on Zebra RPC (default, no extra config needed)
# export ZEBRA_RPC_URL=http://127.0.0.1:8232
```

The backend is created once in `src/main.rs` via the factory function in `src/node.rs`:

```rust
pub fn create_backend(config: &Config) -> Box<dyn NodeBackend> {
    if let Some(ref zaino_url) = config.zaino_grpc_url {
        tracing::info!("Scanner backend: Zaino gRPC at {}", zaino_url);
        Box::new(ZainoBackend::new(zaino_url))
    } else {
        tracing::info!("Scanner backend: Zebra RPC at {}", config.zebra_rpc_url);
        Box::new(ZebraRpcBackend::new(&config.zebra_rpc_url))
    }
}
```

Configuration fields in `src/config.rs`:

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `zebra_rpc_url` | `String` | `http://127.0.0.1:8232` | Zebra JSON-RPC endpoint |
| `zaino_grpc_url` | `Option<String>` | `None` | Zaino gRPC endpoint; enables Zaino when set |

---

## 2. NodeBackend Trait Abstraction

`src/node.rs` defines a trait that both backends implement:

```rust
#[async_trait]
pub trait NodeBackend: Send + Sync {
    async fn get_chain_height(&self) -> Result<u32>;
    async fn get_block_txids(&self, height: u32) -> Result<Vec<String>>;
    async fn get_raw_transaction(&self, txid: &str) -> Result<Vec<u8>>;
    async fn get_mempool_txids(&self) -> Result<Vec<String>>;
}
```

### ZebraRpcBackend

- Protocol: HTTP JSON-RPC
- Port: 8232 (default)
- Methods: `getblockchaininfo`, `getblock`, `getrawtransaction`, `getrawmempool`
- Fetches full block data per height, one RPC call per block

### ZainoBackend

- Protocol: gRPC (HTTP/2, protobuf)
- Port: 8137 (default)
- Service: `CompactTxStreamer` (lightwalletd-compatible)
- Methods: `GetLatestBlock`, `GetBlock`, `GetTransaction`, `GetMempoolTx`
- Uses compact block representations; raw tx fetched only when needed

The scanner in `src/scanner.rs` calls only the `NodeBackend` trait methods. It does not know or care which backend is active. Payment detection, invoice matching, leaf insertion, and anchor verification all operate on the same data structures regardless of transport.

---

## 3. Proto Files

ZAP1 compiles two protobuf files at build time via `tonic-build` (see `build.rs`):

| File | Package | Purpose |
|------|---------|---------|
| `proto/service.proto` | `cash.z.wallet.sdk.rpc` | `CompactTxStreamer` service definition |
| `proto/compact_formats.proto` | `cash.z.wallet.sdk.rpc` | `CompactBlock`, `CompactTx`, `CompactSaplingOutput`, `CompactOrchardAction` |

### Key CompactTxStreamer Methods Used by ZAP1

| Method | Request | Response | Usage |
|--------|---------|----------|-------|
| `GetLatestBlock` | `ChainSpec` | `BlockID` | Chain tip height |
| `GetBlock` | `BlockID` | `CompactBlock` | Block txids for scanner |
| `GetBlockRange` | `BlockRange` | stream `CompactBlock` | Batch block streaming during catch-up |
| `GetTransaction` | `TxFilter` | `RawTransaction` | Full raw tx for memo extraction and anchor verification |
| `GetMempoolTx` | `Exclude` | stream `CompactTx` | Mempool monitoring for unconfirmed payments |
| `GetLightdInfo` | `Empty` | `LightdInfo` | Server version, chain, block height |
| `GetLatestTreeState` | `Empty` | `TreeState` | Sapling + Orchard note commitment tree state |

Build configuration (`build.rs`):

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false) // client only
        .compile_protos(
            &["proto/service.proto", "proto/compact_formats.proto"],
            &["proto"],
        )?;
    Ok(())
}
```

---

## 4. Validation Results

### Test Infrastructure

- Zaino 0.2.0 (ZingoLabs ZainoD) on `127.0.0.1:8137`
- ZainoDB: 96 GB at `/mnt/zebra/zaino-db`
- Connected to Zebra 4.3.0 at `127.0.0.1:8232`
- Chain tip at validation: 3,289,945 (fully synced)

### Anchor Verification: 4/4 Pass

The `zaino_adapter` binary (`src/bin/zaino_adapter.rs`) fetches all ZAP1 anchors from the API, then verifies each one is retrievable via Zaino gRPC. For every anchor it:

1. Fetches the compact block at the anchor height via `GetBlock`
2. Confirms the anchor txid appears in the block
3. Fetches the full raw transaction via `GetTransaction`
4. Verifies the transaction data is non-empty

```
$ cargo run --bin zaino_adapter -- --zaino-url http://127.0.0.1:8137
zaino adapter: connecting to http://127.0.0.1:8137
anchors from API: 4
zaino chain tip: 3289945
  pass: anchor block=3286631 txid=...  leaves=1  tx_bytes=9482
  pass: anchor block=3286633 txid=...  leaves=2  tx_bytes=9531
  pass: anchor block=3288117 txid=...  leaves=3  tx_bytes=9498
  pass: anchor block=3290002 txid=...  leaves=4  tx_bytes=9445
  range: streamed 3372 blocks from 3286631 to 3290002 via zaino

result: 4 pass, 0 fail, 4 total anchors
```

### gRPC Endpoint Coverage

| Method | Result |
|--------|--------|
| `GetLightdInfo` | Version 0.2.0, chain main, block 3,289,945 |
| `GetLatestBlock` | Height 3,289,945, hash returned |
| `GetBlock(3286631)` | First anchor block, compact tx data present |
| `GetBlockRange(3286631-3286633)` | 3 blocks streamed correctly |
| `GetTransaction(ba63e44f...)` | Anchor tx at height 3,290,002, full raw data |
| `GetLatestTreeState` | Sapling + Orchard tree state at tip |

### Compact Block Streaming

Block range streaming from the first anchor block to the last (3,286,631 to 3,290,002) returned 3,372 compact blocks. All blocks contained valid compact transaction data with correct txid encoding (protocol-order bytes reversed to display-order hex).

---

## 5. Deploying Zaino Alongside Zebra

### Prerequisites

- Zebra 4.3.0+ synced to mainnet, RPC on `127.0.0.1:8232`
- Disk space for Zaino index DB (allocate 100+ GB for mainnet)

### Install Zaino

```bash
git clone https://github.com/ZingoLabs/zaino.git
cd zaino
cargo build --release --bin zainod
```

### Configuration

Zaino reads a TOML config file. Production config for this deployment:

```toml
backend = "fetch"
zebra_db_path = "<zebra-chain-data-path>"
network = "Mainnet"

[grpc_settings]
listen_address = "127.0.0.1:8137"

[validator_settings]
validator_grpc_listen_address = "127.0.0.1:18230"
validator_jsonrpc_listen_address = "127.0.0.1:8232"
validator_user = "xxxxxx"
validator_password = "xxxxxx"

[storage.database]
path = "<zaino-db-path>"
size = 384
```

Key configuration notes:

- `validator_jsonrpc_listen_address` must match Zebra's actual RPC port (`8232`, not the older default `18232`)
- Zaino does not replace Zebra; it sits alongside Zebra and re-exposes chain data over gRPC
- The `listen_address` is the gRPC endpoint that ZAP1 connects to

### Bring-Up Sequence

```bash
# 1. Ensure Zebra is synced and serving RPC
zebrad start

# 2. Create Zaino DB directory
mkdir -p /mnt/zebra/zaino-db

# 3. Start Zaino
zainod start --config zainod.toml

# 4. Verify Zaino is responding
grpcurl -plaintext 127.0.0.1:8137 cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo
```

### Systemd Service (Optional)

```ini
[Unit]
Description=Zaino indexer (zainod)
After=network.target zebrad.service

[Service]
ExecStart=/usr/local/bin/zainod start --config /etc/zaino/zainod.toml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## 6. Switching ZAP1 from Zebra to Zaino

### One Environment Variable

```bash
# Switch to Zaino
export ZAINO_GRPC_URL=http://127.0.0.1:8137

# Restart ZAP1
systemctl restart zap1  # or however you run it
```

That is the entire change. No code modifications, no recompilation, no database migration.

### Rollback

```bash
# Switch back to Zebra RPC
unset ZAINO_GRPC_URL

# Restart ZAP1
systemctl restart zap1
```

### Recommended Migration Path

1. Run Zaino in parallel with Zebra (Zaino needs Zebra anyway).
2. Keep production ZAP1 on Zebra RPC initially.
3. Start a staging ZAP1 instance with `ZAINO_GRPC_URL` set.
4. Compare: chain height, detected payments, mempool detections, scanner lag.
5. If parity holds, flip production to Zaino.
6. Retain Zebra RPC as the instant rollback path.

---

## 7. Backend Comparison

| | Zebra RPC | Zaino gRPC |
|---|---|---|
| Protocol | HTTP JSON-RPC | gRPC (HTTP/2, protobuf) |
| Block fetching | `getblock` per height (polling) | `GetBlockRange` streaming |
| Bandwidth | Full block data per request | Compact blocks (smaller payloads) |
| Latency | One round-trip per block | Streaming, lower per-block overhead |
| Mempool | `getrawmempool` polling | `GetMempoolTx` streaming |
| Raw tx access | `getrawtransaction` | `GetTransaction` |
| Maturity | Production (Zebra 4.3.0) | Production (Zaino 0.2.0, validated on mainnet) |
| Extra infra | None (Zebra only) | Requires Zaino alongside Zebra |
| Best for | Simple setups, minimal dependencies | Higher throughput, wallet-compatible scanning |

---

## 8. Architecture Diagram

```
                    +------------------+
                    |     ZAP1         |
                    |  src/scanner.rs  |
                    +--------+---------+
                             |
                    NodeBackend trait
                    (src/node.rs)
                             |
              +--------------+--------------+
              |                             |
     ZebraRpcBackend              ZainoBackend
     (JSON-RPC/HTTP)              (gRPC/HTTP2)
              |                             |
              v                             v
     +--------+--------+          +--------+--------+
     |   Zebra 4.3.0   |          |  Zaino 0.2.0    |
     | 127.0.0.1:8232  |          | 127.0.0.1:8137  |
     +-----------------+          +--------+--------+
                                           |
                                  reads from Zebra
                                  chain state + RPC
```

---

## 9. For Other Zcash Application Builders

The dual-backend pattern used by ZAP1 is reusable. To integrate Zaino into your own application:

1. Define a backend trait around the chain data your app needs (tip height, block txids, raw tx, mempool).
2. Implement the trait for Zebra RPC first (your existing path).
3. Add a Zaino implementation using the `CompactTxStreamer` gRPC service.
4. Switch via environment variable or config, not code changes.
5. The proto files in `zap1/proto/` are the standard lightwalletd definitions and can be reused directly.

Design rule: never mix chain-transport logic into application business logic. Keep scanning, trial decryption, invoice matching, and proof generation independent of the backend.

---

## 10. File Reference

| File | Purpose |
|------|---------|
| `src/node.rs` | `NodeBackend` trait, `ZebraRpcBackend`, `ZainoBackend` implementations |
| `src/config.rs` | Config struct with `zaino_grpc_url` field |
| `src/main.rs` | Backend creation at startup via `create_backend()` |
| `src/scanner.rs` | Scanner loop (backend-agnostic) |
| `src/bin/zaino_adapter.rs` | Validation tool: verifies all anchors via Zaino gRPC |
| `proto/service.proto` | `CompactTxStreamer` gRPC service definition |
| `proto/compact_formats.proto` | `CompactBlock`, `CompactTx` message definitions |
| `build.rs` | tonic-build proto compilation config |
