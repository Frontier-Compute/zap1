# Zaino Integration Guide

Date: 2026-03-28
Status: Integration guide for Zcash application builders
Sources:

- `src/node.rs`
- `src/config.rs`
- `src/main.rs`
- `src/scanner.rs`

## 1. Purpose

The reference implementation supports two scanner backends:

- direct Zebra JSON-RPC
- Zaino gRPC compact-block streaming

The backend boundary exists so payment detection logic does not need to change when moving from full-transaction polling to a lighter compact-block source.

## 2. Running Zaino Alongside Zebra

The current mainnet config is:

```toml
backend = 'fetch'
zebra_db_path = '<zebra-chain-data-path>'
network = 'Mainnet'

[grpc_settings]
listen_address = '127.0.0.1:8137'

[validator_settings]
validator_grpc_listen_address = '127.0.0.1:18230'
validator_jsonrpc_listen_address = '127.0.0.1:8232'
validator_user = 'xxxxxx'
validator_password = 'xxxxxx'

[storage.database]
path = '<zaino-db-path>'
size = 384
```

Operational meaning:

- Zebra chain state lives at the path configured in `zebra_db_path`
- Zaino cache / index DB lives at the path configured in `storage.database.path`
- Zaino serves lightwalletd-compatible gRPC on `127.0.0.1:8137`
- Zaino validates against Zebra JSON-RPC on `127.0.0.1:8232`

Bring-up sequence:

1. Make sure Zebra is already synced and serving RPC on `127.0.0.1:8232`.
2. Create the Zaino database path if needed.
3. Start Zaino with the mainnet config:

```bash
mkdir -p <zaino-db-path>
zainod start --config zainod.toml
```

4. Wait for Zaino to initialize and begin indexing.
5. Point `zap1` at Zaino by setting `ZAINO_GRPC_URL`.

Notes:

- `validator_jsonrpc_listen_address` must match Zebra’s actual RPC port. In this deployment that is `127.0.0.1:8232`, not Zebra’s older default `18232`.
- Zaino does not replace Zebra. It sits alongside Zebra and re-exposes chain data over gRPC in a lightwalletd-compatible form.

## 3. Backend Switching in zap1

Backend selection is env-driven.

In `src/config.rs`:

- `ZEBRA_RPC_URL` defaults to `http://127.0.0.1:18232`
- `ZAINO_GRPC_URL` is optional

In `src/node.rs`:

```rust
pub fn create_backend(config: &crate::config::Config) -> Box<dyn NodeBackend> {
    if let Some(ref zaino_url) = config.zaino_grpc_url {
        tracing::info!("Scanner backend: Zaino gRPC at {}", zaino_url);
        Box::new(ZainoBackend::new(zaino_url))
    } else {
        tracing::info!("Scanner backend: Zebra RPC at {}", config.zebra_rpc_url);
        Box::new(ZebraRpcBackend::new(&config.zebra_rpc_url))
    }
}
```

In `src/main.rs` the scanner backend is created once at startup and passed into the scan loop.

To switch `zap1` to Zaino:

```bash
export ZAINO_GRPC_URL=http://127.0.0.1:8137
```

To stay on direct Zebra RPC:

- do not set `ZAINO_GRPC_URL`
- optionally set `ZEBRA_RPC_URL=http://127.0.0.1:8232` if your Zebra RPC is not on the old default

Important current behavior:

- if `ZAINO_GRPC_URL` is set, `zap1` uses Zaino
- otherwise it falls back to Zebra RPC

## 4. NodeBackend Architecture

`src/node.rs` defines the abstraction:

```rust
#[async_trait]
pub trait NodeBackend: Send + Sync {
    async fn get_chain_height(&self) -> Result<u32>;
    async fn get_block_txids(&self, height: u32) -> Result<Vec<String>>;
    async fn get_raw_transaction(&self, txid: &str) -> Result<Vec<u8>>;
    async fn get_mempool_txids(&self) -> Result<Vec<String>>;
}
```

Two implementations exist.

`ZebraRpcBackend`

- direct JSON-RPC over HTTP
- `getblockchaininfo` for tip height
- `getblock` for block txids
- `getrawtransaction` for full raw tx bytes
- `getrawmempool` for mempool txids

`ZainoBackend`

- gRPC client over the lightwalletd-compatible `CompactTxStreamer` service
- `GetLatestBlock` for chain tip
- `GetBlock` for compact block txids
- `GetTransaction` for full tx bytes when a tx needs deeper inspection
- `GetMempoolTx` streaming for mempool txids

Why the trait matters:

- scanner logic in `src/scanner.rs` does not care whether chain data came from Zebra RPC or Zaino gRPC
- payment detection, trial decryption, invoice matching, and leaf insertion remain unchanged
- only the chain data transport changes

## 5. Performance Model

### Current path: per-block RPC polling

Current scanner loop characteristics from `src/scanner.rs`:

- wake interval: `15` seconds
- chain source: Zebra JSON-RPC by default
- scans blocks in batches up to `500`
- fetches block txids, then fetches each raw transaction individually
- also scans mempool for faster unconfirmed payment detection

Cost profile:

- one block call plus many transaction calls
- heavier JSON serialization / deserialization
- repeated full raw-tx fetches over HTTP
- good for correctness, less efficient for sustained catch-up or higher chain traffic

### Zaino path: compact-block gRPC

Zaino path characteristics:

- gRPC transport instead of HTTP JSON-RPC
- block txids come from compact blocks
- mempool data comes from streaming RPC
- raw transactions are fetched only when needed by the scanner backend
- lighter per-block metadata path than direct full-RPC polling

Why this is better:

- less overhead than repeated JSON-RPC calls
- lighter block representation
- better fit for trial-decryption style scanning workloads
- closer to the architecture already used by lightwalletd-style consumers

Practical summary:

- Zebra RPC polling is simpler and already production-proven in the reference implementation
- Zaino should reduce bandwidth and request overhead, especially during catch-up and sustained polling
- the exact gain depends on chain activity, mempool size, and how often raw tx fetches remain necessary after adapter tuning

## 6. Migration Steps for zap1

Recommended migration path:

1. Run Zaino in parallel with Zebra.
2. Keep production `zap1` on Zebra RPC first.
3. Start a staging `zap1` instance with:

```bash
export ZAINO_GRPC_URL=http://127.0.0.1:8137
export ZEBRA_RPC_URL=http://127.0.0.1:8232
```

4. Compare:
   - reported chain height
   - detected invoice payments
   - mempool detections
   - leaf creation timing
   - scanner lag

5. If parity holds, flip the production scanner to `ZAINO_GRPC_URL`.
6. Retain Zebra RPC as the rollback path.

Rollback is trivial:

- unset `ZAINO_GRPC_URL`
- restart `zap1`

## 7. Migration Steps for Other Zcash App Builders

If your app already talks to Zebra directly:

1. Define a backend trait like `NodeBackend` around the minimal chain data your app actually needs.
2. Keep your application logic backend-agnostic.
3. Implement a Zebra RPC backend first.
4. Add a Zaino backend that speaks the lightwalletd-compatible gRPC interface.
5. Switch via configuration, not code changes.

Recommended minimum interface:

- chain tip height
- block transaction IDs or compact block payloads
- raw transaction fetch
- mempool transaction enumeration

Design rule:

- never mix chain-transport logic into application business logic
- keep invoice matching, note trial decryption, Merkle insertion, and proof generation independent of the backend

## 8. Real Values in This Deployment

Current deployment-specific values from the existing config:

- Zebra chain DB: configured per deployment
- Zaino DB: configured per deployment
- Zaino gRPC: `127.0.0.1:8137`
- Zebra RPC consumed by Zaino: `127.0.0.1:8232`
- `zap1` backend switch env var: `ZAINO_GRPC_URL`

These values are deployment-specific, but the architecture is general.
