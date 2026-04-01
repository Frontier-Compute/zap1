# Zaino Integration Guide

How ZAP1 uses Zaino as a compact-block scanner backend, and how other Zcash applications can do the same.

## What Zaino Provides

Zaino (ZainoDB by ZingoLabs) implements the `CompactTxStreamer` gRPC interface - the same protocol that lightwalletd exposes. Any application that speaks this protocol can switch from lightwalletd to Zaino without code changes.

ZAP1 uses Zaino for two things:
1. **Scanning** - stream compact blocks to find shielded transactions matching a UFVK
2. **Anchor verification** - retrieve raw transactions to confirm anchor memos on-chain

## Setup

### Prerequisites

- Zebra 4.3.0+ synced to mainnet (RPC on 127.0.0.1:8232)
- Zaino built from source or from the ZingoLabs release

### Install Zaino

```bash
git clone https://github.com/ZingoLabs/zaino.git
cd zaino
cargo build --release --bin zainod
```

### Configure

Zaino reads its config from a TOML file. Minimal config:

```toml
[network]
type = "Mainnet"

[node]
zebra_rpc = "http://127.0.0.1:8232"

[server]
listen_address = "127.0.0.1:8137"
```

### Run

```bash
./target/release/zainod start --config zaino.toml
```

Or as a systemd service:

```ini
[Unit]
Description=Zaino indexer (zainod)
After=network.target

[Service]
ExecStart=/path/to/zainod start --config /path/to/zaino.toml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Using Zaino in Your Application

### gRPC Interface

Zaino exposes `CompactTxStreamer` on the configured listen address. The proto definition is at `zaino/proto/service.proto` or available from the lightwalletd repo.

Key methods:

| Method | Purpose |
|---|---|
| `GetLightdInfo` | Server version, chain, block height |
| `GetLatestBlock` | Current chain tip |
| `GetBlock(height)` | Single compact block with tx data |
| `GetBlockRange(start, end)` | Stream of compact blocks |
| `GetTransaction(txid)` | Full raw transaction bytes |
| `GetLatestTreeState` | Sapling + Orchard note commitment tree state |

### Rust Integration (tonic)

```rust
use tonic::transport::Channel;

mod proto {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

use proto::compact_tx_streamer_client::CompactTxStreamerClient;
use proto::{BlockId, BlockRange, ChainSpec};

async fn connect(url: &str) -> Result<CompactTxStreamerClient<Channel>> {
    let client = CompactTxStreamerClient::connect(url.to_string()).await?;
    Ok(client)
}

// Get server info
let info = client.get_lightd_info(ChainSpec {}).await?.into_inner();
println!("chain: {}, block: {}", info.chain_name, info.block_height);

// Stream blocks
let range = BlockRange {
    start: Some(BlockId { height: 3286631, hash: vec![] }),
    end: Some(BlockId { height: 3286640, hash: vec![] }),
};
let mut stream = client.get_block_range(range).await?.into_inner();
while let Some(block) = stream.message().await? {
    println!("block {} with {} txs", block.height, block.vtx.len());
}
```

### Dual Backend Pattern

ZAP1 abstracts the scanner backend so switching between Zebra RPC and Zaino requires only a config change:

```
# Zebra RPC (default)
ZEBRA_RPC_URL=http://127.0.0.1:8232

# Zaino gRPC (add this to enable)
ZAINO_GRPC_URL=http://127.0.0.1:8137
```

The scanner checks `ZAINO_GRPC_URL` at startup. If set, it uses compact block streaming. If not, it falls back to Zebra JSON-RPC polling. Both paths produce identical scanning results.

## Operational Comparison

| | Zebra RPC (JSON-RPC) | Zaino gRPC (CompactTxStreamer) |
|---|---|---|
| Protocol | HTTP JSON-RPC | gRPC (HTTP/2, protobuf) |
| Block fetching | `getblock` per height (polling) | `GetBlockRange` streaming |
| Bandwidth | Full block data | Compact blocks (smaller) |
| Latency | One round-trip per block | Streaming, lower per-block overhead |
| Maturity | Production (Zebra 4.3.0) | Production (Zaino 0.2.0, validated on mainnet) |
| Use when | Simple setup, no extra service | Higher throughput, wallet-compatible scanning |

## Validation

The `zaino_adapter` binary verifies that all ZAP1 anchors are retrievable via Zaino:

```bash
cargo run --bin zaino_adapter -- --zaino-url http://127.0.0.1:8137
```

This fetches every anchor transaction through Zaino gRPC and confirms the memo content matches the expected `ZAP1:09:{root}` format.

## For Other Z3 Stack Applications

If you're building on the Z3 stack (Zebra + Zaino + Zallet), the pattern here is reusable:

1. Define your scanning needs (which transactions, which memos, which note types)
2. Use `CompactTxStreamer` to stream blocks
3. Decode compact transactions to find relevant outputs
4. Fall back to `GetTransaction` for full transaction data when needed
5. Maintain your own state (ZAP1 uses SQLite; adapt to your storage)

The proto definitions and tonic client setup in `zap1/proto/` and `zap1/src/bin/zaino_adapter.rs` are MIT-licensed reference code.
