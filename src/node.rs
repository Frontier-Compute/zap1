//! Node backend abstraction for nsm1 scanner.
//!
//! Provides a trait `NodeBackend` that the scanner uses to fetch chain data.
//! Two implementations:
//! - `ZebraRpcBackend`: direct JSON-RPC to Zebra (current default)
//! - `ZainoBackend`: gRPC to Zaino compact block indexer (lightwalletd-compatible)

use anyhow::{Context, Result};
use async_trait::async_trait;

/// Abstraction over the chain data source used by the scanner.
///
/// Both Zebra RPC and Zaino gRPC implement this trait, allowing the scanner
/// to swap backends without changing its payment detection logic.
#[async_trait]
pub trait NodeBackend: Send + Sync {
    /// Get the current chain tip height.
    async fn get_chain_height(&self) -> Result<u32>;

    /// Get the list of transaction IDs in a block at the given height.
    async fn get_block_txids(&self, height: u32) -> Result<Vec<String>>;

    /// Get a raw transaction by txid (returns serialized bytes).
    async fn get_raw_transaction(&self, txid: &str) -> Result<Vec<u8>>;

    /// Get mempool transaction IDs.
    async fn get_mempool_txids(&self) -> Result<Vec<String>>;
}

// Zebra JSON-RPC backend (existing behavior)

pub struct ZebraRpcBackend {
    client: reqwest::Client,
    url: String,
}

impl ZebraRpcBackend {
    pub fn new(url: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            client,
            url: url.to_string(),
        }
    }

    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp = self
            .client
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .context("RPC request failed")?;

        let json: serde_json::Value = resp.json().await.context("RPC response parse failed")?;

        if let Some(error) = json.get("error") {
            if !error.is_null() {
                anyhow::bail!("RPC error: {}", error);
            }
        }

        Ok(json["result"].clone())
    }
}

#[async_trait]
impl NodeBackend for ZebraRpcBackend {
    async fn get_chain_height(&self) -> Result<u32> {
        let result = self.rpc_call("getblockchaininfo", serde_json::json!([])).await?;
        let height = result["blocks"]
            .as_u64()
            .context("Missing blocks field")?;
        Ok(height as u32)
    }

    async fn get_block_txids(&self, height: u32) -> Result<Vec<String>> {
        let result = self
            .rpc_call("getblock", serde_json::json!([format!("{}", height), 1]))
            .await?;

        let txids: Vec<String> = result["tx"]
            .as_array()
            .context("Missing tx array")?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        Ok(txids)
    }

    async fn get_raw_transaction(&self, txid: &str) -> Result<Vec<u8>> {
        let result = self
            .rpc_call("getrawtransaction", serde_json::json!([txid, 0]))
            .await?;

        let hex_str = result.as_str().context("Expected hex string")?;
        let bytes = hex::decode(hex_str).context("Invalid hex in raw transaction")?;
        Ok(bytes)
    }

    async fn get_mempool_txids(&self) -> Result<Vec<String>> {
        let result = self.rpc_call("getrawmempool", serde_json::json!([])).await?;
        let txids: Vec<String> = result
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(txids)
    }
}

// Zaino gRPC backend (compact block indexer)

/// Zaino backend using the lightwalletd-compatible gRPC protocol.
///
/// Connects to a Zaino instance serving CompactTxStreamer on the configured
/// address (default: 127.0.0.1:8137).
pub struct ZainoBackend {
    uri: String,
}

impl ZainoBackend {
    pub fn new(uri: &str) -> Self {
        Self {
            uri: uri.to_string(),
        }
    }

    /// Create a new gRPC client connection. We create per-call to avoid
    /// holding a long-lived connection that may go stale.
    async fn connect(
        &self,
    ) -> Result<CompactTxStreamerClient<tonic::transport::Channel>> {
        let channel = tonic::transport::Channel::from_shared(self.uri.clone())
            .context("Invalid Zaino URI")?
            .connect()
            .await
            .context("Failed to connect to Zaino gRPC")?;
        Ok(CompactTxStreamerClient::new(channel))
    }
}

#[async_trait]
impl NodeBackend for ZainoBackend {
    async fn get_chain_height(&self) -> Result<u32> {
        let mut client = self.connect().await?;
        let resp = client
            .get_latest_block(ChainSpec {})
            .await
            .context("GetLatestBlock failed")?;
        let block_id = resp.into_inner();
        Ok(block_id.height as u32)
    }

    async fn get_block_txids(&self, height: u32) -> Result<Vec<String>> {
        let mut client = self.connect().await?;
        let resp = client
            .get_block(BlockId {
                height: height as u64,
                hash: vec![],
            })
            .await
            .context("GetBlock failed")?;
        let block = resp.into_inner();

        // Extract txids from CompactBlock - txid bytes are in protocol order,
        // we need to reverse and hex-encode for display format
        let txids: Vec<String> = block
            .vtx
            .iter()
            .map(|ctx| {
                let mut txid_bytes = ctx.txid.clone();
                txid_bytes.reverse(); // protocol order → display order
                hex::encode(txid_bytes)
            })
            .collect();

        Ok(txids)
    }

    async fn get_raw_transaction(&self, txid: &str) -> Result<Vec<u8>> {
        let mut client = self.connect().await?;

        // Convert display-order hex txid to protocol-order bytes
        let mut txid_bytes = hex::decode(txid).context("Invalid txid hex")?;
        txid_bytes.reverse(); // display order → protocol order

        let resp = client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: txid_bytes,
            })
            .await
            .context("GetTransaction failed")?;

        Ok(resp.into_inner().data)
    }

    async fn get_mempool_txids(&self) -> Result<Vec<String>> {
        let mut client = self.connect().await?;

        let request = GetMempoolTxRequest {
            exclude_txid_suffixes: vec![],
            pool_types: vec![], // default: shielded only
        };

        let mut stream = client
            .get_mempool_tx(request)
            .await
            .context("GetMempoolTx failed")?
            .into_inner();

        let mut txids = Vec::new();
        while let Some(ctx) = stream.message().await? {
            let mut txid_bytes = ctx.txid;
            txid_bytes.reverse();
            txids.push(hex::encode(txid_bytes));
        }

        Ok(txids)
    }
}

// gRPC type stubs - generated from service.proto / compact_formats.proto
// These match the lightwalletd proto definitions. In a full build, these would
// come from tonic-build + prost codegen. For now, we define the minimal types
// needed for the CompactTxStreamer client.

pub mod proto {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

use proto::compact_tx_streamer_client::CompactTxStreamerClient;
use proto::{BlockId, ChainSpec, GetMempoolTxRequest, TxFilter};

// Factory

/// Create a NodeBackend from configuration.
pub fn create_backend(config: &crate::config::Config) -> Box<dyn NodeBackend> {
    if let Some(ref zaino_url) = config.zaino_grpc_url {
        tracing::info!("Scanner backend: Zaino gRPC at {}", zaino_url);
        Box::new(ZainoBackend::new(zaino_url))
    } else {
        tracing::info!("Scanner backend: Zebra RPC at {}", config.zebra_rpc_url);
        Box::new(ZebraRpcBackend::new(&config.zebra_rpc_url))
    }
}
