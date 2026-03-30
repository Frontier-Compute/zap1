//! Memo scanner: scan a block range via Zaino and classify all decryptable memos.
//!
//! Connects to Zaino gRPC, fetches compact blocks, retrieves raw transactions
//! for blocks with shielded outputs, and classifies any memos found.
//! Useful for explorers, indexers, and ecosystem tools that want to understand
//! what's in Zcash shielded memos without building their own parser.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};

use zcash_client_backend::decrypt_transaction;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

mod proto {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

use proto::compact_tx_streamer_client::CompactTxStreamerClient;
use proto::{BlockId, TxFilter};

struct Cli {
    zaino_url: String,
    ufvk: String,
    start_height: u32,
    end_height: Option<u32>,
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args()?;

    let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&MainNetwork, &cli.ufvk)
        .map_err(|e| anyhow!("invalid UFVK: {e}"))?;

    let channel = tonic::transport::Channel::from_shared(cli.zaino_url.clone())
        .context("invalid zaino URI")?
        .connect()
        .await
        .context("failed to connect to zaino")?;
    let mut client = CompactTxStreamerClient::new(channel);

    let end = match cli.end_height {
        Some(h) => h,
        None => {
            let tip = client
                .get_latest_block(proto::ChainSpec {})
                .await
                .context("failed to get chain tip")?
                .into_inner();
            tip.height as u32
        }
    };

    let mut ufvks: HashMap<u32, UnifiedFullViewingKey> = HashMap::new();
    ufvks.insert(0, ufvk);

    let mut found = 0u32;
    let mut scanned = 0u32;

    for height in cli.start_height..=end {
        let block = client
            .get_block(BlockId {
                height: height as u64,
                hash: vec![],
            })
            .await
            .with_context(|| format!("GetBlock failed at {height}"))?
            .into_inner();

        for ctx in &block.vtx {
            if ctx.outputs.is_empty() && ctx.actions.is_empty() {
                continue;
            }

            let mut txid_bytes = ctx.txid.clone();
            txid_bytes.reverse();
            let txid_hex = hex::encode(&txid_bytes);

            let raw = match client
                .get_transaction(TxFilter {
                    block: None,
                    index: 0,
                    hash: ctx.txid.clone(),
                })
                .await
            {
                Ok(resp) => resp.into_inner().data,
                Err(_) => continue,
            };

            let block_height = BlockHeight::from_u32(height);
            let branch_id = BranchId::for_height(&MainNetwork, block_height);
            let tx = match Transaction::read(&raw[..], branch_id) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let decrypted =
                decrypt_transaction(&MainNetwork, Some(block_height), None, &tx, &ufvks);

            for output in decrypted.orchard_outputs() {
                scanned += 1;
                let memo_bytes = output.memo().as_array();
                let decoded = zcash_memo_decode::decode(memo_bytes);
                let fmt = zcash_memo_decode::label(&decoded);

                if fmt == "empty" {
                    continue;
                }

                found += 1;

                if cli.json {
                    let entry = match &decoded {
                        zcash_memo_decode::MemoFormat::Text(s) => serde_json::json!({
                            "height": height,
                            "txid": txid_hex,
                            "format": fmt,
                            "text": s,
                        }),
                        zcash_memo_decode::MemoFormat::Attestation {
                            event_label,
                            payload_hash,
                            ..
                        } => serde_json::json!({
                            "height": height,
                            "txid": txid_hex,
                            "format": fmt,
                            "event": event_label,
                            "payload": hex::encode(payload_hash),
                        }),
                        _ => serde_json::json!({
                            "height": height,
                            "txid": txid_hex,
                            "format": fmt,
                        }),
                    };
                    println!("{}", serde_json::to_string(&entry)?);
                } else {
                    println!("{} {} {}", height, &txid_hex[..12], fmt);
                }
            }
        }
    }

    eprintln!(
        "scanned {} outputs across blocks {}-{}, found {} non-empty memos",
        scanned, cli.start_height, end, found
    );

    Ok(())
}

fn parse_args() -> Result<Cli> {
    let mut args = std::env::args().skip(1);
    let mut zaino_url = String::from("http://127.0.0.1:8137");
    let mut ufvk = std::env::var("UFVK").unwrap_or_default();
    let mut start_height = 0u32;
    let mut end_height: Option<u32> = None;
    let mut json = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--zaino-url" => {
                zaino_url = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --zaino-url"))?;
            }
            "--ufvk" => {
                ufvk = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --ufvk"))?;
            }
            "--start" => {
                start_height = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --start"))?
                    .parse()
                    .context("invalid --start value")?;
            }
            "--end" => {
                end_height = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("missing value for --end"))?
                        .parse()
                        .context("invalid --end value")?,
                );
            }
            "--json" => json = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    if ufvk.is_empty() {
        return Err(anyhow!("UFVK required via --ufvk or UFVK env var"));
    }

    Ok(Cli {
        zaino_url,
        ufvk,
        start_height,
        end_height,
        json,
    })
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  memo_scan --ufvk <ufvk> --start <height>");
    eprintln!("  memo_scan --ufvk <ufvk> --start <height> --end <height> --json");
    eprintln!("  UFVK=<ufvk> memo_scan --start 3286631 --end 3290000");
    eprintln!();
    eprintln!("Scans blocks via Zaino gRPC, decrypts memos with the given UFVK,");
    eprintln!("and classifies each memo using zcash-memo-decode.");
}
