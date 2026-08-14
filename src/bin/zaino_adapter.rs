//! Zaino compact block adapter for ZAP1.
//!
//! Connects to a Zaino gRPC endpoint and checks whether API-recorded
//! transaction references are retrievable through the compact-block path.
//! This does not inspect encrypted memo contents or bind a root to a transaction.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

mod proto {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

use proto::compact_tx_streamer_client::CompactTxStreamerClient;
use proto::{BlockId, BlockRange, ChainSpec, TxFilter};

#[derive(Debug, Deserialize)]
struct AnchorHistoryResponse {
    anchors: Vec<AnchorRecord>,
    total: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AnchorRecord {
    height: Option<u32>,
    leaf_count: usize,
    root: String,
    txid: Option<String>,
}

struct Cli {
    zaino_url: String,
    api_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args()?;

    println!("zaino adapter: connecting to {}", cli.zaino_url);

    // fetch anchor history from ZAP1 API
    let anchors: AnchorHistoryResponse = reqwest::get(format!("{}/anchor/history", cli.api_url))
        .await
        .context("failed to fetch anchor history")?
        .json()
        .await
        .context("invalid anchor history JSON")?;

    println!("anchors from API: {}", anchors.total);
    if anchors.total != anchors.anchors.len() {
        return Err(anyhow!(
            "anchor history total {} does not match {} returned records",
            anchors.total,
            anchors.anchors.len()
        ));
    }

    // connect to zaino
    let channel = tonic::transport::Channel::from_shared(cli.zaino_url.clone())
        .context("invalid zaino URI")?
        .connect()
        .await
        .context("failed to connect to zaino gRPC")?;
    let mut client = CompactTxStreamerClient::new(channel);

    // get chain tip via zaino
    let tip = client
        .get_latest_block(ChainSpec {})
        .await
        .context("GetLatestBlock failed")?
        .into_inner();
    println!("zaino chain tip: {}", tip.height);

    let mut pass = 0;
    let mut fail = 0;

    for anchor in &anchors.anchors {
        let height = match anchor.height {
            Some(h) => h,
            None => {
                println!("  skip: anchor has no height");
                continue;
            }
        };

        let txid_hex = match &anchor.txid {
            Some(t) => t.clone(),
            None => {
                println!("  skip: anchor at {} has no txid", height);
                continue;
            }
        };
        if txid_hex.len() != 64
            || !txid_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            println!("  FAIL: recorded transaction reference has a noncanonical txid");
            fail += 1;
            continue;
        }

        // fetch block via zaino compact block stream
        let block_resp = client
            .get_block(BlockId {
                height: height as u64,
                hash: vec![],
            })
            .await
            .with_context(|| format!("GetBlock failed for height {}", height))?;

        let block = block_resp.into_inner();
        let block_txids: Vec<String> = block
            .vtx
            .iter()
            .map(|ctx| {
                let mut bytes = ctx.txid.clone();
                bytes.reverse();
                hex::encode(bytes)
            })
            .collect();

        let found_in_block = block_txids.contains(&txid_hex);

        // fetch raw transaction via zaino
        let mut txid_bytes = hex::decode(&txid_hex).context("invalid txid hex")?;
        txid_bytes.reverse();

        let tx_resp = client
            .get_transaction(TxFilter {
                block: None,
                index: 0,
                hash: txid_bytes,
            })
            .await;

        let tx_ok = tx_resp.is_ok();
        let tx_size = tx_resp.map(|r| r.into_inner().data.len()).unwrap_or(0);

        if found_in_block && tx_ok && tx_size > 0 {
            println!(
                "  pass: recorded transaction reference block={} txid={}.. leaves={} tx_bytes={}",
                height,
                &txid_hex[..12],
                anchor.leaf_count,
                tx_size
            );
            pass += 1;
        } else {
            println!(
                "  FAIL: recorded transaction reference block={} txid={}.. in_block={} tx_ok={} tx_size={}",
                height,
                &txid_hex[..12],
                found_in_block,
                tx_ok,
                tx_size
            );
            fail += 1;
        }
    }

    // test block range streaming
    if let Some(first) = anchors.anchors.first() {
        if let Some(last) = anchors.anchors.last() {
            if let (Some(start_h), Some(end_h)) = (first.height, last.height) {
                let range_resp = client
                    .get_block_range(BlockRange {
                        start: Some(BlockId {
                            height: start_h as u64,
                            hash: vec![],
                        }),
                        end: Some(BlockId {
                            height: end_h as u64,
                            hash: vec![],
                        }),
                        pool_types: vec![],
                    })
                    .await
                    .context("GetBlockRange failed")?;

                let mut stream = range_resp.into_inner();
                let mut block_count = 0u32;
                while let Some(_block) = stream.message().await? {
                    block_count += 1;
                }

                println!(
                    "  range: streamed {} blocks from {} to {} via zaino",
                    block_count, start_h, end_h
                );
            }
        }
    }

    println!();
    println!(
        "result: {} pass, {} fail, {} total anchors",
        pass, fail, anchors.total
    );

    if fail > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn parse_args() -> Result<Cli> {
    let mut args = std::env::args().skip(1);
    let mut zaino_url = String::from("http://127.0.0.1:8137");
    let mut api_url = String::from("http://127.0.0.1:3080");

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--zaino-url" => {
                zaino_url = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --zaino-url"))?;
            }
            "--api-url" => {
                api_url = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --api-url"))?;
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    Ok(Cli { zaino_url, api_url })
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  zaino_adapter");
    eprintln!("  zaino_adapter --zaino-url http://127.0.0.1:8137 --api-url http://127.0.0.1:3080");
}
