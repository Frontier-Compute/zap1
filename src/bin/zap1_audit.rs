use std::fs;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ProofBundle {
    protocol: String,
    version: String,
    leaf: BundleLeaf,
    proof: Vec<BundleProofStep>,
    root: BundleRoot,
    anchor: BundleAnchor,
}

#[derive(Debug, Deserialize)]
struct BundleLeaf {
    hash: String,
    event_type: String,
    wallet_hash: String,
    serial_number: Option<String>,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct BundleProofStep {
    hash: String,
    position: String,
}

#[derive(Debug, Deserialize)]
struct BundleRoot {
    hash: String,
    leaf_count: u64,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct BundleAnchor {
    txid: Option<String>,
    height: Option<u32>,
}

enum InputSource {
    File(String),
    Url(String),
}

#[tokio::main]
async fn main() -> Result<()> {
    let source = parse_args()?;
    let raw = match source {
        InputSource::File(path) => fs::read_to_string(&path)
            .with_context(|| format!("failed to read bundle file: {path}"))?,
        InputSource::Url(url) => reqwest::get(&url)
            .await
            .with_context(|| format!("failed to fetch bundle url: {url}"))?
            .error_for_status()
            .with_context(|| format!("bundle url returned error status: {url}"))?
            .text()
            .await
            .with_context(|| format!("failed to read bundle response body: {url}"))?,
    };

    let bundle: ProofBundle = serde_json::from_str(&raw).context("invalid proof bundle JSON")?;
    verify_bundle(&bundle)?;
    print_report(&bundle);
    Ok(())
}

fn parse_args() -> Result<InputSource> {
    let mut args = std::env::args().skip(1);
    let mut source = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bundle" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --bundle"))?;
                source = Some(InputSource::File(path));
            }
            "--bundle-url" => {
                let url = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --bundle-url"))?;
                source = Some(InputSource::Url(url));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    source.ok_or_else(|| anyhow!("usage: zap1_audit --bundle <proof.json> | --bundle-url <url>"))
}

fn verify_bundle(bundle: &ProofBundle) -> Result<()> {
    if bundle.protocol != "ZAP1" {
        return Err(anyhow!("unexpected protocol: {}", bundle.protocol));
    }

    let leaf = zap1_verify::hex_to_bytes32(&bundle.leaf.hash)
        .ok_or_else(|| anyhow!("invalid leaf hash hex"))?;
    let root = zap1_verify::hex_to_bytes32(&bundle.root.hash)
        .ok_or_else(|| anyhow!("invalid root hash hex"))?;

    let proof = bundle
        .proof
        .iter()
        .map(|step| {
            let hash = zap1_verify::hex_to_bytes32(&step.hash)
                .ok_or_else(|| anyhow!("invalid proof step hash hex: {}", step.hash))?;
            let position = match step.position.as_str() {
                "left" => zap1_verify::SiblingPosition::Left,
                "right" => zap1_verify::SiblingPosition::Right,
                other => return Err(anyhow!("invalid proof step position: {other}")),
            };
            Ok(zap1_verify::ProofStep { hash, position })
        })
        .collect::<Result<Vec<_>>>()?;

    if !zap1_verify::verify_proof(&leaf, &proof, &root) {
        return Err(anyhow!("proof verification failed"));
    }

    Ok(())
}

fn print_report(bundle: &ProofBundle) {
    println!("proof: ok");
    println!("bundle version: {}", bundle.version);
    println!("event type: {}", bundle.leaf.event_type);
    println!("leaf hash: {}", bundle.leaf.hash);
    println!("wallet hash: {}", bundle.leaf.wallet_hash);
    if let Some(serial) = &bundle.leaf.serial_number {
        println!("serial number: {}", serial);
    }
    println!("leaf created at: {}", bundle.leaf.created_at);
    println!("proof steps: {}", bundle.proof.len());
    println!("root hash: {}", bundle.root.hash);
    println!("root leaf count: {}", bundle.root.leaf_count);
    println!("root created at: {}", bundle.root.created_at);
    println!(
        "anchor txid: {}",
        bundle.anchor.txid.as_deref().unwrap_or("not anchored")
    );
    println!(
        "anchor height: {}",
        bundle
            .anchor
            .height
            .map(|h| h.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );
    println!();
    println!("next checks:");
    println!("- confirm txid and block height on a Zcash explorer or local node");
    println!("- confirm the transaction memo commits the same root");
    println!("- confirm the anchored root matches this bundle root");
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  zap1_audit --bundle <proof.json>");
    eprintln!("  zap1_audit --bundle-url <https://.../proof.json>");
}
