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
    Bundle(String),
    BundleUrl(String),
    ExportFile(String),
}

#[derive(Debug, Deserialize)]
struct AuditPackage {
    proofs: Vec<ExportProof>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ExportProof {
    leaf_hash: String,
    event_type: String,
    proof_steps: Vec<BundleProofStep>,
    root: String,
    anchor_txid: Option<String>,
    anchor_height: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let source = parse_args()?;
    match source {
        InputSource::Bundle(path) => {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read bundle file: {path}"))?;
            let bundle: ProofBundle =
                serde_json::from_str(&raw).context("invalid proof bundle JSON")?;
            verify_bundle(&bundle)?;
            print_report(&bundle);
        }
        InputSource::BundleUrl(url) => {
            let raw = reqwest::get(&url)
                .await
                .with_context(|| format!("failed to fetch bundle url: {url}"))?
                .error_for_status()
                .with_context(|| format!("bundle url returned error status: {url}"))?
                .text()
                .await
                .with_context(|| format!("failed to read bundle response body: {url}"))?;
            let bundle: ProofBundle =
                serde_json::from_str(&raw).context("invalid proof bundle JSON")?;
            verify_bundle(&bundle)?;
            print_report(&bundle);
        }
        InputSource::ExportFile(path) => {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read export file: {path}"))?;
            let package: AuditPackage =
                serde_json::from_str(&raw).context("invalid export package JSON")?;
            verify_export(&package)?;
        }
    }
    Ok(())
}

fn verify_export(package: &AuditPackage) -> Result<()> {
    let mut pass = 0u32;
    let mut fail = 0u32;

    for proof in &package.proofs {
        let leaf = zap1_verify::hex_to_bytes32(&proof.leaf_hash)
            .ok_or_else(|| anyhow!("invalid leaf hash: {}", &proof.leaf_hash[..16]))?;
        let root = zap1_verify::hex_to_bytes32(&proof.root)
            .ok_or_else(|| anyhow!("invalid root hash: {}", &proof.root[..16]))?;

        let steps: Vec<zap1_verify::ProofStep> = proof
            .proof_steps
            .iter()
            .map(|s| {
                let hash = zap1_verify::hex_to_bytes32(&s.hash)
                    .ok_or_else(|| anyhow!("invalid step hash"))?;
                let position = match s.position.as_str() {
                    "left" => zap1_verify::SiblingPosition::Left,
                    "right" => zap1_verify::SiblingPosition::Right,
                    other => return Err(anyhow!("invalid position: {other}")),
                };
                Ok(zap1_verify::ProofStep { hash, position })
            })
            .collect::<Result<Vec<_>>>()?;

        let valid = zap1_verify::verify_proof(&leaf, &steps, &root);
        if valid {
            println!(
                "pass: {} {} anchor={}",
                proof.event_type,
                &proof.leaf_hash[..12],
                proof
                    .anchor_height
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "none".into())
            );
            pass += 1;
        } else {
            println!(
                "FAIL: {} {} proof verification failed",
                proof.event_type,
                &proof.leaf_hash[..12]
            );
            fail += 1;
        }
    }

    println!();
    println!("{pass} pass, {fail} fail");

    if fail > 0 {
        std::process::exit(1);
    }
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
                source = Some(InputSource::Bundle(path));
            }
            "--bundle-url" => {
                let url = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --bundle-url"))?;
                source = Some(InputSource::BundleUrl(url));
            }
            "--export" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --export"))?;
                source = Some(InputSource::ExportFile(path));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    source.ok_or_else(|| {
        anyhow!(
        "usage: zap1_audit --bundle <proof.json> | --bundle-url <url> | --export <package.json>"
    )
    })
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
    eprintln!("  zap1_audit --export <package.json>  (verify all proofs in an export package)");
}
