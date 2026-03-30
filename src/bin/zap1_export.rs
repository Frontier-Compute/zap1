//! ZAP1 selective disclosure export.
//!
//! Generates scoped audit packages from attestation history.
//! An operator selects which leaves to disclose, and the tool
//! produces a self-contained package with proof bundles and
//! witness data that a counterparty can verify independently.
//!
//! Use cases:
//! - auditor wants to see hosting payment history for a serial
//! - regulator wants proof of program entry for a wallet hash
//! - counterparty wants ownership verification for a transfer
//! - investor wants to see deployment status across a cohort

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct AuditPackage {
    protocol: &'static str,
    generated_at: String,
    scope: String,
    proofs: Vec<ProofEntry>,
    verification: VerificationInfo,
}

#[derive(Debug, Serialize)]
struct ProofEntry {
    leaf_hash: String,
    event_type: String,
    wallet_hash: String,
    serial_number: Option<String>,
    created_at: String,
    proof_steps: Vec<serde_json::Value>,
    root: String,
    anchor_txid: Option<String>,
    anchor_height: Option<u32>,
    witness: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct VerificationInfo {
    sdk: &'static str,
    crate_url: &'static str,
    memo_decoder: &'static str,
    procedure: Vec<&'static str>,
}

#[derive(Debug, Deserialize)]
struct ApiProofBundle {
    leaf: ApiLeaf,
    proof: Vec<ApiProofStep>,
    root: ApiRoot,
    anchor: ApiAnchor,
}

#[derive(Debug, Deserialize)]
struct ApiLeaf {
    hash: String,
    event_type: String,
    wallet_hash: String,
    serial_number: Option<String>,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct ApiProofStep {
    hash: String,
    position: String,
}

#[derive(Debug, Deserialize)]
struct ApiRoot {
    hash: String,
}

#[derive(Debug, Deserialize)]
struct ApiAnchor {
    txid: Option<String>,
    height: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct LifecycleResponse {
    events: Vec<LifecycleEvent>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct LifecycleEvent {
    leaf_hash: String,
    event_type: String,
    serial_number: Option<String>,
    created_at: Option<String>,
    anchored: Option<bool>,
}

struct Cli {
    api_url: String,
    wallet_hash: Option<String>,
    serial: Option<String>,
    event_types: Vec<String>,
    output: Option<String>,
    profile: Option<String>,
}

fn apply_profile(profile: &str) -> Vec<String> {
    match profile {
        "auditor" => vec![
            "PROGRAM_ENTRY",
            "OWNERSHIP_ATTEST",
            "HOSTING_PAYMENT",
            "SHIELD_RENEWAL",
            "CONTRACT_ANCHOR",
            "EXIT",
        ],
        "counterparty" => vec!["PROGRAM_ENTRY", "OWNERSHIP_ATTEST", "DEPLOYMENT"],
        "member" => vec![
            "PROGRAM_ENTRY",
            "OWNERSHIP_ATTEST",
            "HOSTING_PAYMENT",
            "SHIELD_RENEWAL",
        ],
        "regulator" => vec![
            "PROGRAM_ENTRY",
            "OWNERSHIP_ATTEST",
            "CONTRACT_ANCHOR",
            "HOSTING_PAYMENT",
            "SHIELD_RENEWAL",
            "TRANSFER",
            "EXIT",
        ],
        _ => vec![],
    }
    .into_iter()
    .map(String::from)
    .collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // apply profile if set
    let mut cli = cli;
    if let Some(ref profile) = cli.profile {
        if cli.event_types.is_empty() {
            cli.event_types = apply_profile(profile);
            if cli.event_types.is_empty() {
                return Err(anyhow!(
                    "unknown profile: {profile}. use: auditor, counterparty, member, regulator"
                ));
            }
            eprintln!("profile '{}': filtering to {:?}", profile, cli.event_types);
        }
    }

    // get leaf hashes and lifecycle events
    let (leaf_hashes, leaf_events) = collect_leaf_hashes(&client, &cli).await?;

    if leaf_hashes.is_empty() {
        eprintln!("no matching leaves found");
        std::process::exit(1);
    }

    eprintln!("exporting {} proof bundles", leaf_hashes.len());

    // fetch proof bundles for each leaf
    let mut proofs = Vec::new();
    for hash in &leaf_hashes {
        let url = format!("{}/verify/{}/proof.json", cli.api_url, hash);
        let resp = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failed to fetch proof for {}", &hash[..12]))?;

        if !resp.status().is_success() {
            eprintln!("  skip {}: HTTP {}", &hash[..12], resp.status());
            continue;
        }

        let bundle: ApiProofBundle = resp
            .json()
            .await
            .with_context(|| format!("invalid proof JSON for {}", &hash[..12]))?;

        // find the lifecycle event for this leaf to get witness fields
        let lifecycle_event = leaf_events.iter().find(|e| e.leaf_hash == *hash);

        proofs.push(ProofEntry {
            leaf_hash: bundle.leaf.hash,
            event_type: bundle.leaf.event_type,
            wallet_hash: bundle.leaf.wallet_hash,
            serial_number: bundle.leaf.serial_number,
            created_at: bundle.leaf.created_at,
            proof_steps: bundle
                .proof
                .into_iter()
                .map(|s| serde_json::json!({"hash": s.hash, "position": s.position}))
                .collect(),
            root: bundle.root.hash,
            anchor_txid: bundle.anchor.txid,
            anchor_height: bundle.anchor.height,
            witness: serde_json::json!({
                "wallet_hash_preimage": cli.wallet_hash,
                "serial_number": lifecycle_event.and_then(|e| e.serial_number.clone()),
                "hash_function": "BLAKE2b-256",
                "personalization": "NordicShield_",
                "recompute": "hash(type_byte || length_prefixed_fields) with NordicShield_ personalization",
            }),
        });
    }

    let scope = match (&cli.wallet_hash, &cli.serial) {
        (Some(wh), Some(sn)) => format!("wallet={} serial={}", &wh[..12.min(wh.len())], sn),
        (Some(wh), None) => format!("wallet={}", &wh[..12.min(wh.len())]),
        (None, Some(sn)) => format!("serial={}", sn),
        (None, None) => "all".to_string(),
    };

    let package = AuditPackage {
        protocol: "ZAP1",
        generated_at: chrono::Utc::now().to_rfc3339(),
        scope,
        proofs,
        verification: VerificationInfo {
            sdk: "zap1-verify",
            crate_url: "https://crates.io/crates/zap1-verify",
            memo_decoder: "https://crates.io/crates/zcash-memo-decode",
            procedure: vec![
                "for each proof entry, verify the Merkle proof from leaf_hash to root",
                "use BLAKE2b-256 with NordicShield_MRK personalization for tree nodes",
                "confirm the root matches the anchor_txid on Zcash mainnet",
                "confirm the anchor_txid is mined at anchor_height",
                "optionally use zap1_schema --emit-witness to verify preimage fields",
            ],
        },
    };

    let json = serde_json::to_string_pretty(&package)?;

    if let Some(path) = &cli.output {
        std::fs::write(path, &json).with_context(|| format!("failed to write {path}"))?;
        eprintln!("wrote audit package to {path}");
    } else {
        println!("{json}");
    }

    Ok(())
}

async fn collect_leaf_hashes(
    client: &reqwest::Client,
    cli: &Cli,
) -> Result<(Vec<String>, Vec<LifecycleEvent>)> {
    if let Some(wh) = &cli.wallet_hash {
        let url = format!("{}/lifecycle/{}", cli.api_url, wh);
        let resp = client
            .get(&url)
            .send()
            .await
            .context("failed to fetch lifecycle")?;
        let body: LifecycleResponse = resp.json().await.context("invalid lifecycle JSON")?;

        let filtered: Vec<LifecycleEvent> = body
            .events
            .into_iter()
            .filter(|e| cli.event_types.is_empty() || cli.event_types.contains(&e.event_type))
            .collect();
        let hashes: Vec<String> = filtered.iter().map(|e| e.leaf_hash.clone()).collect();

        Ok((hashes, filtered))
    } else {
        Err(anyhow!("--wallet-hash required to scope the export"))
    }
}

fn parse_args() -> Result<Cli> {
    let mut args = std::env::args().skip(1);
    let mut api_url = String::from("http://127.0.0.1:3080");
    let mut wallet_hash = None;
    let mut serial = None;
    let mut event_types = Vec::new();
    let mut output = None;
    let mut profile = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--api-url" => {
                api_url = args
                    .next()
                    .ok_or_else(|| anyhow!("missing --api-url value"))?;
            }
            "--wallet-hash" => {
                wallet_hash = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("missing --wallet-hash value"))?,
                );
            }
            "--serial" => {
                serial = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("missing --serial value"))?,
                );
            }
            "--event-type" => {
                event_types.push(
                    args.next()
                        .ok_or_else(|| anyhow!("missing --event-type value"))?,
                );
            }
            "--output" | "-o" => {
                output = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("missing --output value"))?,
                );
            }
            "--profile" => {
                profile = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("missing --profile value"))?,
                );
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    Ok(Cli {
        api_url,
        wallet_hash,
        serial,
        event_types,
        output,
        profile,
    })
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  zap1_export --wallet-hash <hash>");
    eprintln!("  zap1_export --wallet-hash <hash> --profile auditor");
    eprintln!("  zap1_export --wallet-hash <hash> --profile counterparty -o package.json");
    eprintln!("  zap1_export --wallet-hash <hash> --event-type HOSTING_PAYMENT");
    eprintln!();
    eprintln!("Profiles: auditor, counterparty, member, regulator");
    eprintln!("Each profile selects a predefined set of event types to disclose.");
    eprintln!("Verify offline: zap1_audit --export package.json");
}
