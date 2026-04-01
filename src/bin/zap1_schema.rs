//! ZAP1 event schema validator.
//!
//! Validates event witness data against the deployed hash construction.
//! Given plaintext fields (wallet_hash, serial, month, year, etc), recomputes
//! the leaf hash and compares it to the expected value.
//!
//! This is the tool that closes the gap between "leaf hash exists in tree"
//! and "I can prove what that leaf means."

use std::fs;

use anyhow::{anyhow, Context, Result};
use blake2b_simd::Params;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct WitnessFile {
    events: Vec<EventWitness>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EventWitness {
    event_type: String,
    expected_hash: Option<String>,
    wallet_hash: Option<String>,
    serial_number: Option<String>,
    contract_sha256: Option<String>,
    facility_id: Option<String>,
    timestamp: Option<u64>,
    month: Option<u32>,
    year: Option<u32>,
    old_wallet_hash: Option<String>,
    new_wallet_hash: Option<String>,
    merkle_root: Option<String>,
    amount_zat: Option<u64>,
    validator_id: Option<String>,
    epoch: Option<u32>,
    proposal_id: Option<String>,
    proposal_hash: Option<String>,
    vote_commitment: Option<String>,
    result_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct ValidationResult {
    event_type: String,
    computed_hash: String,
    expected_hash: Option<String>,
    valid: bool,
    error: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_args()?;

    let raw = match &cli.source {
        Source::File(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read witness file: {path}"))?,
        Source::Url(url) => {
            reqwest::get(url)
                .await
                .with_context(|| format!("failed to fetch: {url}"))?
                .text()
                .await?
        }
    };

    let witness_file: WitnessFile = serde_json::from_str(&raw).context("invalid witness JSON")?;

    let mut results = Vec::new();
    let mut pass = 0;
    let mut fail = 0;

    for event in &witness_file.events {
        let result = validate_event(event);
        match &result {
            Ok(r) if r.valid => pass += 1,
            _ => fail += 1,
        }
        results.push(result.unwrap_or_else(|e| ValidationResult {
            event_type: event.event_type.clone(),
            computed_hash: String::new(),
            expected_hash: event.expected_hash.clone(),
            valid: false,
            error: Some(e.to_string()),
        }));
    }

    if cli.emit_witness {
        let witness_bundle: Vec<serde_json::Value> = witness_file
            .events
            .iter()
            .zip(results.iter())
            .map(|(event, result)| {
                serde_json::json!({
                    "event_type": event.event_type,
                    "computed_hash": result.computed_hash,
                    "valid": result.valid,
                    "personalization": "NordicShield_",
                    "hash_function": "BLAKE2b-256",
                    "preimage": {
                        "wallet_hash": event.wallet_hash,
                        "serial_number": event.serial_number,
                        "contract_sha256": event.contract_sha256,
                        "facility_id": event.facility_id,
                        "timestamp": event.timestamp,
                        "month": event.month,
                        "year": event.year,
                        "old_wallet_hash": event.old_wallet_hash,
                        "new_wallet_hash": event.new_wallet_hash,
                        "merkle_root": event.merkle_root,
                    },
                    "verification": {
                        "procedure": "recompute BLAKE2b-256 with type byte prefix and NordicShield_ personalization",
                        "sdk": "zap1-verify (crates.io) or zcash-memo-decode (crates.io)",
                    }
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&witness_bundle)?);
    } else if cli.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for r in &results {
            let status = if r.valid { "pass" } else { "FAIL" };
            println!(
                "{}: {} hash={}",
                status,
                r.event_type,
                &r.computed_hash[..16.min(r.computed_hash.len())]
            );
            if let Some(err) = &r.error {
                println!("  error: {}", err);
            }
        }
        println!();
        println!("{} pass, {} fail", pass, fail);
    }

    if fail > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn validate_event(event: &EventWitness) -> Result<ValidationResult> {
    let computed = match event.event_type.as_str() {
        "PROGRAM_ENTRY" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("PROGRAM_ENTRY requires wallet_hash"))?;
            hash_payload(0x01, wh.as_bytes())
        }
        "OWNERSHIP_ATTEST" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("OWNERSHIP_ATTEST requires wallet_hash"))?;
            let sn = event
                .serial_number
                .as_ref()
                .ok_or_else(|| anyhow!("OWNERSHIP_ATTEST requires serial_number"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(wh.len() as u16).to_be_bytes());
            payload.extend_from_slice(wh.as_bytes());
            payload.extend_from_slice(&(sn.len() as u16).to_be_bytes());
            payload.extend_from_slice(sn.as_bytes());
            hash_payload(0x02, &payload)
        }
        "CONTRACT_ANCHOR" => {
            let sn = event
                .serial_number
                .as_ref()
                .ok_or_else(|| anyhow!("CONTRACT_ANCHOR requires serial_number"))?;
            let cs = event
                .contract_sha256
                .as_ref()
                .ok_or_else(|| anyhow!("CONTRACT_ANCHOR requires contract_sha256"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(sn.len() as u16).to_be_bytes());
            payload.extend_from_slice(sn.as_bytes());
            payload.extend_from_slice(&(cs.len() as u16).to_be_bytes());
            payload.extend_from_slice(cs.as_bytes());
            hash_payload(0x03, &payload)
        }
        "DEPLOYMENT" => {
            let sn = event
                .serial_number
                .as_ref()
                .ok_or_else(|| anyhow!("DEPLOYMENT requires serial_number"))?;
            let fi = event
                .facility_id
                .as_ref()
                .ok_or_else(|| anyhow!("DEPLOYMENT requires facility_id"))?;
            let ts = event
                .timestamp
                .ok_or_else(|| anyhow!("DEPLOYMENT requires timestamp"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(sn.len() as u16).to_be_bytes());
            payload.extend_from_slice(sn.as_bytes());
            payload.extend_from_slice(&(fi.len() as u16).to_be_bytes());
            payload.extend_from_slice(fi.as_bytes());
            payload.extend_from_slice(&ts.to_be_bytes());
            hash_payload(0x04, &payload)
        }
        "HOSTING_PAYMENT" => {
            let sn = event
                .serial_number
                .as_ref()
                .ok_or_else(|| anyhow!("HOSTING_PAYMENT requires serial_number"))?;
            let month = event
                .month
                .ok_or_else(|| anyhow!("HOSTING_PAYMENT requires month"))?;
            let year = event
                .year
                .ok_or_else(|| anyhow!("HOSTING_PAYMENT requires year"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(sn.len() as u16).to_be_bytes());
            payload.extend_from_slice(sn.as_bytes());
            payload.extend_from_slice(&month.to_be_bytes());
            payload.extend_from_slice(&year.to_be_bytes());
            hash_payload(0x05, &payload)
        }
        "SHIELD_RENEWAL" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("SHIELD_RENEWAL requires wallet_hash"))?;
            let year = event
                .year
                .ok_or_else(|| anyhow!("SHIELD_RENEWAL requires year"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(wh.len() as u16).to_be_bytes());
            payload.extend_from_slice(wh.as_bytes());
            payload.extend_from_slice(&year.to_be_bytes());
            hash_payload(0x06, &payload)
        }
        "TRANSFER" => {
            let ow = event
                .old_wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("TRANSFER requires old_wallet_hash"))?;
            let nw = event
                .new_wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("TRANSFER requires new_wallet_hash"))?;
            let sn = event
                .serial_number
                .as_ref()
                .ok_or_else(|| anyhow!("TRANSFER requires serial_number"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(ow.len() as u16).to_be_bytes());
            payload.extend_from_slice(ow.as_bytes());
            payload.extend_from_slice(&(nw.len() as u16).to_be_bytes());
            payload.extend_from_slice(nw.as_bytes());
            payload.extend_from_slice(&(sn.len() as u16).to_be_bytes());
            payload.extend_from_slice(sn.as_bytes());
            hash_payload(0x07, &payload)
        }
        "EXIT" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("EXIT requires wallet_hash"))?;
            let sn = event
                .serial_number
                .as_ref()
                .ok_or_else(|| anyhow!("EXIT requires serial_number"))?;
            let ts = event
                .timestamp
                .ok_or_else(|| anyhow!("EXIT requires timestamp"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(wh.len() as u16).to_be_bytes());
            payload.extend_from_slice(wh.as_bytes());
            payload.extend_from_slice(&(sn.len() as u16).to_be_bytes());
            payload.extend_from_slice(sn.as_bytes());
            payload.extend_from_slice(&ts.to_be_bytes());
            hash_payload(0x08, &payload)
        }
        "MERKLE_ROOT" => {
            let root_hex = event
                .merkle_root
                .as_ref()
                .ok_or_else(|| anyhow!("MERKLE_ROOT requires merkle_root"))?;
            let root_bytes = hex::decode(root_hex).context("invalid merkle_root hex")?;
            if root_bytes.len() != 32 {
                return Err(anyhow!("merkle_root must be 32 bytes"));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&root_bytes);
            hash
        }
        "STAKING_DEPOSIT" | "STAKING_WITHDRAW" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("{} requires wallet_hash", event.event_type))?;
            let amt = event
                .amount_zat
                .ok_or_else(|| anyhow!("{} requires amount_zat", event.event_type))?;
            let vid = event
                .validator_id
                .as_ref()
                .ok_or_else(|| anyhow!("{} requires validator_id", event.event_type))?;
            let type_byte = if event.event_type == "STAKING_DEPOSIT" {
                0x0A
            } else {
                0x0B
            };
            let mut payload = Vec::new();
            payload.extend_from_slice(&(wh.len() as u16).to_be_bytes());
            payload.extend_from_slice(wh.as_bytes());
            payload.extend_from_slice(&amt.to_be_bytes());
            payload.extend_from_slice(&(vid.len() as u16).to_be_bytes());
            payload.extend_from_slice(vid.as_bytes());
            hash_payload(type_byte, &payload)
        }
        "STAKING_REWARD" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("STAKING_REWARD requires wallet_hash"))?;
            let amt = event
                .amount_zat
                .ok_or_else(|| anyhow!("STAKING_REWARD requires amount_zat"))?;
            let ep = event
                .epoch
                .ok_or_else(|| anyhow!("STAKING_REWARD requires epoch"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(wh.len() as u16).to_be_bytes());
            payload.extend_from_slice(wh.as_bytes());
            payload.extend_from_slice(&amt.to_be_bytes());
            payload.extend_from_slice(&ep.to_be_bytes());
            hash_payload(0x0C, &payload)
        }
        "GOVERNANCE_PROPOSAL" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("requires wallet_hash"))?;
            let pid = event
                .proposal_id
                .as_ref()
                .ok_or_else(|| anyhow!("requires proposal_id"))?;
            let ph = event
                .proposal_hash
                .as_ref()
                .ok_or_else(|| anyhow!("requires proposal_hash"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(wh.len() as u16).to_be_bytes());
            payload.extend_from_slice(wh.as_bytes());
            payload.extend_from_slice(&(pid.len() as u16).to_be_bytes());
            payload.extend_from_slice(pid.as_bytes());
            payload.extend_from_slice(&(ph.len() as u16).to_be_bytes());
            payload.extend_from_slice(ph.as_bytes());
            hash_payload(0x0D, &payload)
        }
        "GOVERNANCE_VOTE" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("requires wallet_hash"))?;
            let pid = event
                .proposal_id
                .as_ref()
                .ok_or_else(|| anyhow!("requires proposal_id"))?;
            let vc = event
                .vote_commitment
                .as_ref()
                .ok_or_else(|| anyhow!("requires vote_commitment"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(wh.len() as u16).to_be_bytes());
            payload.extend_from_slice(wh.as_bytes());
            payload.extend_from_slice(&(pid.len() as u16).to_be_bytes());
            payload.extend_from_slice(pid.as_bytes());
            payload.extend_from_slice(&(vc.len() as u16).to_be_bytes());
            payload.extend_from_slice(vc.as_bytes());
            hash_payload(0x0E, &payload)
        }
        "GOVERNANCE_RESULT" => {
            let wh = event
                .wallet_hash
                .as_ref()
                .ok_or_else(|| anyhow!("requires wallet_hash"))?;
            let pid = event
                .proposal_id
                .as_ref()
                .ok_or_else(|| anyhow!("requires proposal_id"))?;
            let rh = event
                .result_hash
                .as_ref()
                .ok_or_else(|| anyhow!("requires result_hash"))?;
            let mut payload = Vec::new();
            payload.extend_from_slice(&(wh.len() as u16).to_be_bytes());
            payload.extend_from_slice(wh.as_bytes());
            payload.extend_from_slice(&(pid.len() as u16).to_be_bytes());
            payload.extend_from_slice(pid.as_bytes());
            payload.extend_from_slice(&(rh.len() as u16).to_be_bytes());
            payload.extend_from_slice(rh.as_bytes());
            hash_payload(0x0F, &payload)
        }
        other => return Err(anyhow!("unknown event type: {other}")),
    };

    let computed_hex = hex::encode(computed);

    let valid = match &event.expected_hash {
        Some(expected) => computed_hex == *expected,
        None => true, // no expected hash means we just compute
    };

    Ok(ValidationResult {
        event_type: event.event_type.clone(),
        computed_hash: computed_hex,
        expected_hash: event.expected_hash.clone(),
        valid,
        error: if valid {
            None
        } else {
            Some("hash mismatch".to_string())
        },
    })
}

fn hash_payload(type_byte: u8, payload: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(1 + payload.len());
    input.push(type_byte);
    input.extend_from_slice(payload);

    let hash = Params::new()
        .hash_length(32)
        .personal(&personalization())
        .hash(&input);

    let mut output = [0u8; 32];
    output.copy_from_slice(hash.as_bytes());
    output
}

fn personalization() -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..13].copy_from_slice(b"NordicShield_");
    p
}

enum Source {
    File(String),
    Url(String),
}

struct Cli {
    source: Source,
    json: bool,
    emit_witness: bool,
}

fn parse_args() -> Result<Cli> {
    let mut args = std::env::args().skip(1);
    let mut source = None;
    let mut json = false;
    let mut emit_witness = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--witness" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --witness"))?;
                source = Some(Source::File(path));
            }
            "--witness-url" => {
                let url = args
                    .next()
                    .ok_or_else(|| anyhow!("missing value for --witness-url"))?;
                source = Some(Source::Url(url));
            }
            "--json" => json = true,
            "--emit-witness" => emit_witness = true,
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    Ok(Cli {
        source: source.ok_or_else(|| anyhow!("usage: zap1_schema --witness <file.json>"))?,
        json,
        emit_witness,
    })
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  zap1_schema --witness <events.json>");
    eprintln!("  zap1_schema --witness <events.json> --json");
    eprintln!("  zap1_schema --witness <events.json> --emit-witness");
    eprintln!("  zap1_schema --witness-url <url>");
}
