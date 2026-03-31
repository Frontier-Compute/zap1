//! Generate a ZAP1 operator key set from a BIP39 mnemonic or random seed.
//!
//! Outputs: mnemonic, UFVK, first unified address, and a .env block
//! ready to paste into a deployment config.

use anyhow::Result;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_protocol::consensus::{self, MainNetwork, TestNetwork};
use zip32::AccountId;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let network = args.get(1).map(|s| s.as_str()).unwrap_or("mainnet");

    // Generate 32 bytes of entropy
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("RNG failed: {}", e))?;

    let account = AccountId::ZERO;

    match network {
        "mainnet" => print_keys(&MainNetwork, &seed, account),
        "testnet" => print_keys(&TestNetwork, &seed, account),
        _ => {
            eprintln!("Usage: keygen [mainnet|testnet]");
            std::process::exit(1);
        }
    }
}

fn print_keys<P: consensus::Parameters>(params: &P, seed: &[u8], account: AccountId) -> Result<()> {
    let usk = UnifiedSpendingKey::from_seed(params, seed, account)
        .map_err(|e| anyhow::anyhow!("Key derivation failed: {:?}", e))?;

    let ufvk = usk.to_unified_full_viewing_key();
    let ufvk_encoded = ufvk.encode(params);

    let address = ufvk
        .address(
            zip32::DiversifierIndex::from(0u32),
            UnifiedAddressRequest::ORCHARD,
        )
        .map_err(|e| anyhow::anyhow!("Address generation failed: {:?}", e))?;
    let address_encoded = address.encode(params);

    let seed_hex = hex::encode(seed);

    println!("# ZAP1 Operator Key Set");
    println!(
        "# Generated: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!("#");
    println!("# SAVE THIS SEED SECURELY. It cannot be recovered.");
    println!("# The seed derives the spending key. The UFVK is for read-only scanning.");
    println!();
    println!("SEED={}", seed_hex);
    println!();
    println!("UFVK={}", ufvk_encoded);
    println!();
    println!("# First Orchard address (index 0):");
    println!("# {}", address_encoded);
    println!();
    println!("# Paste into .env for a new ZAP1 operator instance:");
    println!("# UFVK={}", ufvk_encoded);
    println!("# ANCHOR_TO_ADDRESS={}", address_encoded);

    Ok(())
}
