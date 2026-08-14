//! Generate a ZAP1 operator key set from operating-system randomness.
//!
//! The spending seed is withheld unless the operator explicitly passes
//! `--show-secret`.

use anyhow::Result;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_protocol::consensus::{self, MainNetwork, TestNetwork};
use zip32::AccountId;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let network = args.first().map(|s| s.as_str()).unwrap_or("mainnet");
    let show_secret = args.iter().any(|arg| arg == "--show-secret");
    if args
        .iter()
        .skip(1)
        .any(|arg| arg.as_str() != "--show-secret")
    {
        anyhow::bail!("Usage: keygen [mainnet|testnet] [--show-secret]");
    }

    // Generate 32 bytes of entropy
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("RNG failed: {}", e))?;

    let account = AccountId::ZERO;

    match network {
        "mainnet" => print_keys(&MainNetwork, &seed, account, show_secret),
        "testnet" => print_keys(&TestNetwork, &seed, account, show_secret),
        _ => {
            eprintln!("Usage: keygen [mainnet|testnet] [--show-secret]");
            std::process::exit(1);
        }
    }
}

fn print_keys<P: consensus::Parameters>(
    params: &P,
    seed: &[u8],
    account: AccountId,
    show_secret: bool,
) -> Result<()> {
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
    if show_secret {
        eprintln!("WARNING: emitting a spending seed to stdout by explicit request");
        println!("# SAVE THIS SEED SECURELY. It cannot be recovered.");
        println!("# The seed derives the spending key. The UFVK is for read-only scanning.");
        println!();
        println!("SEED={}", seed_hex);
        println!();
    } else {
        println!("# Spending seed withheld. Use --show-secret only in a protected terminal.");
        println!();
    }
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
