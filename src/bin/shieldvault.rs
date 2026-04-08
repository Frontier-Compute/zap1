//! ShieldVault FROST CLI -- threshold signing for Zcash shielded transactions.
//!
//! Commands:
//!   keygen   -- Generate a FROST 2-of-3 key package (dealer mode)
//!   sign     -- Sign a message using two FROST shares
//!   verify   -- Verify a threshold signature against the group key
//!   info     -- Display group verifying key from share files

use std::path::Path;
use std::process;

use anyhow::Result;

fn usage() {
    eprintln!("ShieldVault FROST CLI -- threshold signing for Zcash shielded transactions");
    eprintln!();
    eprintln!("Usage: shieldvault <command> [args...]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  keygen               Generate a FROST 2-of-3 key set (dealer mode)");
    eprintln!("  sign <share2> <share3> <msg_hex>");
    eprintln!("                       Sign a message (hex) using two share files");
    eprintln!("  verify <share2> <share3> <msg_hex> <sig_hex>");
    eprintln!("                       Verify a signature against the group key");
    eprintln!("  info <share2> <share3>");
    eprintln!("                       Display the group verifying key");
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  shieldvault keygen");
    eprintln!("  shieldvault sign share2.json share3.json $(echo -n \"hello\" | xxd -p)");
    eprintln!("  shieldvault verify share2.json share3.json <msg_hex> <sig_hex>");
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {:#}", e);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        usage();
        process::exit(0);
    }

    match args[1].as_str() {
        "keygen" => cmd_keygen(),
        "sign" => {
            if args.len() < 5 {
                eprintln!("Usage: shieldvault sign <share2.json> <share3.json> <msg_hex>");
                process::exit(1);
            }
            cmd_sign(&args[2], &args[3], &args[4])
        }
        "verify" => {
            if args.len() < 6 {
                eprintln!("Usage: shieldvault verify <share2.json> <share3.json> <msg_hex> <sig_hex>");
                process::exit(1);
            }
            cmd_verify(&args[2], &args[3], &args[4], &args[5])
        }
        "info" => {
            if args.len() < 4 {
                eprintln!("Usage: shieldvault info <share2.json> <share3.json>");
                process::exit(1);
            }
            cmd_info(&args[2], &args[3])
        }
        "--help" | "-h" | "help" => {
            usage();
            Ok(())
        }
        other => {
            eprintln!("unknown command: {}", other);
            usage();
            process::exit(1);
        }
    }
}

/// Generate a 2-of-3 FROST key set using the trusted dealer protocol.
/// Writes three share files to the current directory.
fn cmd_keygen() -> Result<()> {
    use frost_rerandomized::frost_core::frost::keys::IdentifierList;
    use frost_rerandomized::frost_core::{Ciphersuite, Group};
    use reddsa::frost::redpallas::keys;
    use reddsa::frost::redpallas::{Identifier, PallasBlake2b512};

    let mut rng = rand::rngs::OsRng;

    let (shares, pub_key_pkg) =
        keys::generate_with_dealer(3, 2, IdentifierList::Default, &mut rng)
            .map_err(|e| anyhow::anyhow!("dealer keygen failed: {}", e))?;

    let gvk_bytes: [u8; 32] = <<PallasBlake2b512 as Ciphersuite>::Group as Group>::serialize(
        &pub_key_pkg.group_public().to_element(),
    );

    println!("FROST 2-of-3 key generation complete");
    println!("Group verifying key: {}", hex::encode(gvk_bytes));
    println!();

    for i in 1u16..=3 {
        let id = Identifier::try_from(i).unwrap();
        let share = &shares[&id];

        // Verify the share to get the verifying share and group key
        let (verifying_share, _group_vk) = share
            .verify()
            .map_err(|e| anyhow::anyhow!("share verification failed: {:?}", e))?;

        let id_bytes: [u8; 32] = share.identifier().serialize();
        let ss_bytes: [u8; 32] = share.secret().serialize();
        let vs_bytes: [u8; 32] = verifying_share.serialize();

        let commitment_hashes: Vec<String> = share
            .commitment()
            .serialize()
            .iter()
            .map(|b| hex::encode(b))
            .collect();

        let json = serde_json::json!({
            "ciphersuite": "FROST(Pallas, BLAKE2b-512)",
            "identifier": hex::encode(id_bytes),
            "signing_share": hex::encode(ss_bytes),
            "verifying_share": hex::encode(vs_bytes),
            "group_verifying_key": hex::encode(gvk_bytes),
            "commitment": commitment_hashes,
            "threshold": 2,
            "max_signers": 3,
        });

        let filename = format!("frost_share_{}.json", i);
        std::fs::write(&filename, serde_json::to_string_pretty(&json)?)?;
        println!("Wrote {}", filename);
    }

    println!();
    println!("Distribute shares to participants. Keep share files secure.");
    println!("Any 2 of 3 shares can produce a valid signature.");

    Ok(())
}

/// Sign a hex-encoded message using two FROST share files.
fn cmd_sign(share2_path: &str, share3_path: &str, msg_hex: &str) -> Result<()> {
    use zap1::frost_signer::FrostSigner;

    let msg = hex::decode(msg_hex).map_err(|e| anyhow::anyhow!("bad msg hex: {}", e))?;
    let signer = FrostSigner::from_files(Path::new(share2_path), Path::new(share3_path))?;

    let sig = signer.sign_raw(&msg)?;
    let sig_bytes: [u8; 64] = sig.into();

    println!("{}", hex::encode(sig_bytes));

    Ok(())
}

/// Verify a signature against the group public key derived from share files.
fn cmd_verify(
    share2_path: &str,
    share3_path: &str,
    msg_hex: &str,
    sig_hex: &str,
) -> Result<()> {
    use zap1::frost_signer::FrostSigner;

    let msg = hex::decode(msg_hex).map_err(|e| anyhow::anyhow!("bad msg hex: {}", e))?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| anyhow::anyhow!("bad sig hex: {}", e))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = reddsa::Signature::from(sig_bytes);

    let signer = FrostSigner::from_files(Path::new(share2_path), Path::new(share3_path))?;
    signer.verify(&msg, &sig)?;

    println!("OK -- signature valid");

    Ok(())
}

/// Display the group verifying key from share files.
fn cmd_info(share2_path: &str, share3_path: &str) -> Result<()> {
    use frost_rerandomized::frost_core::{Ciphersuite, Group};
    use reddsa::frost::redpallas::PallasBlake2b512;
    use zap1::frost_signer::FrostSigner;

    let signer = FrostSigner::from_files(Path::new(share2_path), Path::new(share3_path))?;

    let gvk_bytes: [u8; 32] = <<PallasBlake2b512 as Ciphersuite>::Group as Group>::serialize(
        &signer.group_verifying_key().to_element(),
    );

    println!("Group verifying key: {}", hex::encode(gvk_bytes));

    Ok(())
}
