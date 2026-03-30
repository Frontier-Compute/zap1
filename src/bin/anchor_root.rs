use std::collections::HashMap;
use std::env;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use zap1::db::Db;
use zap1::memo::{merkle_root_memo, StructuredMemo};
use zap1::merkle::decode_hash;

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    let flags = parse_flags(args)?;
    match command.as_str() {
        "send" => send_anchor(flags),
        "record" => record_anchor(flags),
        _ => {
            print_usage();
            Ok(())
        }
    }
}

fn send_anchor(flags: HashMap<String, String>) -> Result<()> {
    let db_path = required(&flags, "--db")?;
    let zingo_cli = required(&flags, "--zingo-cli")?;
    let chain = required(&flags, "--chain")?;
    let server = required(&flags, "--server")?;
    let data_dir = required(&flags, "--data-dir")?;
    let to = required(&flags, "--to")?;
    let amount_zat = required(&flags, "--amount-zat")?;

    let db = Db::open(db_path)?;
    let root = db
        .current_merkle_root()?
        .ok_or_else(|| anyhow!("no Merkle root available yet"))?;
    let root_bytes = decode_hash(&root.root_hash)?;
    let memo = merkle_root_memo(&root_bytes).encode();

    let send_output = Command::new(zingo_cli)
        .args([
            "--chain",
            chain,
            "--server",
            server,
            "--data-dir",
            data_dir,
            "send",
            to,
            amount_zat,
            &memo,
        ])
        .output()
        .with_context(|| format!("failed to execute {zingo_cli} send"))?;

    anyhow::ensure!(
        send_output.status.success(),
        "zingo-cli send failed: {}",
        String::from_utf8_lossy(&send_output.stderr)
    );

    let confirm_output = Command::new(zingo_cli)
        .args([
            "--chain",
            chain,
            "--server",
            server,
            "--data-dir",
            data_dir,
            "confirm",
        ])
        .output()
        .with_context(|| format!("failed to execute {zingo_cli} confirm"))?;

    anyhow::ensure!(
        confirm_output.status.success(),
        "zingo-cli confirm failed: {}",
        String::from_utf8_lossy(&confirm_output.stderr)
    );

    let stdout = format!(
        "{}\n{}",
        String::from_utf8_lossy(&send_output.stdout),
        String::from_utf8_lossy(&confirm_output.stdout)
    );
    let txid = extract_txid(&stdout);
    if let Some(txid) = txid.as_deref() {
        db.record_merkle_anchor(&root.root_hash, txid, None)?;
    }

    println!("Merkle root: {}", root.root_hash);
    println!("Leaf count: {}", root.leaf_count);
    println!("Memo: {}", StructuredMemo::decode(&memo)?.encode());
    println!();
    println!("zingo-cli send output:\n{}", String::from_utf8_lossy(&send_output.stdout));
    println!("zingo-cli confirm output:\n{}", String::from_utf8_lossy(&confirm_output.stdout));
    println!();

    match txid {
        Some(txid) => {
            println!("Broadcast txid: {txid}");
            println!("Height pending. Record it after confirmation:");
            println!(
                "  cargo run --bin anchor_root -- record --db {} --root {} --txid {} --height <CONFIRMED_HEIGHT>",
                db_path, root.root_hash, txid
            );
        }
        None => {
            println!("Txid not detected in zingo-cli output.");
            println!("Record it manually after broadcast:");
            println!(
                "  cargo run --bin anchor_root -- record --db {} --root {} --txid <TXID> --height <CONFIRMED_HEIGHT>",
                db_path, root.root_hash
            );
        }
    }

    Ok(())
}

fn record_anchor(flags: HashMap<String, String>) -> Result<()> {
    let db_path = required(&flags, "--db")?;
    let root_hash = required(&flags, "--root")?;
    let txid = required(&flags, "--txid")?;
    let height: u32 = required(&flags, "--height")?.parse()?;

    let db = Db::open(db_path)?;
    db.record_merkle_anchor(root_hash, txid, Some(height))?;

    println!("Recorded anchor for root {root_hash}");
    println!("Txid: {txid}");
    println!("Height: {height}");
    Ok(())
}

fn parse_flags(args: impl Iterator<Item = String>) -> Result<HashMap<String, String>> {
    let mut flags = HashMap::new();
    let mut pending_key: Option<String> = None;

    for arg in args {
        if arg.starts_with("--") {
            if pending_key.is_some() {
                return Err(anyhow!("missing value for {}", pending_key.unwrap()));
            }
            pending_key = Some(arg);
        } else if let Some(key) = pending_key.take() {
            flags.insert(key, arg);
        } else {
            return Err(anyhow!("unexpected positional argument: {arg}"));
        }
    }

    if let Some(key) = pending_key {
        return Err(anyhow!("missing value for {key}"));
    }

    Ok(flags)
}

fn required<'a>(flags: &'a HashMap<String, String>, key: &str) -> Result<&'a str> {
    flags
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| anyhow!("missing required flag {key}"))
}

fn extract_txid(output: &str) -> Option<String> {
    output
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ':')
        .find(|token| token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()))
        .map(|token| token.to_lowercase())
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  anchor_root send --db <db_path> --zingo-cli <path> --chain <mainnet|testnet> --server <url> --data-dir <dir> --to <shielded_addr> --amount-zat <zats>");
    eprintln!("  anchor_root record --db <db_path> --root <root_hash> --txid <txid> --height <block_height>");
}
