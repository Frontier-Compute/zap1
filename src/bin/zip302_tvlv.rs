use std::fs;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use zap1::zip302::{decode_tvlv, encode_tvlv};

#[derive(Debug, Deserialize)]
struct EncodePart {
    part_type: u16,
    version: u8,
    value_hex: String,
}

#[derive(Debug, Serialize)]
struct DecodePart {
    part_type: u16,
    version: u8,
    value_hex: String,
    value_utf8: Option<String>,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        print_usage();
        return Err(anyhow!("missing subcommand"));
    };

    match cmd.as_str() {
        "encode" => {
            let path = args
                .next()
                .ok_or_else(|| anyhow!("missing json file path"))?;
            if args.next().is_some() {
                return Err(anyhow!("encode accepts exactly one json file path"));
            }
            encode_cmd(&path)
        }
        "decode" => {
            let hex = args.next().ok_or_else(|| anyhow!("missing memo hex"))?;
            if args.next().is_some() {
                return Err(anyhow!("decode accepts exactly one memo hex argument"));
            }
            decode_cmd(&hex)
        }
        "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => Err(anyhow!("unknown subcommand: {other}")),
    }
}

fn encode_cmd(path: &str) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read: {path}"))?;
    let parts: Vec<EncodePart> = serde_json::from_str(&raw).context("invalid parts JSON")?;
    let parsed = parts
        .iter()
        .map(|part| {
            let value = hex::decode(&part.value_hex)
                .with_context(|| format!("invalid hex for part type {}", part.part_type))?;
            Ok((part.part_type, part.version, value))
        })
        .collect::<Result<Vec<_>>>()?;

    let refs = parsed
        .iter()
        .map(|(part_type, version, value)| (*part_type, *version, value.as_slice()))
        .collect::<Vec<_>>();
    let memo = encode_tvlv(&refs);

    println!("{}", hex::encode(memo));
    Ok(())
}

fn decode_cmd(memo_hex: &str) -> Result<()> {
    let memo = hex::decode(memo_hex).context("invalid memo hex")?;
    let parts = decode_tvlv(&memo).context("failed to decode TVLV memo")?;
    let out = parts
        .into_iter()
        .map(|part| DecodePart {
            part_type: part.part_type,
            version: part.version,
            value_utf8: String::from_utf8(part.value.clone()).ok(),
            value_hex: hex::encode(part.value),
        })
        .collect::<Vec<_>>();

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  zip302_tvlv encode <parts.json>");
    eprintln!("  zip302_tvlv decode <memo_hex>");
    eprintln!();
    eprintln!("Encode JSON format:");
    eprintln!(r#"  [{{"part_type":65530,"version":1,"value_hex":"7b226b223a2276227d"}}]"#);
}
