use std::fs;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

const COUNT_BOUND_SCHEME: &str = "ZAP1_COUNT_BOUND_V2";
const LEGACY_SCHEME: &str = "ZAP1_LEGACY_DUPLICATE_ODD";
const LEGACY_ROOT_MAX_ANCHOR_HEIGHT: u32 = 3_317_133;
const CURRENT_BUNDLE_VERSION: &str = "2";
const HISTORICAL_BUNDLE_VERSION: &str = "1.0.0";

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
    #[serde(default)]
    wallet_hash: Option<String>,
    #[serde(default)]
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
    scheme: Option<String>,
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
    protocol: String,
    proofs: Vec<ExportProof>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ExportProof {
    leaf_hash: String,
    event_type: String,
    proof_steps: Vec<BundleProofStep>,
    root: String,
    leaf_count: Option<usize>,
    merkle_scheme: Option<String>,
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
            verify_bundle(&bundle, None)?;
            print_report(&bundle);
        }
        InputSource::BundleUrl(url) => {
            let requested_leaf = requested_leaf_from_url(&url)?;
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
            verify_bundle(&bundle, requested_leaf.as_deref())?;
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
    if package.protocol != "ZAP1" {
        return Err(anyhow!(
            "export protocol must be exactly ZAP1, got {}",
            package.protocol
        ));
    }
    let mut pass = 0u32;
    let mut fail = 0u32;

    for proof in &package.proofs {
        let scheme = proof
            .merkle_scheme
            .as_deref()
            .ok_or_else(|| anyhow!("missing merkle_scheme"))?;
        if scheme != COUNT_BOUND_SCHEME && scheme != LEGACY_SCHEME {
            return Err(anyhow!("unrecognized merkle_scheme: {scheme}"));
        }
        let leaf = canonical_hash32(&proof.leaf_hash, "leaf_hash")?;
        let root = canonical_hash32(&proof.root, "root")?;
        if let Some(txid) = &proof.anchor_txid {
            canonical_hash32(txid, "anchor_txid")?;
        }

        let steps: Vec<zap1_verify::ProofStep> = proof
            .proof_steps
            .iter()
            .map(|s| {
                let hash = canonical_hash32(&s.hash, "proof step hash")?;
                let position = match s.position.as_str() {
                    "left" => zap1_verify::SiblingPosition::Left,
                    "right" => zap1_verify::SiblingPosition::Right,
                    other => return Err(anyhow!("invalid position: {other}")),
                };
                Ok(zap1_verify::ProofStep { hash, position })
            })
            .collect::<Result<Vec<_>>>()?;

        let valid_count_bound = if scheme == COUNT_BOUND_SCHEME {
            let leaf_count = proof
                .leaf_count
                .ok_or_else(|| anyhow!("count-bound proof is missing leaf_count"))?;
            if leaf_count == 0 {
                return Err(anyhow!("leaf_count must be positive"));
            }
            zap1_verify::verify_proof(&leaf, &steps, leaf_count, &root)
        } else {
            false
        };
        let valid_legacy = scheme == LEGACY_SCHEME
            && historical_legacy_allowed(proof.anchor_height)
            && zap1_verify::verify_legacy_proof(&leaf, &steps, &root);
        let valid = valid_count_bound || valid_legacy;
        if valid {
            println!(
                "pass: Merkle inclusion; bundle-claimed event type={} leaf={} anchor={}",
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
        return Err(anyhow!("{fail} proof(s) failed verification"));
    }
    Ok(())
}

fn canonical_hash32(value: &str, label: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(anyhow!("{label} must be exactly 32-byte lowercase hex"));
    }
    zap1_verify::hex_to_bytes32(value)
        .ok_or_else(|| anyhow!("{label} must be exactly 32-byte lowercase hex"))
}

fn requested_leaf_from_url(url: &str) -> Result<Option<String>> {
    let parsed = reqwest::Url::parse(url).context("invalid bundle URL")?;
    let segments: Vec<_> = parsed
        .path_segments()
        .map(|parts| parts.collect())
        .unwrap_or_default();
    if segments.len() >= 3
        && segments[segments.len() - 3] == "verify"
        && segments[segments.len() - 1] == "proof.json"
    {
        let leaf = segments[segments.len() - 2];
        canonical_hash32(leaf, "requested leaf hash")?;
        return Ok(Some(leaf.to_string()));
    }
    Ok(None)
}

fn historical_legacy_allowed(anchor_height: Option<u32>) -> bool {
    anchor_height
        .map(|height| height <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT)
        .unwrap_or(false)
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

fn verify_bundle(bundle: &ProofBundle, requested_leaf: Option<&str>) -> Result<()> {
    if bundle.protocol != "ZAP1" {
        return Err(anyhow!(
            "bundle protocol must be exactly ZAP1, got {}",
            bundle.protocol
        ));
    }
    let scheme = bundle
        .root
        .scheme
        .as_deref()
        .ok_or_else(|| anyhow!("missing root.scheme"))?;
    if scheme != COUNT_BOUND_SCHEME && scheme != LEGACY_SCHEME {
        return Err(anyhow!("unrecognized root.scheme: {scheme}"));
    }
    let admitted_pair = bundle.version == CURRENT_BUNDLE_VERSION
        || (bundle.version == HISTORICAL_BUNDLE_VERSION && scheme == LEGACY_SCHEME);
    if !admitted_pair {
        return Err(anyhow!(
            "bundle version and root.scheme are not an admitted pair"
        ));
    }
    if bundle.root.leaf_count == 0 {
        return Err(anyhow!("root.leaf_count must be positive"));
    }

    let leaf = canonical_hash32(&bundle.leaf.hash, "leaf.hash")?;
    let root = canonical_hash32(&bundle.root.hash, "root.hash")?;
    if let Some(txid) = &bundle.anchor.txid {
        canonical_hash32(txid, "anchor.txid")?;
    }
    if let Some(requested) = requested_leaf {
        canonical_hash32(requested, "requested leaf hash")?;
        if requested != bundle.leaf.hash {
            return Err(anyhow!(
                "returned bundle leaf.hash does not match requested leaf hash"
            ));
        }
    }
    if scheme == LEGACY_SCHEME && !historical_legacy_allowed(bundle.anchor.height) {
        return Err(anyhow!(
            "historical legacy bundle lacks an admitted anchor height"
        ));
    }

    let proof = bundle
        .proof
        .iter()
        .map(|step| {
            let hash = canonical_hash32(&step.hash, "proof step hash")?;
            let position = match step.position.as_str() {
                "left" => zap1_verify::SiblingPosition::Left,
                "right" => zap1_verify::SiblingPosition::Right,
                other => return Err(anyhow!("invalid proof step position: {other}")),
            };
            Ok(zap1_verify::ProofStep { hash, position })
        })
        .collect::<Result<Vec<_>>>()?;

    let leaf_count = usize::try_from(bundle.root.leaf_count)
        .map_err(|_| anyhow!("root.leaf_count does not fit this platform"))?;
    let valid_count_bound =
        scheme == COUNT_BOUND_SCHEME && zap1_verify::verify_proof(&leaf, &proof, leaf_count, &root);
    let valid_legacy = scheme == LEGACY_SCHEME
        && historical_legacy_allowed(bundle.anchor.height)
        && zap1_verify::verify_legacy_proof(&leaf, &proof, &root);

    if !(valid_count_bound || valid_legacy) {
        return Err(anyhow!("proof verification failed"));
    }

    Ok(())
}

fn print_report(bundle: &ProofBundle) {
    println!("Merkle inclusion: ok");
    println!("bundle version: {}", bundle.version);
    println!(
        "bundle-claimed event type: {} (not authenticated without a disclosed leaf witness)",
        bundle.leaf.event_type
    );
    println!("leaf hash: {}", bundle.leaf.hash);
    if let Some(wallet_hash) = &bundle.leaf.wallet_hash {
        println!(
            "bundle-supplied wallet hash: {} (not recomputed)",
            wallet_hash
        );
    }
    if let Some(serial) = &bundle.leaf.serial_number {
        println!("bundle-supplied serial number: {} (not recomputed)", serial);
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
    println!("verified scope: supplied leaf-hash inclusion under the supplied root");
    println!("not verified: event truth, event type, wallet, serial, tx-to-memo binding, or independent origin");
    println!();
    println!("next checks:");
    println!("- confirm txid and block height on a Zcash explorer or local node");
    println!("- confirm the bundle proof matches its supplied root");
    println!("- require a safe disclosure/opening artifact before claiming the encrypted memo commits that root");
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  zap1_audit --bundle <proof.json>");
    eprintln!("  zap1_audit --bundle-url <https://.../proof.json>");
    eprintln!("  zap1_audit --export <package.json>  (verify all proofs in an export package)");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_count_bound_bundle() -> ProofBundle {
        ProofBundle {
            protocol: "ZAP1".to_string(),
            version: CURRENT_BUNDLE_VERSION.to_string(),
            leaf: BundleLeaf {
                hash: "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b"
                    .to_string(),
                event_type: "PROGRAM_ENTRY".to_string(),
                wallet_hash: None,
                serial_number: None,
                created_at: "2026-03-27T03:28:57Z".to_string(),
            },
            proof: Vec::new(),
            root: BundleRoot {
                hash: "586a84be4d3a717f06a0b837e8dbb9a333a3c44a679338dfa29d422569cd1d8c"
                    .to_string(),
                leaf_count: 1,
                created_at: "2026-03-27T03:29:26Z".to_string(),
                scheme: Some(COUNT_BOUND_SCHEME.to_string()),
            },
            anchor: BundleAnchor {
                txid: None,
                height: None,
            },
        }
    }

    #[test]
    fn rejects_short_hash_without_panicking() {
        let mut bundle = valid_count_bound_bundle();
        bundle.leaf.hash = "00".to_string();
        assert!(verify_bundle(&bundle, None).is_err());
    }

    #[test]
    fn rejects_noncanonical_uppercase_hash() {
        let mut bundle = valid_count_bound_bundle();
        bundle.leaf.hash = bundle.leaf.hash.to_uppercase();
        assert!(verify_bundle(&bundle, None).is_err());
    }

    #[test]
    fn rejects_fake_bundle_scheme() {
        let mut bundle = valid_count_bound_bundle();
        bundle.root.scheme = Some("ZAP1_FAKE_SCHEME".to_string());
        assert!(verify_bundle(&bundle, None).is_err());
    }

    #[test]
    fn rejects_unknown_proof_position() {
        let mut bundle = valid_count_bound_bundle();
        bundle.proof.push(BundleProofStep {
            hash: "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133".to_string(),
            position: "banana".to_string(),
        });
        assert!(verify_bundle(&bundle, None).is_err());
    }

    #[test]
    fn rejects_historical_version_with_count_bound_scheme() {
        let mut bundle = valid_count_bound_bundle();
        bundle.version = HISTORICAL_BUNDLE_VERSION.to_string();
        assert!(verify_bundle(&bundle, None).is_err());
    }

    #[test]
    fn binds_bundle_to_requested_url_leaf() {
        let bundle = valid_count_bound_bundle();
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(verify_bundle(&bundle, Some(other)).is_err());
    }

    #[test]
    fn count_bound_scheme_does_not_accept_legacy_raw_root() {
        let mut bundle = valid_count_bound_bundle();
        bundle.root.hash = bundle.leaf.hash.clone();
        assert!(verify_bundle(&bundle, None).is_err());
    }

    #[test]
    fn rejects_fake_export_scheme() {
        let package = AuditPackage {
            protocol: "ZAP1".to_string(),
            proofs: vec![ExportProof {
                leaf_hash: "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b"
                    .to_string(),
                event_type: "PROGRAM_ENTRY".to_string(),
                proof_steps: Vec::new(),
                root: "586a84be4d3a717f06a0b837e8dbb9a333a3c44a679338dfa29d422569cd1d8c"
                    .to_string(),
                leaf_count: Some(1),
                merkle_scheme: Some("ZAP1_FAKE_SCHEME".to_string()),
                anchor_txid: None,
                anchor_height: None,
            }],
        };
        assert!(verify_export(&package).is_err());
    }
}
