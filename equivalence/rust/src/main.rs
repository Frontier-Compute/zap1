//! ZAP1 verifier cross-implementation fingerprint (Rust side).
//!
//! Reads equivalence/corpus.json, runs the standalone `zap1-verify` verifier on
//! each case, and prints one canonical line per case: `<id> <sha256_hex>`,
//! sorted by id. The Python side (equivalence/fingerprint.py) prints the same
//! lines from a separately written verifier. CI compares the two outputs and
//! the committed equivalence/fingerprints.expected.txt.
//!
//! A match shows the two verifier implementations agree on the frozen corpus.
//! It is a consistency check between two implementations we control, not a
//! proof that either verifier is correct against intent, and not a boundary
//! against an attacker. See equivalence/README.md and equivalence/SPEC.md.
//!
//! The encoding and the check follow the pattern published by Tachyon/Ragu
//! (github.com/tachyon-zcash/ragu). Cited, not claimed.

use std::fs;

use sha2::{Digest, Sha256};
use zap1_verify::{
    bytes_to_hex, commit_root, hex_to_bytes32, node_hash, verify_legacy_proof, verify_proof,
    ProofStep, SiblingPosition,
};

const DOMAIN: &[u8] = b"zap1-verifier-equiv-v1";
const COUNT_BOUND_SCHEME: &str = "ZAP1_COUNT_BOUND_V2";
const LEGACY_SCHEME: &str = "ZAP1_LEGACY_DUPLICATE_ODD";
const LEGACY_ROOT_MAX_ANCHOR_HEIGHT: u64 = 3_317_133;

fn push_len_prefixed(buf: &mut Vec<u8>, s: &str) {
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s.as_bytes());
}

fn walk_raw(leaf: &[u8; 32], proof: &[ProofStep]) -> [u8; 32] {
    let mut current = *leaf;
    for step in proof {
        current = match step.position {
            SiblingPosition::Right => node_hash(&current, &step.hash),
            SiblingPosition::Left => node_hash(&step.hash, &current),
        };
    }
    current
}

fn legacy_allowed(scheme: Option<&str>, anchor_height: Option<u64>, allow: bool) -> bool {
    (allow || scheme == Some(LEGACY_SCHEME))
        && anchor_height
            .map(|h| h <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT)
            .unwrap_or(false)
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "equivalence/corpus.json".to_string());
    let data = fs::read_to_string(&path).expect("read corpus.json");
    let corpus: serde_json::Value = serde_json::from_str(&data).expect("parse corpus.json");
    let cases = corpus["cases"].as_array().expect("cases array");

    let mut lines: Vec<String> = Vec::with_capacity(cases.len());
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let leaf = hex_to_bytes32(case["leaf_hash"].as_str().expect("leaf_hash")).expect("leaf hex");
        let leaf_count = case["leaf_count"].as_u64().expect("leaf_count") as usize;
        let proof: Vec<ProofStep> = case["proof"]
            .as_array()
            .expect("proof")
            .iter()
            .map(|s| {
                let hash =
                    hex_to_bytes32(s["hash"].as_str().expect("step hash")).expect("step hex");
                let position = match s["position"].as_str().expect("position") {
                    "right" => SiblingPosition::Right,
                    "left" => SiblingPosition::Left,
                    other => panic!("bad position {other}"),
                };
                ProofStep { hash, position }
            })
            .collect();
        let expected =
            hex_to_bytes32(case["expected_root"].as_str().expect("expected_root")).expect("root hex");
        let scheme = case["scheme"].as_str();
        let anchor_height = case["anchor_height"].as_u64();
        let allow = case["allow_historical_legacy"].as_bool().unwrap_or(false);

        let raw_root = walk_raw(&leaf, &proof);
        let count_bound_root = commit_root(leaf_count, &raw_root);
        let v2_valid = verify_proof(&leaf, &proof, leaf_count, &expected);
        let legacy_match = verify_legacy_proof(&leaf, &proof, &expected);

        let (valid, result_scheme): (bool, &str) = if v2_valid {
            (true, COUNT_BOUND_SCHEME)
        } else if legacy_match && legacy_allowed(scheme, anchor_height, allow) {
            (true, LEGACY_SCHEME)
        } else {
            (false, "INVALID")
        };

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(DOMAIN);
        push_len_prefixed(&mut buf, id);
        buf.extend_from_slice(&leaf);
        buf.extend_from_slice(&(leaf_count as u64).to_be_bytes());
        buf.extend_from_slice(&(proof.len() as u64).to_be_bytes());
        for step in &proof {
            buf.push(match step.position {
                SiblingPosition::Right => 1,
                SiblingPosition::Left => 0,
            });
            buf.extend_from_slice(&step.hash);
        }
        buf.extend_from_slice(&expected);
        match scheme {
            None => buf.push(0),
            Some(s) => {
                buf.push(1);
                push_len_prefixed(&mut buf, s);
            }
        }
        match anchor_height {
            None => buf.push(0),
            Some(h) => {
                buf.push(1);
                buf.extend_from_slice(&h.to_be_bytes());
            }
        }
        buf.push(u8::from(allow));
        buf.push(u8::from(valid));
        push_len_prefixed(&mut buf, result_scheme);
        buf.extend_from_slice(&count_bound_root);
        buf.extend_from_slice(&raw_root);

        let digest = Sha256::digest(&buf);
        lines.push(format!("{id} {}", bytes_to_hex(&digest)));
    }

    lines.sort();
    for line in lines {
        println!("{line}");
    }
}
