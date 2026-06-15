use blake2b_simd::Params;
use serde::Serialize;

use crate::memo::MemoType;

#[derive(Debug, Clone)]
pub struct MerkleLeafRecord {
    pub leaf_hash: String,
    pub event_type: MemoType,
    pub wallet_hash: String,
    pub serial_number: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct MerkleRootRecord {
    pub root_hash: String,
    pub leaf_count: usize,
    pub anchor_txid: Option<String>,
    pub anchor_height: Option<u32>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProofPosition {
    Left,
    Right,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProofStep {
    pub hash: String,
    pub position: ProofPosition,
}

#[derive(Debug, Clone)]
pub struct VerificationBundle {
    pub leaf: MerkleLeafRecord,
    pub proof: Vec<ProofStep>,
    pub root: MerkleRootRecord,
}

/// Compute the ZAP1 Merkle root commitment for a set of leaves.
///
/// The committed root binds the leaf count to the tree root so odd-cardinality
/// trees cannot collide with trees where the final leaf is duplicated.
pub fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let raw_root = compute_raw_tree_root(leaves);
    commit_root(leaves.len(), &raw_root)
}

/// Compute the raw tree root using carry-up semantics for an odd final node.
pub fn compute_raw_tree_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_node(&chunk[0], &chunk[1]));
            } else {
                next.push(chunk[0]);
            }
        }
        level = next;
    }

    level[0]
}

/// Legacy root computation retained only for verifying historical anchors.
///
/// New anchors must use [`compute_root`].
pub fn compute_legacy_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            next.push(hash_node(&chunk[0], &right));
        }
        level = next;
    }

    level[0]
}

/// Bind the raw tree root to the leaf count.
pub fn commit_root(leaf_count: usize, raw_root: &[u8; 32]) -> [u8; 32] {
    let leaf_count = u64::try_from(leaf_count).expect("leaf count exceeds u64");
    let mut input = [0u8; 41];
    input[0] = 1;
    input[1..9].copy_from_slice(&leaf_count.to_be_bytes());
    input[9..].copy_from_slice(raw_root);

    let hash = Params::new()
        .hash_length(32)
        .personal(&root_personalization())
        .hash(&input);

    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

pub fn generate_proof(leaves: &[[u8; 32]], index: usize) -> Vec<ProofStep> {
    if leaves.is_empty() || index >= leaves.len() {
        return Vec::new();
    }

    let mut proof = Vec::new();
    let mut level = leaves.to_vec();
    let mut current_index = index;

    while level.len() > 1 {
        if current_index % 2 == 0 {
            let sibling_index = current_index + 1;
            if sibling_index < level.len() {
                proof.push(ProofStep {
                    hash: hex::encode(level[sibling_index]),
                    position: ProofPosition::Right,
                });
            }
        } else {
            proof.push(ProofStep {
                hash: hex::encode(level[current_index - 1]),
                position: ProofPosition::Left,
            });
        }

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next.push(hash_node(&chunk[0], &chunk[1]));
            } else {
                next.push(chunk[0]);
            }
        }

        level = next;
        current_index /= 2;
    }

    proof
}

pub fn generate_legacy_proof(leaves: &[[u8; 32]], index: usize) -> Vec<ProofStep> {
    if leaves.is_empty() || index >= leaves.len() {
        return Vec::new();
    }

    let mut proof = Vec::new();
    let mut level = leaves.to_vec();
    let mut current_index = index;

    while level.len() > 1 {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };

        let sibling = if sibling_index < level.len() {
            level[sibling_index]
        } else {
            level[current_index]
        };

        proof.push(ProofStep {
            hash: hex::encode(sibling),
            position: if current_index % 2 == 0 {
                ProofPosition::Right
            } else {
                ProofPosition::Left
            },
        });

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            next.push(hash_node(&chunk[0], &right));
        }

        level = next;
        current_index /= 2;
    }

    proof
}

pub fn decode_hash(hex_hash: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_hash)?;
    anyhow::ensure!(bytes.len() == 32, "expected 32-byte hash");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);

    let hash = Params::new()
        .hash_length(32)
        .personal(&node_personalization())
        .hash(&input);

    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

fn node_personalization() -> [u8; 16] {
    let mut personal = [0u8; 16];
    personal[..13].copy_from_slice(b"NordicShield_");
    personal[13..].copy_from_slice(b"MRK");
    personal
}

fn root_personalization() -> [u8; 16] {
    let mut personal = [0u8; 16];
    personal[..13].copy_from_slice(b"NordicShield_");
    personal[13..].copy_from_slice(b"RTK");
    personal
}
