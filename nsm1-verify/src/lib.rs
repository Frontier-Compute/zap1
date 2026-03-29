//! nsm1-verify - Standalone Merkle proof verifier for the NSM1 protocol.
//!
//! Zero-trust verification of Nordic Shield on-chain commitments.
//! Implements BLAKE2b-256 leaf hashing for all 9 NSM1 event types
//! and Merkle proof path walking with `NordicShield_MRK` node personalization.
//!
//! Only dependency: `blake2b_simd`.

use blake2b_simd::Params;

// Constants

/// BLAKE2b-256 personalization for leaf hashing (types 0x01-0x08).
/// 13 bytes; blake2b_simd zero-pads to 16 internally.
pub const DEFAULT_LEAF_PERSONAL: &[u8; 13] = b"NordicShield_";

/// BLAKE2b-256 personalization for Merkle node hashing.
pub const DEFAULT_NODE_PERSONAL: &[u8; 16] = b"NordicShield_MRK";

/// Domain-separation strings used for NSM1 leaf and Merkle hashing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Personalization<'a> {
    pub leaf: &'a [u8],
    pub node: &'a [u8],
}

/// Default NSM1 personalization values.
pub const DEFAULT_PERSONALIZATION: Personalization<'static> = Personalization {
    leaf: DEFAULT_LEAF_PERSONAL,
    node: DEFAULT_NODE_PERSONAL,
};

// Types

/// NSM1 event type bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EventType {
    ProgramEntry    = 0x01,
    OwnershipAttest = 0x02,
    ContractAnchor  = 0x03,
    Deployment      = 0x04,
    HostingPayment  = 0x05,
    ShieldRenewal   = 0x06,
    Transfer        = 0x07,
    Exit            = 0x08,
    MerkleRoot      = 0x09,
}

impl EventType {
    /// Parse from the raw type byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::ProgramEntry),
            0x02 => Some(Self::OwnershipAttest),
            0x03 => Some(Self::ContractAnchor),
            0x04 => Some(Self::Deployment),
            0x05 => Some(Self::HostingPayment),
            0x06 => Some(Self::ShieldRenewal),
            0x07 => Some(Self::Transfer),
            0x08 => Some(Self::Exit),
            0x09 => Some(Self::MerkleRoot),
            _    => None,
        }
    }
}

/// Typed payload for computing an NSM1 leaf hash.
///
/// All byte-slice fields are UTF-8 encoded strings (wallet hashes, serial
/// numbers, facility IDs, hex-encoded contract SHA-256 digests).
/// Integer fields are encoded big-endian in the hash preimage.
#[derive(Debug, Clone)]
pub enum EventPayload<'a> {
    /// `BLAKE2b(0x01 || wallet_hash)` - no length prefix.
    ProgramEntry {
        wallet_hash: &'a [u8],
    },
    /// `BLAKE2b(0x02 || len(wallet) || wallet || len(serial) || serial)`
    OwnershipAttest {
        wallet_hash: &'a [u8],
        serial_number: &'a [u8],
    },
    /// `BLAKE2b(0x03 || len(serial) || serial || len(contract_sha256) || contract_sha256)`
    ContractAnchor {
        serial_number: &'a [u8],
        contract_sha256: &'a [u8],
    },
    /// `BLAKE2b(0x04 || len(serial) || serial || len(facility) || facility || timestamp_be)`
    Deployment {
        serial_number: &'a [u8],
        facility_id: &'a [u8],
        timestamp: u64,
    },
    /// `BLAKE2b(0x05 || len(serial) || serial || month_be || year_be)`
    HostingPayment {
        serial_number: &'a [u8],
        month: u32,
        year: u32,
    },
    /// `BLAKE2b(0x06 || len(wallet) || wallet || year_be)`
    ShieldRenewal {
        wallet_hash: &'a [u8],
        year: u32,
    },
    /// `BLAKE2b(0x07 || len(old) || old || len(new) || new || len(serial) || serial)`
    Transfer {
        old_wallet_hash: &'a [u8],
        new_wallet_hash: &'a [u8],
        serial_number: &'a [u8],
    },
    /// `BLAKE2b(0x08 || len(wallet) || wallet || len(serial) || serial || timestamp_be)`
    Exit {
        wallet_hash: &'a [u8],
        serial_number: &'a [u8],
        timestamp: u64,
    },
    /// Type 0x09: raw 32-byte Merkle root (no additional hashing).
    MerkleRoot {
        root_hash: [u8; 32],
    },
}

/// Position of a sibling node in a Merkle proof step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingPosition {
    Left,
    Right,
}

/// One step in a Merkle inclusion proof.
#[derive(Debug, Clone)]
pub struct ProofStep {
    pub hash: [u8; 32],
    pub position: SiblingPosition,
}

// Core functions

/// BLAKE2b-256 with the selected leaf personalization.
fn leaf_blake2b(data: &[u8], personalization: &Personalization<'_>) -> [u8; 32] {
    let mut params = Params::new();
    params.hash_length(32);
    params.personal(personalization.leaf);
    let h = params.hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// BLAKE2b-256 of `left || right` with the node personalization (`NordicShield_MRK`).
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    node_hash_with_personalization(left, right, None)
}

/// BLAKE2b-256 of `left || right` with an optional custom node personalization.
pub fn node_hash_with_personalization(
    left: &[u8; 32],
    right: &[u8; 32],
    personalization: Option<&Personalization<'_>>,
) -> [u8; 32] {
    let personalization = personalization.unwrap_or(&DEFAULT_PERSONALIZATION);
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);
    let mut params = Params::new();
    params.hash_length(32);
    params.personal(personalization.node);
    let h = params.hash(&data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Append a 2-byte big-endian length prefix followed by the field bytes.
#[inline]
fn push_len_prefixed(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u16).to_be_bytes());
    buf.extend_from_slice(field);
}

/// Compute the leaf hash for an NSM1 event.
///
/// Returns the 32-byte BLAKE2b-256 digest for types 0x01 - 0x08,
/// or the raw root bytes for type 0x09 (`MERKLE_ROOT`).
pub fn compute_leaf_hash(payload: &EventPayload) -> [u8; 32] {
    compute_leaf_hash_with_personalization(payload, None)
}

/// Compute the leaf hash for an NSM1 event with an optional custom personalization.
///
/// Passing `None` preserves the deployed NSM1 defaults.
pub fn compute_leaf_hash_with_personalization(
    payload: &EventPayload,
    personalization: Option<&Personalization<'_>>,
) -> [u8; 32] {
    let personalization = personalization.unwrap_or(&DEFAULT_PERSONALIZATION);
    match payload {
        EventPayload::ProgramEntry { wallet_hash } => {
            let mut buf = Vec::with_capacity(1 + wallet_hash.len());
            buf.push(EventType::ProgramEntry as u8);
            buf.extend_from_slice(wallet_hash);
            leaf_blake2b(&buf, personalization)
        }

        EventPayload::OwnershipAttest { wallet_hash, serial_number } => {
            let mut buf = Vec::with_capacity(1 + 2 + wallet_hash.len() + 2 + serial_number.len());
            buf.push(EventType::OwnershipAttest as u8);
            push_len_prefixed(&mut buf, wallet_hash);
            push_len_prefixed(&mut buf, serial_number);
            leaf_blake2b(&buf, personalization)
        }

        EventPayload::ContractAnchor { serial_number, contract_sha256 } => {
            let mut buf = Vec::with_capacity(1 + 2 + serial_number.len() + 2 + contract_sha256.len());
            buf.push(EventType::ContractAnchor as u8);
            push_len_prefixed(&mut buf, serial_number);
            push_len_prefixed(&mut buf, contract_sha256);
            leaf_blake2b(&buf, personalization)
        }

        EventPayload::Deployment { serial_number, facility_id, timestamp } => {
            let mut buf = Vec::with_capacity(1 + 2 + serial_number.len() + 2 + facility_id.len() + 8);
            buf.push(EventType::Deployment as u8);
            push_len_prefixed(&mut buf, serial_number);
            push_len_prefixed(&mut buf, facility_id);
            buf.extend_from_slice(&timestamp.to_be_bytes());
            leaf_blake2b(&buf, personalization)
        }

        EventPayload::HostingPayment { serial_number, month, year } => {
            let mut buf = Vec::with_capacity(1 + 2 + serial_number.len() + 4 + 4);
            buf.push(EventType::HostingPayment as u8);
            push_len_prefixed(&mut buf, serial_number);
            buf.extend_from_slice(&month.to_be_bytes());
            buf.extend_from_slice(&year.to_be_bytes());
            leaf_blake2b(&buf, personalization)
        }

        EventPayload::ShieldRenewal { wallet_hash, year } => {
            let mut buf = Vec::with_capacity(1 + 2 + wallet_hash.len() + 4);
            buf.push(EventType::ShieldRenewal as u8);
            push_len_prefixed(&mut buf, wallet_hash);
            buf.extend_from_slice(&year.to_be_bytes());
            leaf_blake2b(&buf, personalization)
        }

        EventPayload::Transfer { old_wallet_hash, new_wallet_hash, serial_number } => {
            let mut buf = Vec::with_capacity(
                1 + 2 + old_wallet_hash.len() + 2 + new_wallet_hash.len() + 2 + serial_number.len(),
            );
            buf.push(EventType::Transfer as u8);
            push_len_prefixed(&mut buf, old_wallet_hash);
            push_len_prefixed(&mut buf, new_wallet_hash);
            push_len_prefixed(&mut buf, serial_number);
            leaf_blake2b(&buf, personalization)
        }

        EventPayload::Exit { wallet_hash, serial_number, timestamp } => {
            let mut buf = Vec::with_capacity(1 + 2 + wallet_hash.len() + 2 + serial_number.len() + 8);
            buf.push(EventType::Exit as u8);
            push_len_prefixed(&mut buf, wallet_hash);
            push_len_prefixed(&mut buf, serial_number);
            buf.extend_from_slice(&timestamp.to_be_bytes());
            leaf_blake2b(&buf, personalization)
        }

        EventPayload::MerkleRoot { root_hash } => *root_hash,
    }
}

/// Verify a Merkle inclusion proof.
///
/// Walks from `leaf_hash` through each step in `proof_path`, hashing
/// with `NordicShield_MRK` personalization at each level.
/// Returns `true` if the computed root matches `expected_root`.
pub fn verify_proof(
    leaf_hash: &[u8; 32],
    proof_path: &[ProofStep],
    expected_root: &[u8; 32],
) -> bool {
    let mut current = *leaf_hash;
    for step in proof_path {
        current = match step.position {
            SiblingPosition::Right => node_hash(&current, &step.hash),
            SiblingPosition::Left  => node_hash(&step.hash, &current),
        };
    }
    current == *expected_root
}

// Hex utilities

/// Decode a 64-character hex string to a 32-byte array.
pub fn hex_to_bytes32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Encode bytes as a lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// Tests - vectors from TEST_VECTORS.md and E2E_PROOF_20260327.md

#[cfg(test)]
mod tests {
    use super::*;

    // TEST_VECTORS.md - all 9 event types

    #[test]
    fn vec_01_program_entry() {
        let hash = compute_leaf_hash(&EventPayload::ProgramEntry {
            wallet_hash: b"wallet_abc",
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "344a05bf81faf6e2d54a0e52ea0267aff0244998eb1ee27adf5627413e92f089"
        );
    }

    #[test]
    fn vec_02_ownership_attest() {
        let hash = compute_leaf_hash(&EventPayload::OwnershipAttest {
            wallet_hash: b"wallet_abc",
            serial_number: b"Z15P-2026-001",
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "5d77b9a3435948a98099267e510a14663cc0fa80afd2a3ee5fb4363f6ecdfa13"
        );
    }

    #[test]
    fn vec_03_contract_anchor() {
        let hash = compute_leaf_hash(&EventPayload::ContractAnchor {
            serial_number: b"Z15P-2026-001",
            contract_sha256: b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "ae15a6e4afceee1d6339690204f55d4c1336339ee4736147b3a0760d45c2bf04"
        );
    }

    #[test]
    fn vec_04_deployment() {
        let hash = compute_leaf_hash(&EventPayload::Deployment {
            serial_number: b"Z15P-2026-001",
            facility_id: b"hamus-mo-i-rana",
            timestamp: 1711843200,
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "f265b9a06a61b2b8c6eeed7fc00c7aa686ad511053467815bf1f1037d460e1f1"
        );
    }

    #[test]
    fn vec_05_hosting_payment() {
        let hash = compute_leaf_hash(&EventPayload::HostingPayment {
            serial_number: b"Z15P-2026-001",
            month: 7,
            year: 2026,
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "6fe67554ae4108215a05d2e6f0e24c15fd7d5846ebd653618eff498f1be41a4f"
        );
    }

    #[test]
    fn vec_06_shield_renewal() {
        let hash = compute_leaf_hash(&EventPayload::ShieldRenewal {
            wallet_hash: b"wallet_abc",
            year: 2027,
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "9f49ece77e800ac211f84f1695bea91bc4c93d228ddbce57901b179ea12e9e26"
        );
    }

    #[test]
    fn vec_07_transfer() {
        let hash = compute_leaf_hash(&EventPayload::Transfer {
            old_wallet_hash: b"wallet_abc",
            new_wallet_hash: b"wallet_xyz",
            serial_number: b"Z15P-2026-001",
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "abcc3e0af84d0a3f0ebdb0cd22fc61234e6355c4e77e8b6cdabb86f1ee70a1ec"
        );
    }

    #[test]
    fn vec_08_exit() {
        let hash = compute_leaf_hash(&EventPayload::Exit {
            wallet_hash: b"wallet_abc",
            serial_number: b"Z15P-2026-001",
            timestamp: 1714521600,
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "4e024461b940fb02a31722f60d2a17b667c9caf86e1d4f4e751123c20c6bcaf5"
        );
    }

    #[test]
    fn vec_09_merkle_root() {
        let root = hex_to_bytes32(
            "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
        ).unwrap();
        let hash = compute_leaf_hash(&EventPayload::MerkleRoot { root_hash: root });
        assert_eq!(hash, root);
    }

    // E2E_PROOF_20260327.md - end-to-end proof walk

    #[test]
    fn e2e_program_entry_leaf() {
        let hash = compute_leaf_hash(&EventPayload::ProgramEntry {
            wallet_hash: b"e2e_wallet_20260327",
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b"
        );
    }

    #[test]
    fn e2e_ownership_attest_leaf() {
        let hash = compute_leaf_hash(&EventPayload::OwnershipAttest {
            wallet_hash: b"e2e_wallet_20260327",
            serial_number: b"Z15P-E2E-001",
        });
        assert_eq!(
            bytes_to_hex(&hash),
            "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133"
        );
    }

    #[test]
    fn e2e_node_hash_to_root() {
        let leaf1 = hex_to_bytes32(
            "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
        ).unwrap();
        let leaf2 = hex_to_bytes32(
            "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133",
        ).unwrap();
        let root = node_hash(&leaf1, &leaf2);
        assert_eq!(
            bytes_to_hex(&root),
            "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a"
        );
    }

    #[test]
    fn e2e_verify_proof_leaf1() {
        // Verify leaf1 (PROGRAM_ENTRY) with leaf2 as sibling on the right
        let leaf1 = hex_to_bytes32(
            "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
        ).unwrap();
        let leaf2 = hex_to_bytes32(
            "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133",
        ).unwrap();
        let expected_root = hex_to_bytes32(
            "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
        ).unwrap();

        let proof = vec![ProofStep {
            hash: leaf2,
            position: SiblingPosition::Right,
        }];

        assert!(verify_proof(&leaf1, &proof, &expected_root));
    }

    #[test]
    fn e2e_verify_proof_leaf2() {
        // Verify leaf2 (OWNERSHIP_ATTEST) with leaf1 as sibling on the left
        let leaf1 = hex_to_bytes32(
            "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
        ).unwrap();
        let leaf2 = hex_to_bytes32(
            "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133",
        ).unwrap();
        let expected_root = hex_to_bytes32(
            "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
        ).unwrap();

        let proof = vec![ProofStep {
            hash: leaf1,
            position: SiblingPosition::Left,
        }];

        assert!(verify_proof(&leaf2, &proof, &expected_root));
    }

    #[test]
    fn verify_proof_wrong_root_fails() {
        let leaf = hex_to_bytes32(
            "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
        ).unwrap();
        let sibling = hex_to_bytes32(
            "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133",
        ).unwrap();
        let wrong_root = [0xffu8; 32];

        let proof = vec![ProofStep {
            hash: sibling,
            position: SiblingPosition::Right,
        }];

        assert!(!verify_proof(&leaf, &proof, &wrong_root));
    }

    #[test]
    fn verify_proof_empty_path() {
        // Empty proof path: leaf IS the root
        let leaf = hex_to_bytes32(
            "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
        ).unwrap();
        assert!(verify_proof(&leaf, &[], &leaf));
    }

    #[test]
    fn verify_proof_multi_level() {
        // Build a 4-leaf tree and verify a 2-step proof
        let a = compute_leaf_hash(&EventPayload::ProgramEntry { wallet_hash: b"w1" });
        let b = compute_leaf_hash(&EventPayload::ProgramEntry { wallet_hash: b"w2" });
        let c = compute_leaf_hash(&EventPayload::ProgramEntry { wallet_hash: b"w3" });
        let d = compute_leaf_hash(&EventPayload::ProgramEntry { wallet_hash: b"w4" });

        let ab = node_hash(&a, &b);
        let cd = node_hash(&c, &d);
        let root = node_hash(&ab, &cd);

        // Prove leaf c: sibling d (right), then sibling ab (left)
        let proof = vec![
            ProofStep { hash: d, position: SiblingPosition::Right },
            ProofStep { hash: ab, position: SiblingPosition::Left },
        ];
        assert!(verify_proof(&c, &proof, &root));

        // Prove leaf b: sibling a (left), then sibling cd (right)
        let proof = vec![
            ProofStep { hash: a, position: SiblingPosition::Left },
            ProofStep { hash: cd, position: SiblingPosition::Right },
        ];
        assert!(verify_proof(&b, &proof, &root));
    }

    #[test]
    fn custom_leaf_personalization_changes_hash() {
        let payload = EventPayload::ProgramEntry {
            wallet_hash: b"wallet_abc",
        };
        let custom = Personalization {
            leaf: b"CustomLeafHash!",
            node: DEFAULT_NODE_PERSONAL,
        };

        let default_hash = compute_leaf_hash(&payload);
        let custom_hash = compute_leaf_hash_with_personalization(&payload, Some(&custom));

        assert_ne!(default_hash, custom_hash);
    }

    #[test]
    fn custom_node_personalization_changes_hash() {
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let custom = Personalization {
            leaf: DEFAULT_LEAF_PERSONAL,
            node: b"CustomNodeHash!",
        };

        let default_hash = node_hash(&left, &right);
        let custom_hash = node_hash_with_personalization(&left, &right, Some(&custom));

        assert_ne!(default_hash, custom_hash);
    }

    // Hex utilities

    #[test]
    fn hex_roundtrip() {
        let bytes = [0x01, 0x23, 0xab, 0xff, 0x00, 0x99, 0xde, 0xad,
                     0xbe, 0xef, 0xca, 0xfe, 0x42, 0x00, 0x7f, 0x80,
                     0x01, 0x23, 0xab, 0xff, 0x00, 0x99, 0xde, 0xad,
                     0xbe, 0xef, 0xca, 0xfe, 0x42, 0x00, 0x7f, 0x80];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex_to_bytes32(&hex).unwrap(), bytes);
    }

    #[test]
    fn hex_bad_length() {
        assert!(hex_to_bytes32("abcd").is_none());
        assert!(hex_to_bytes32("").is_none());
    }

    #[test]
    fn event_type_from_byte() {
        assert_eq!(EventType::from_byte(0x01), Some(EventType::ProgramEntry));
        assert_eq!(EventType::from_byte(0x09), Some(EventType::MerkleRoot));
        assert_eq!(EventType::from_byte(0x00), None);
        assert_eq!(EventType::from_byte(0x0a), None);
    }
}
