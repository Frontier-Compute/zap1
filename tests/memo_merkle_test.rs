use nsm1::memo::{
    hash_ownership_attest, hash_program_entry, merkle_root_memo, MemoType, StructuredMemo,
};
use nsm1::merkle::{compute_root, decode_hash, generate_proof};

#[test]
fn memo_encode_decode_roundtrip() {
    let entry = hash_program_entry("abc123");
    let memo = StructuredMemo {
        memo_type: MemoType::ProgramEntry,
        payload: entry,
    };
    let encoded = memo.encode();
    assert!(encoded.starts_with("NSM1:01:"));
    let decoded = StructuredMemo::decode(&encoded).unwrap();
    assert_eq!(decoded.memo_type, MemoType::ProgramEntry);
    assert_eq!(decoded.payload, entry);
}

#[test]
fn memo_decode_rejects_bad_prefix() {
    assert!(StructuredMemo::decode("FAKE:01:aa").is_err());
}

#[test]
fn memo_decode_rejects_unknown_type() {
    let payload_hex = "00".repeat(32);
    let bad = format!("NSM1:ff:{payload_hex}");
    assert!(StructuredMemo::decode(&bad).is_err());
}

#[test]
fn memo_decode_rejects_wrong_length() {
    assert!(StructuredMemo::decode("NSM1:01:aabb").is_err());
}

#[test]
fn memo_type_roundtrip() {
    for (byte, expected) in [(0x01, MemoType::ProgramEntry), (0x02, MemoType::OwnershipAttest), (0x09, MemoType::MerkleRoot)] {
        let t = MemoType::from_u8(byte).unwrap();
        assert_eq!(t, expected);
        assert_eq!(t.as_u8(), byte);
    }
}

#[test]
fn program_entry_hash_deterministic() {
    let h1 = hash_program_entry("wallet_abc");
    let h2 = hash_program_entry("wallet_abc");
    assert_eq!(h1, h2);
}

#[test]
fn program_entry_hash_different_wallets() {
    let h1 = hash_program_entry("wallet_abc");
    let h2 = hash_program_entry("wallet_xyz");
    assert_ne!(h1, h2);
}

#[test]
fn ownership_attest_hash_deterministic() {
    let h1 = hash_ownership_attest("wallet_abc", "Z15P-2026-001");
    let h2 = hash_ownership_attest("wallet_abc", "Z15P-2026-001");
    assert_eq!(h1, h2);
}

#[test]
fn ownership_attest_different_serial() {
    let h1 = hash_ownership_attest("wallet_abc", "Z15P-2026-001");
    let h2 = hash_ownership_attest("wallet_abc", "Z15P-2026-002");
    assert_ne!(h1, h2);
}

#[test]
fn ownership_attest_different_wallet() {
    let h1 = hash_ownership_attest("wallet_abc", "Z15P-2026-001");
    let h2 = hash_ownership_attest("wallet_xyz", "Z15P-2026-001");
    assert_ne!(h1, h2);
}

#[test]
fn merkle_root_memo_encodes_raw_root() {
    let root = [0xaa; 32];
    let memo = merkle_root_memo(&root);
    assert_eq!(memo.memo_type, MemoType::MerkleRoot);
    assert_eq!(memo.payload, root);
    let encoded = memo.encode();
    assert!(encoded.starts_with("NSM1:09:"));
    assert!(encoded.contains(&"aa".repeat(32)));
}

// Merkle tree tests

#[test]
fn merkle_root_single_leaf() {
    let leaf = hash_program_entry("wallet_a");
    let root = compute_root(&[leaf]);
    assert_eq!(root, leaf);
}

#[test]
fn merkle_root_two_leaves() {
    let a = hash_program_entry("wallet_a");
    let b = hash_program_entry("wallet_b");
    let root = compute_root(&[a, b]);
    assert_ne!(root, a);
    assert_ne!(root, b);
    assert_ne!(root, [0u8; 32]);
}

#[test]
fn merkle_root_deterministic() {
    let leaves: Vec<[u8; 32]> = (0..5)
        .map(|i| hash_program_entry(&format!("wallet_{i}")))
        .collect();
    let r1 = compute_root(&leaves);
    let r2 = compute_root(&leaves);
    assert_eq!(r1, r2);
}

#[test]
fn merkle_root_order_matters() {
    let a = hash_program_entry("wallet_a");
    let b = hash_program_entry("wallet_b");
    let r1 = compute_root(&[a, b]);
    let r2 = compute_root(&[b, a]);
    assert_ne!(r1, r2);
}

#[test]
fn merkle_root_empty() {
    let root = compute_root(&[]);
    assert_eq!(root, [0u8; 32]);
}

#[test]
fn merkle_proof_single_leaf() {
    let leaf = hash_program_entry("wallet_a");
    let proof = generate_proof(&[leaf], 0);
    assert!(proof.is_empty());
}

#[test]
fn merkle_proof_two_leaves() {
    let a = hash_program_entry("wallet_a");
    let b = hash_program_entry("wallet_b");
    let proof_a = generate_proof(&[a, b], 0);
    assert_eq!(proof_a.len(), 1);
    assert_eq!(proof_a[0].hash, hex::encode(b));

    let proof_b = generate_proof(&[a, b], 1);
    assert_eq!(proof_b.len(), 1);
    assert_eq!(proof_b[0].hash, hex::encode(a));
}

#[test]
fn merkle_proof_verifies_manually() {
    let leaves: Vec<[u8; 32]> = (0..4)
        .map(|i| hash_program_entry(&format!("wallet_{i}")))
        .collect();
    let root = compute_root(&leaves);

    for i in 0..4 {
        let proof = generate_proof(&leaves, i);
        let mut current = leaves[i];
        let mut idx = i;
        for step in &proof {
            let sibling = decode_hash(&step.hash).unwrap();
            let (left, right) = match step.position {
                nsm1::merkle::ProofPosition::Right => (&current, &sibling),
                nsm1::merkle::ProofPosition::Left => (&sibling, &current),
            };
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(left);
            input[32..].copy_from_slice(right);
            let hash = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"NordicShield_MRK")
                .hash(&input);
            current.copy_from_slice(hash.as_bytes());
            idx /= 2;
        }
        assert_eq!(current, root, "Proof verification failed for leaf {i}");
    }
}

#[test]
fn merkle_proof_out_of_bounds() {
    let a = hash_program_entry("wallet_a");
    let proof = generate_proof(&[a], 5);
    assert!(proof.is_empty());
}

#[test]
fn decode_hash_valid() {
    let hex_str = "aa".repeat(32);
    let result = decode_hash(&hex_str).unwrap();
    assert_eq!(result, [0xaa; 32]);
}

#[test]
fn decode_hash_wrong_length() {
    assert!(decode_hash("aabb").is_err());
}

#[test]
fn decode_hash_invalid_hex() {
    assert!(decode_hash(&"zz".repeat(32)).is_err());
}
