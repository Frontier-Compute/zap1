use zap1::memo::{
    hash_agent_action, hash_agent_policy, hash_agent_register, hash_contract_anchor,
    hash_deployment, hash_exit, hash_governance_proposal, hash_governance_result,
    hash_governance_vote, hash_hosting_payment, hash_ownership_attest, hash_program_entry,
    hash_shield_renewal, hash_staking_deposit, hash_staking_reward, hash_staking_withdraw,
    hash_transfer, merkle_root_memo, MemoType, StructuredMemo,
};
use zap1::merkle::{
    commit_root, compute_legacy_root, compute_raw_tree_root, compute_root, decode_hash,
    generate_proof,
};

#[test]
fn memo_encode_decode_roundtrip() {
    let entry = hash_program_entry("abc123");
    let memo = StructuredMemo {
        memo_type: MemoType::ProgramEntry,
        payload: entry,
    };
    let encoded = memo.encode();
    assert!(encoded.starts_with("ZAP1:01:"));
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
    let bad = format!("ZAP1:ff:{payload_hex}");
    assert!(StructuredMemo::decode(&bad).is_err());
}

#[test]
fn memo_decode_rejects_wrong_length() {
    assert!(StructuredMemo::decode("ZAP1:01:aabb").is_err());
}

#[test]
fn memo_type_roundtrip() {
    for (byte, expected) in [
        (0x01, MemoType::ProgramEntry),
        (0x02, MemoType::OwnershipAttest),
        (0x09, MemoType::MerkleRoot),
    ] {
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
    assert!(encoded.starts_with("ZAP1:09:"));
    assert!(encoded.contains(&"aa".repeat(32)));
}

// Merkle tree tests

#[test]
fn merkle_root_single_leaf() {
    let leaf = hash_program_entry("wallet_a");
    let root = compute_root(&[leaf]);
    assert_ne!(root, leaf);
    assert_eq!(compute_raw_tree_root(&[leaf]), leaf);
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
fn merkle_root_binds_odd_leaf_count() {
    let a = hash_program_entry("wallet_a");
    let b = hash_program_entry("wallet_b");
    let c = hash_program_entry("wallet_c");
    let root_three = compute_root(&[a, b, c]);
    let root_four = compute_root(&[a, b, c, c]);
    assert_ne!(root_three, root_four);
    assert_eq!(
        compute_legacy_root(&[a, b, c]),
        compute_legacy_root(&[a, b, c, c])
    );
}

#[test]
fn merkle_proof_odd_carry_skips_missing_sibling() {
    let a = hash_program_entry("wallet_a");
    let b = hash_program_entry("wallet_b");
    let c = hash_program_entry("wallet_c");
    let proof = generate_proof(&[a, b, c], 2);
    assert_eq!(proof.len(), 1);
    assert_eq!(proof[0].hash, hex::encode(compute_raw_tree_root(&[a, b])));
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
        for step in &proof {
            let sibling = decode_hash(&step.hash).unwrap();
            let (left, right) = match step.position {
                zap1::merkle::ProofPosition::Right => (&current, &sibling),
                zap1::merkle::ProofPosition::Left => (&sibling, &current),
            };
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(left);
            input[32..].copy_from_slice(right);
            let hash = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"NordicShield_MRK")
                .hash(&input);
            current.copy_from_slice(hash.as_bytes());
        }
        assert_eq!(
            commit_root(leaves.len(), &current),
            root,
            "Proof verification failed for leaf {i}"
        );
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

// Legacy NSM1 backward compatibility

#[test]
fn legacy_nsm1_prefix_decodes() {
    let entry = hash_program_entry("wallet_legacy");
    let memo = StructuredMemo {
        memo_type: MemoType::ProgramEntry,
        payload: entry,
    };
    let encoded = memo.encode();
    let legacy = encoded.replace("ZAP1:", "NSM1:");
    let decoded = StructuredMemo::decode(&legacy).unwrap();
    assert_eq!(decoded.memo_type, MemoType::ProgramEntry);
    assert_eq!(decoded.payload, entry);
}

#[test]
fn new_zap1_prefix_encodes() {
    let memo = StructuredMemo {
        memo_type: MemoType::ProgramEntry,
        payload: [0u8; 32],
    };
    assert!(memo.encode().starts_with("ZAP1:"));
}

// All event type hash functions

#[test]
fn contract_anchor_hash_deterministic() {
    let h1 = hash_contract_anchor(
        "Z15P-001",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    );
    let h2 = hash_contract_anchor(
        "Z15P-001",
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    );
    assert_eq!(h1, h2);
}

#[test]
fn deployment_hash_deterministic() {
    let h1 = hash_deployment("Z15P-001", "NO-ARCTIC-01", 1711500000);
    let h2 = hash_deployment("Z15P-001", "NO-ARCTIC-01", 1711500000);
    assert_eq!(h1, h2);
}

#[test]
fn deployment_different_timestamp() {
    let h1 = hash_deployment("Z15P-001", "NO-ARCTIC-01", 1711500000);
    let h2 = hash_deployment("Z15P-001", "NO-ARCTIC-01", 1711500001);
    assert_ne!(h1, h2);
}

#[test]
fn hosting_payment_hash_deterministic() {
    let h1 = hash_hosting_payment("Z15P-001", 3, 2026);
    let h2 = hash_hosting_payment("Z15P-001", 3, 2026);
    assert_eq!(h1, h2);
}

#[test]
fn hosting_payment_different_month() {
    let h1 = hash_hosting_payment("Z15P-001", 3, 2026);
    let h2 = hash_hosting_payment("Z15P-001", 4, 2026);
    assert_ne!(h1, h2);
}

#[test]
fn shield_renewal_hash_deterministic() {
    let h1 = hash_shield_renewal("wallet_abc", 2026);
    let h2 = hash_shield_renewal("wallet_abc", 2026);
    assert_eq!(h1, h2);
}

#[test]
fn transfer_hash_deterministic() {
    let h1 = hash_transfer("old_wallet", "new_wallet", "Z15P-001");
    let h2 = hash_transfer("old_wallet", "new_wallet", "Z15P-001");
    assert_eq!(h1, h2);
}

#[test]
fn transfer_direction_matters() {
    let h1 = hash_transfer("wallet_a", "wallet_b", "Z15P-001");
    let h2 = hash_transfer("wallet_b", "wallet_a", "Z15P-001");
    assert_ne!(h1, h2);
}

#[test]
fn exit_hash_deterministic() {
    let h1 = hash_exit("wallet_abc", "Z15P-001", 1711500000);
    let h2 = hash_exit("wallet_abc", "Z15P-001", 1711500000);
    assert_eq!(h1, h2);
}

// Mainnet verification: known leaf hash from block 3,286,631

#[test]
fn mainnet_program_entry_e2e_wallet() {
    let hash = hash_program_entry("e2e_wallet_20260327");
    let expected = "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b";
    assert_eq!(hex::encode(hash), expected);
}

// All memo type labels roundtrip

#[test]
fn all_memo_type_labels_roundtrip() {
    assert_eq!(MemoType::ALL.len(), 18);
    for expected in MemoType::ALL {
        let byte = expected.as_u8();
        let label = expected.label();
        assert_eq!(MemoType::from_u8(byte).unwrap(), expected);
        assert_eq!(MemoType::from_label(label).unwrap(), expected);
    }
}

// Merkle tree with many leaves

#[test]
fn merkle_proof_verifies_12_leaves() {
    let leaves: Vec<[u8; 32]> = (0..12)
        .map(|i| hash_program_entry(&format!("participant_{i}")))
        .collect();
    let root = compute_root(&leaves);

    for i in 0..12 {
        let proof = generate_proof(&leaves, i);
        let mut current = leaves[i];
        for step in &proof {
            let sibling = decode_hash(&step.hash).unwrap();
            let (left, right) = match step.position {
                zap1::merkle::ProofPosition::Right => (&current, &sibling),
                zap1::merkle::ProofPosition::Left => (&sibling, &current),
            };
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(left);
            input[32..].copy_from_slice(right);
            let hash = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"NordicShield_MRK")
                .hash(&input);
            current.copy_from_slice(hash.as_bytes());
        }
        assert_eq!(
            commit_root(leaves.len(), &current),
            root,
            "Proof failed for leaf {i} of 12"
        );
    }
}

#[test]
fn staking_deposit_hash_deterministic() {
    let a = hash_staking_deposit("validator_001", 1_000_000_000, "val-london-01");
    let b = hash_staking_deposit("validator_001", 1_000_000_000, "val-london-01");
    assert_eq!(a, b);
    let c = hash_staking_deposit("validator_002", 1_000_000_000, "val-london-01");
    assert_ne!(a, c);
}

#[test]
fn staking_withdraw_hash_deterministic() {
    let a = hash_staking_withdraw("validator_001", 500_000_000, "val-london-01");
    let b = hash_staking_withdraw("validator_001", 500_000_000, "val-london-01");
    assert_eq!(a, b);
    let c = hash_staking_withdraw("validator_001", 500_000_001, "val-london-01");
    assert_ne!(a, c);
}

#[test]
fn staking_reward_hash_deterministic() {
    let a = hash_staking_reward("validator_001", 312_500, 1);
    let b = hash_staking_reward("validator_001", 312_500, 1);
    assert_eq!(a, b);
    let c = hash_staking_reward("validator_001", 312_500, 2);
    assert_ne!(a, c);
}

#[test]
fn governance_proposal_hash_deterministic() {
    let a = hash_governance_proposal("dao_op", "prop-001", "abcdef1234");
    let b = hash_governance_proposal("dao_op", "prop-001", "abcdef1234");
    assert_eq!(a, b);
    let c = hash_governance_proposal("dao_op", "prop-002", "abcdef1234");
    assert_ne!(a, c);
}

#[test]
fn governance_vote_hash_deterministic() {
    let a = hash_governance_vote("voter_a", "prop-001", "commitment_hash_a");
    let b = hash_governance_vote("voter_a", "prop-001", "commitment_hash_a");
    assert_eq!(a, b);
    let c = hash_governance_vote("voter_b", "prop-001", "commitment_hash_a");
    assert_ne!(a, c);
}

#[test]
fn governance_result_hash_deterministic() {
    let a = hash_governance_result("dao_op", "prop-001", "tally_hash");
    let b = hash_governance_result("dao_op", "prop-001", "tally_hash");
    assert_eq!(a, b);
    let c = hash_governance_result("dao_op", "prop-001", "different_tally");
    assert_ne!(a, c);
}

#[test]
fn agent_register_hash_binds_every_field() {
    let base = hash_agent_register(
        "agent_001",
        "pubkey_hash_001",
        "model_hash_001",
        "policy_hash_001",
    );
    assert_eq!(
        base,
        hash_agent_register(
            "agent_001",
            "pubkey_hash_001",
            "model_hash_001",
            "policy_hash_001",
        )
    );
    assert_ne!(
        base,
        hash_agent_register(
            "agent_002",
            "pubkey_hash_001",
            "model_hash_001",
            "policy_hash_001",
        )
    );
    assert_ne!(
        base,
        hash_agent_register(
            "agent_001",
            "pubkey_hash_002",
            "model_hash_001",
            "policy_hash_001",
        )
    );
    assert_ne!(
        base,
        hash_agent_register(
            "agent_001",
            "pubkey_hash_001",
            "model_hash_002",
            "policy_hash_001",
        )
    );
    assert_ne!(
        base,
        hash_agent_register(
            "agent_001",
            "pubkey_hash_001",
            "model_hash_001",
            "policy_hash_002",
        )
    );
}

#[test]
fn agent_policy_hash_binds_every_field() {
    let base = hash_agent_policy("agent_001", 7, "rules_hash_001");
    assert_eq!(base, hash_agent_policy("agent_001", 7, "rules_hash_001"));
    assert_ne!(base, hash_agent_policy("agent_002", 7, "rules_hash_001"));
    assert_ne!(base, hash_agent_policy("agent_001", 8, "rules_hash_001"));
    assert_ne!(base, hash_agent_policy("agent_001", 7, "rules_hash_002"));
}

#[test]
fn agent_action_hash_binds_every_field() {
    let base = hash_agent_action(
        "agent_001",
        "tool_call",
        "input_hash_001",
        "output_hash_001",
    );
    assert_eq!(
        base,
        hash_agent_action(
            "agent_001",
            "tool_call",
            "input_hash_001",
            "output_hash_001",
        )
    );
    assert_ne!(
        base,
        hash_agent_action(
            "agent_002",
            "tool_call",
            "input_hash_001",
            "output_hash_001",
        )
    );
    assert_ne!(
        base,
        hash_agent_action("agent_001", "transfer", "input_hash_001", "output_hash_001",)
    );
    assert_ne!(
        base,
        hash_agent_action(
            "agent_001",
            "tool_call",
            "input_hash_002",
            "output_hash_001",
        )
    );
    assert_ne!(
        base,
        hash_agent_action(
            "agent_001",
            "tool_call",
            "input_hash_001",
            "output_hash_002",
        )
    );
}

#[test]
fn extended_registry_vectors_match_independent_values() {
    let vectors = [
        (
            hash_staking_deposit(
                "crosslink_validator_001",
                1_000_000_000,
                "validator-london-01",
            ),
            "94473f27ed59a1cca8353a5e26127dd61b3f23c67320c5f1c458e3dbc0d61803",
        ),
        (
            hash_staking_withdraw(
                "crosslink_validator_001",
                500_000_000,
                "validator-london-01",
            ),
            "02cf2490cb4746354914af7225187aa9fab5095a1e5e7f76246c7ae8f29172c0",
        ),
        (
            hash_staking_reward("crosslink_validator_001", 312_500, 1),
            "22371dd6f20d531631e331dc6ff27cd633e6eee9c92b3df1418da53885aaec43",
        ),
        (
            hash_governance_proposal("dao_operator_001", "proposal-001", "abcdef1234"),
            "2106e98c28c3f8812ecdfe3a7a97c31eeb88096ae69162f57eec1d17d4c371d7",
        ),
        (
            hash_governance_vote("voter_001", "proposal-001", "commitment_hash_001"),
            "9506b5d69b9e8ee0305460440a87205ae405acab6f17dd3cbd1d45969aa2a9ef",
        ),
        (
            hash_governance_result("dao_operator_001", "proposal-001", "tally_hash_001"),
            "ea0cb641d1ca12a1bf943057a77c5a5715d0bccb0d3a6862a907fc7b352191f4",
        ),
        (
            hash_agent_register(
                "agent_001",
                "pubkey_hash_001",
                "model_hash_001",
                "policy_hash_001",
            ),
            "e3042e9891a9eb88fd4e8053189abe27707803bf81ae6caea4508c3d4bd7ebda",
        ),
        (
            hash_agent_policy("agent_001", 7, "rules_hash_001"),
            "93686221f113a403eeeab7b15d7c5845fe9a9abb16d3ad0931d155c23b53a75a",
        ),
        (
            hash_agent_action(
                "agent_001",
                "tool_call",
                "input_hash_001",
                "output_hash_001",
            ),
            "d68620ccc6de6957ab6b01fe8830ac64e2e2c455b80ce4506ef41078bcbb76f6",
        ),
    ];

    for (actual, expected_hex) in vectors {
        assert_eq!(hex::encode(actual), expected_hex);
    }
}
