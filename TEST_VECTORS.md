# ZAP1 Test Vectors

Date: 2026-03-31
Status: Protocol specification deliverable
Sources:

- `tests/memo_merkle_test.rs`
- `verify_proof.py`
- `src/memo.rs`
- `conformance/hash_vectors.json`
- `conformance/tree_vectors.json`
- `ONCHAIN_PROTOCOL.md`

This document publishes a standalone test vector suite for all twelve ZAP1 event types (`0x01` through `0x0C`), plus Merkle tree construction vectors and memo encoding vectors.

Hash rules:

- Leaf hashing for `0x01` through `0x08` uses BLAKE2b-256 with personalization `NordicShield_`
- Merkle node hashing uses BLAKE2b-256 with personalization `NordicShield_MRK`
- `0x09 MERKLE_ROOT` is a protocol exception: the payload is the raw 32-byte Merkle root, not a second BLAKE2b leaf hash

Input encoding matches `src/memo.rs` and `verify_proof.py` exactly:

- `wallet_hash`, `serial_number`, `facility_id`, `contract_sha256`, `old_wallet_hash`, and `new_wallet_hash` are length-prefixed with a 2-byte big-endian length when required by the event rule
- `month` and `year` use 4-byte big-endian encoding
- `timestamp` uses 8-byte big-endian encoding
- each hashed event prepends the 1-byte event type before hashing

## JSON Suite

```json
{
  "suite": "ZAP1 event vectors",
  "version": "2026-03-31",
  "leaf_hash_function": "BLAKE2b-256",
  "leaf_personalization": "NordicShield_",
  "node_hash_function": "BLAKE2b-256",
  "node_personalization": "NordicShield_MRK",
  "source_files": [
    "zap1/tests/memo_merkle_test.rs",
    "verify_proof.py",
    "zap1/src/memo.rs",
    "conformance/hash_vectors.json",
    "conformance/tree_vectors.json",
    "ONCHAIN_PROTOCOL.md"
  ],
  "vectors": [
    {
      "event_type": "PROGRAM_ENTRY",
      "type_byte": "0x01",
      "input_fields": {
        "wallet_hash": "wallet_abc"
      },
      "expected_hash": "344a05bf81faf6e2d54a0e52ea0267aff0244998eb1ee27adf5627413e92f089",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x01 || wallet_hash)"
    },
    {
      "event_type": "OWNERSHIP_ATTEST",
      "type_byte": "0x02",
      "input_fields": {
        "wallet_hash": "wallet_abc",
        "serial_number": "Z15P-2026-001"
      },
      "expected_hash": "5d77b9a3435948a98099267e510a14663cc0fa80afd2a3ee5fb4363f6ecdfa13",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x02 || len(wallet_hash) || wallet_hash || len(serial_number) || serial_number)"
    },
    {
      "event_type": "CONTRACT_ANCHOR",
      "type_byte": "0x03",
      "input_fields": {
        "serial_number": "Z15P-2026-001",
        "contract_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      },
      "expected_hash": "ae15a6e4afceee1d6339690204f55d4c1336339ee4736147b3a0760d45c2bf04",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x03 || len(serial_number) || serial_number || len(contract_sha256) || contract_sha256)"
    },
    {
      "event_type": "DEPLOYMENT",
      "type_byte": "0x04",
      "input_fields": {
        "serial_number": "Z15P-2026-001",
        "facility_id": "hamus-mo-i-rana",
        "timestamp": 1711843200
      },
      "expected_hash": "f265b9a06a61b2b8c6eeed7fc00c7aa686ad511053467815bf1f1037d460e1f1",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x04 || len(serial_number) || serial_number || len(facility_id) || facility_id || timestamp_be)"
    },
    {
      "event_type": "HOSTING_PAYMENT",
      "type_byte": "0x05",
      "input_fields": {
        "serial_number": "Z15P-2026-001",
        "month": 7,
        "year": 2026
      },
      "expected_hash": "6fe67554ae4108215a05d2e6f0e24c15fd7d5846ebd653618eff498f1be41a4f",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x05 || len(serial_number) || serial_number || month_be || year_be)"
    },
    {
      "event_type": "SHIELD_RENEWAL",
      "type_byte": "0x06",
      "input_fields": {
        "wallet_hash": "wallet_abc",
        "year": 2027
      },
      "expected_hash": "9f49ece77e800ac211f84f1695bea91bc4c93d228ddbce57901b179ea12e9e26",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x06 || len(wallet_hash) || wallet_hash || year_be)"
    },
    {
      "event_type": "TRANSFER",
      "type_byte": "0x07",
      "input_fields": {
        "old_wallet_hash": "wallet_abc",
        "new_wallet_hash": "wallet_xyz",
        "serial_number": "Z15P-2026-001"
      },
      "expected_hash": "abcc3e0af84d0a3f0ebdb0cd22fc61234e6355c4e77e8b6cdabb86f1ee70a1ec",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x07 || len(old_wallet_hash) || old_wallet_hash || len(new_wallet_hash) || new_wallet_hash || len(serial_number) || serial_number)"
    },
    {
      "event_type": "EXIT",
      "type_byte": "0x08",
      "input_fields": {
        "wallet_hash": "wallet_abc",
        "serial_number": "Z15P-2026-001",
        "timestamp": 1714521600
      },
      "expected_hash": "4e024461b940fb02a31722f60d2a17b667c9caf86e1d4f4e751123c20c6bcaf5",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x08 || len(wallet_hash) || wallet_hash || len(serial_number) || serial_number || timestamp_be)"
    },
    {
      "event_type": "MERKLE_ROOT",
      "type_byte": "0x09",
      "input_fields": {
        "root_hash": "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a"
      },
      "expected_hash": "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
      "hash_function_used": "raw 32-byte Merkle root payload (no additional BLAKE2b leaf hashing for type 0x09)",
      "construction_rule": "MERKLE_ROOT = current_root"
    },
    {
      "event_type": "STAKING_DEPOSIT",
      "type_byte": "0x0A",
      "status": "active",
      "construction_rule": "BLAKE2b_32(personalization: NordicShield_, input: 0x0A || len(wallet_hash) || wallet_hash || amount_zat(8 bytes BE) || len(validator_id) || validator_id)",
      "input_fields": {
        "wallet_hash": "crosslink_validator_001",
        "amount_zat": 1000000000,
        "validator_id": "validator-london-01"
      },
      "expected_hash": "94473f27ed59a1cca8353a5e26127dd61b3f23c67320c5f1c458e3dbc0d61803"
    },
    {
      "event_type": "STAKING_WITHDRAW",
      "type_byte": "0x0B",
      "status": "active",
      "construction_rule": "BLAKE2b_32(personalization: NordicShield_, input: 0x0B || len(wallet_hash) || wallet_hash || amount_zat(8 bytes BE) || len(validator_id) || validator_id)",
      "note": "Same construction as STAKING_DEPOSIT with type byte 0x0B"
    },
    {
      "event_type": "STAKING_REWARD",
      "type_byte": "0x0C",
      "status": "active",
      "construction_rule": "BLAKE2b_32(personalization: NordicShield_, input: 0x0C || len(wallet_hash) || wallet_hash || amount_zat(8 bytes BE) || epoch(4 bytes BE))",
      "input_fields": {
        "wallet_hash": "crosslink_validator_001",
        "amount_zat": 312500,
        "epoch": 1
      },
      "expected_hash": "22371dd6f20d531631e331dc6ff27cd633e6eee9c92b3df1418da53885aaec43"
    }
  ],
  "conformance_vectors": [
    {
      "description": "mainnet PROGRAM_ENTRY from block 3,286,631",
      "event_type": "PROGRAM_ENTRY",
      "type_byte": "0x01",
      "input_fields": {
        "wallet_hash": "e2e_wallet_20260327"
      },
      "expected_hash": "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
      "source": "conformance/hash_vectors.json, tests/memo_merkle_test.rs (mainnet_program_entry_e2e_wallet)"
    },
    {
      "description": "alternate PROGRAM_ENTRY wallet",
      "event_type": "PROGRAM_ENTRY",
      "type_byte": "0x01",
      "input_fields": {
        "wallet_hash": "test_wallet_abc"
      },
      "expected_hash": "771fd5dbf5245e22a43218e4312f9a6e9b020a03a1617e70ee91d10914e82507",
      "source": "conformance/hash_vectors.json"
    },
    {
      "description": "mainnet OWNERSHIP_ATTEST",
      "event_type": "OWNERSHIP_ATTEST",
      "type_byte": "0x02",
      "input_fields": {
        "wallet_hash": "e2e_wallet_20260327",
        "serial_number": "Z15P-E2E-001"
      },
      "expected_hash": "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133",
      "source": "conformance/hash_vectors.json"
    },
    {
      "description": "HOSTING_PAYMENT with test serial",
      "event_type": "HOSTING_PAYMENT",
      "type_byte": "0x05",
      "input_fields": {
        "serial_number": "Z15P-TEST-001",
        "month": 3,
        "year": 2026
      },
      "expected_hash": "dac74f263c985f808aa398d05500f4b6515875fa627cd0c85d5a82ea8b383367",
      "source": "conformance/hash_vectors.json"
    }
  ],
  "merkle_tree_vectors": [
    {
      "description": "empty tree - root is 32 zero bytes",
      "leaves": [],
      "expected_root": "0000000000000000000000000000000000000000000000000000000000000000",
      "note": "compute_root returns all zeros for an empty leaf set",
      "source": "conformance/tree_vectors.json"
    },
    {
      "description": "single leaf - root equals the leaf hash",
      "leaves": [
        "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b"
      ],
      "expected_root": "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
      "note": "no internal node hashing needed for a single leaf",
      "source": "conformance/tree_vectors.json"
    },
    {
      "description": "two-leaf tree from mainnet anchor at block 3,286,631",
      "leaves": [
        "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
        "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133"
      ],
      "expected_root": "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
      "node_hash_function": "BLAKE2b-256 with NordicShield_MRK personalization",
      "construction_rule": "BLAKE2b_32(leaf[0] || leaf[1])",
      "source": "conformance/tree_vectors.json, conformance/hash_vectors.json"
    }
  ],
  "memo_encoding_vectors": [
    {
      "description": "PROGRAM_ENTRY memo wire format",
      "event_type": "PROGRAM_ENTRY",
      "type_byte": "0x01",
      "payload_hash": "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
      "expected_memo_string": "ZAP1:01:075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
      "expected_byte_length": 73,
      "note": "Format is {prefix}:{type_hex}:{payload_hex}. All fields are ASCII.",
      "source": "conformance/hash_vectors.json memo_wire_format"
    },
    {
      "description": "MERKLE_ROOT memo wire format",
      "event_type": "MERKLE_ROOT",
      "type_byte": "0x09",
      "payload_hash": "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
      "expected_memo_string": "ZAP1:09:024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
      "expected_byte_length": 73,
      "note": "MERKLE_ROOT payload is the raw root, not a second hash"
    },
    {
      "description": "legacy NSM1 prefix - accepted during decode",
      "event_type": "PROGRAM_ENTRY",
      "type_byte": "0x01",
      "payload_hash": "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
      "expected_memo_string": "NSM1:01:075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
      "expected_byte_length": 73,
      "note": "NSM1 prefix is accepted during decode for backward compatibility. New memos always encode with ZAP1.",
      "source": "tests/memo_merkle_test.rs (legacy_nsm1_prefix_decodes)"
    }
  ]
}
```

## Notes

- All hash values in this document are verified against `conformance/hash_vectors.json`, `conformance/tree_vectors.json`, and `tests/memo_merkle_test.rs`. No values are fabricated.
- The sample values are deterministic and can be recomputed with the hash functions in `verify_proof.py` or `src/memo.rs`.
- Any implementation can use these vectors to confirm leaf construction matches ZAP1.
- `MERKLE_ROOT` (0x09) is included because it is one of the twelve ZAP1 event types, but it is not hashed the same way as `0x01` through `0x08`. The payload is the raw 32-byte root.
- `STAKING_DEPOSIT` (0x0A), `STAKING_WITHDRAW` (0x0B), and `STAKING_REWARD` (0x0C) are reserved for Crosslink. No hash functions are implemented in the reference codebase. Their construction rules are preliminary. Concrete test vectors will be added when these types activate.
- Merkle tree vectors use `NordicShield_MRK` personalization for internal node hashing. Odd-layer duplication: if a layer has an odd number of nodes, the final node is duplicated before pairing.
- Memo encoding vectors cover the `ZAP1:{type_hex}:{payload_hex}` wire format (73 ASCII bytes) and the legacy `NSM1` prefix accepted during decode.
