# ZAP1 Test Vectors

Date: 2026-03-28
Status: Protocol specification deliverable
Sources:

- `tests/memo_merkle_test.rs`
- `verify_proof.py`
- `src/memo.rs`
- `ONCHAIN_PROTOCOL.md`

This document publishes a standalone JSON test vector suite for the nine deployed ZAP1 event types (`0x01` through `0x09`).

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
  "suite": "ZAP1 deployed event vectors",
  "version": "2026-03-28",
  "leaf_hash_function": "BLAKE2b-256",
  "leaf_personalization": "NordicShield_",
  "node_hash_function": "BLAKE2b-256",
  "node_personalization": "NordicShield_MRK",
  "source_files": [
    "zap1/tests/memo_merkle_test.rs",
    "verify_proof.py",
    "zap1/src/memo.rs",
    "ONCHAIN_PROTOCOL.md"
  ],
  "vectors": [
    {
      "event_type": "PROGRAM_ENTRY",
      "type_byte": "0x01",
      "input_fields": {
        "wallet_hash": "wallet_abc"
      },
      "expected_leaf_hash": "344a05bf81faf6e2d54a0e52ea0267aff0244998eb1ee27adf5627413e92f089",
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
      "expected_leaf_hash": "5d77b9a3435948a98099267e510a14663cc0fa80afd2a3ee5fb4363f6ecdfa13",
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
      "expected_leaf_hash": "ae15a6e4afceee1d6339690204f55d4c1336339ee4736147b3a0760d45c2bf04",
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
      "expected_leaf_hash": "f265b9a06a61b2b8c6eeed7fc00c7aa686ad511053467815bf1f1037d460e1f1",
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
      "expected_leaf_hash": "6fe67554ae4108215a05d2e6f0e24c15fd7d5846ebd653618eff498f1be41a4f",
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
      "expected_leaf_hash": "9f49ece77e800ac211f84f1695bea91bc4c93d228ddbce57901b179ea12e9e26",
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
      "expected_leaf_hash": "abcc3e0af84d0a3f0ebdb0cd22fc61234e6355c4e77e8b6cdabb86f1ee70a1ec",
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
      "expected_leaf_hash": "4e024461b940fb02a31722f60d2a17b667c9caf86e1d4f4e751123c20c6bcaf5",
      "hash_function_used": "BLAKE2b-256 with NordicShield_ personalization",
      "construction_rule": "BLAKE2b_32(0x08 || len(wallet_hash) || wallet_hash || len(serial_number) || serial_number || timestamp_be)"
    },
    {
      "event_type": "MERKLE_ROOT",
      "type_byte": "0x09",
      "input_fields": {
        "root_hash": "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a"
      },
      "expected_leaf_hash": "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a",
      "hash_function_used": "raw 32-byte Merkle root payload (no additional BLAKE2b leaf hashing for type 0x09)",
      "construction_rule": "MERKLE_ROOT = current_root"
    }
  ]
}
```

## Notes

- The sample values are deterministic and can be recomputed with the hash functions in `verify_proof.py`.
- Any implementation can use these vectors to confirm leaf construction matches ZAP1.
- `MERKLE_ROOT` is included because it is one of the nine deployed ZAP1 event types, but it is not hashed the same way as `0x01` through `0x08`.
