#!/usr/bin/env python3
"""
Nordic Shield Independent Verifier
===================================
Verify a Merkle inclusion proof without trusting the operator's server.

Usage:
  python3 verify_proof.py --leaf-hash <hex> --proof <json_file> --root <hex>
  python3 verify_proof.py --wallet-hash <str> --serial <str> --proof <json_file> --root <hex>
  python3 verify_proof.py --event-type HOSTING_PAYMENT --serial <str> --month 7 --year 2026 --proof <json_file> --root <hex>

The proof JSON file should contain an array of steps:
  [{"hash": "aabb...", "position": "left|right"}, ...]

Supports all 9 NSM1 event types (ONCHAIN_PROTOCOL.md v2.0.0):
  0x01 PROGRAM_ENTRY, 0x02 OWNERSHIP_ATTEST, 0x03 CONTRACT_ANCHOR,
  0x04 DEPLOYMENT, 0x05 HOSTING_PAYMENT, 0x06 SHIELD_RENEWAL,
  0x07 TRANSFER, 0x08 EXIT, 0x09 MERKLE_ROOT

Hash: BLAKE2b-256, personalization "NordicShield_" (leaf) / "NordicShield_MRK" (node)
"""

import argparse
import json
import struct
import sys

try:
    from blake2b import blake2b  # type: ignore
except ImportError:
    from hashlib import blake2b  # stdlib fallback (Python 3.6+)


LEAF_PERSONAL = b"NordicShield_\x00\x00\x00"  # 16 bytes
NODE_PERSONAL = b"NordicShield_MRK"  # 16 bytes


def _hash(type_byte: int, payload: bytes) -> bytes:
    data = bytes([type_byte]) + payload
    return blake2b(data, digest_size=32, person=LEAF_PERSONAL).digest()


def _len_prefix(s: str) -> bytes:
    b = s.encode()
    return struct.pack(">H", len(b)) + b


# --- Event hash functions (match src/memo.rs exactly) ---

def hash_program_entry(wallet_hash: str) -> bytes:
    return _hash(0x01, wallet_hash.encode())


def hash_ownership_attest(wallet_hash: str, serial_number: str) -> bytes:
    return _hash(0x02, _len_prefix(wallet_hash) + _len_prefix(serial_number))


def hash_contract_anchor(serial_number: str, contract_sha256: str) -> bytes:
    return _hash(0x03, _len_prefix(serial_number) + _len_prefix(contract_sha256))


def hash_deployment(serial_number: str, facility_id: str, timestamp: int) -> bytes:
    return _hash(0x04, _len_prefix(serial_number) + _len_prefix(facility_id) + struct.pack(">Q", timestamp))


def hash_hosting_payment(serial_number: str, month: int, year: int) -> bytes:
    return _hash(0x05, _len_prefix(serial_number) + struct.pack(">I", month) + struct.pack(">I", year))


def hash_shield_renewal(wallet_hash: str, year: int) -> bytes:
    return _hash(0x06, _len_prefix(wallet_hash) + struct.pack(">I", year))


def hash_transfer(old_wallet: str, new_wallet: str, serial_number: str) -> bytes:
    return _hash(0x07, _len_prefix(old_wallet) + _len_prefix(new_wallet) + _len_prefix(serial_number))


def hash_exit(wallet_hash: str, serial_number: str, timestamp: int) -> bytes:
    return _hash(0x08, _len_prefix(wallet_hash) + _len_prefix(serial_number) + struct.pack(">Q", timestamp))


def hash_node(left: bytes, right: bytes) -> bytes:
    return blake2b(left + right, digest_size=32, person=NODE_PERSONAL).digest()


def verify_proof(leaf_hash: bytes, proof: list, expected_root: bytes) -> bool:
    current = leaf_hash
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        if step["position"] == "right":
            current = hash_node(current, sibling)
        else:
            current = hash_node(sibling, current)
    return current == expected_root


def compute_leaf(args) -> tuple:
    """Returns (leaf_hash, description_string)."""
    et = (args.event_type or "").upper()

    if args.leaf_hash:
        return bytes.fromhex(args.leaf_hash), "provided"

    if et == "CONTRACT_ANCHOR":
        h = hash_contract_anchor(args.serial, args.contract_sha256)
        return h, f"CONTRACT_ANCHOR serial={args.serial} sha256={args.contract_sha256[:16]}..."

    if et == "DEPLOYMENT":
        h = hash_deployment(args.serial, args.facility_id, args.timestamp)
        return h, f"DEPLOYMENT serial={args.serial} facility={args.facility_id} ts={args.timestamp}"

    if et == "HOSTING_PAYMENT":
        h = hash_hosting_payment(args.serial, args.month, args.year)
        return h, f"HOSTING_PAYMENT serial={args.serial} period={args.year}-{args.month:02d}"

    if et == "SHIELD_RENEWAL":
        h = hash_shield_renewal(args.wallet_hash, args.year)
        return h, f"SHIELD_RENEWAL wallet={args.wallet_hash} year={args.year}"

    if et == "TRANSFER":
        h = hash_transfer(args.wallet_hash, args.new_wallet_hash, args.serial)
        return h, f"TRANSFER old={args.wallet_hash} new={args.new_wallet_hash} serial={args.serial}"

    if et == "EXIT":
        h = hash_exit(args.wallet_hash, args.serial, args.timestamp)
        return h, f"EXIT wallet={args.wallet_hash} serial={args.serial} ts={args.timestamp}"

    # Legacy: auto-detect from args
    if args.wallet_hash and args.serial:
        h = hash_ownership_attest(args.wallet_hash, args.serial)
        return h, f"OWNERSHIP_ATTEST wallet={args.wallet_hash} serial={args.serial}"

    if args.wallet_hash:
        h = hash_program_entry(args.wallet_hash)
        return h, f"PROGRAM_ENTRY wallet={args.wallet_hash}"

    print("Error: provide --leaf-hash, or --event-type with required fields, or --wallet-hash")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Nordic Shield Merkle Proof Verifier (all 9 NSM1 event types)")
    parser.add_argument("--leaf-hash", help="Hex-encoded leaf hash (if known)")
    parser.add_argument("--event-type", help="Event type: PROGRAM_ENTRY, OWNERSHIP_ATTEST, CONTRACT_ANCHOR, DEPLOYMENT, HOSTING_PAYMENT, SHIELD_RENEWAL, TRANSFER, EXIT")
    parser.add_argument("--wallet-hash", help="Wallet hash string")
    parser.add_argument("--serial", help="Serial number")
    parser.add_argument("--contract-sha256", help="Contract SHA-256 (for CONTRACT_ANCHOR)")
    parser.add_argument("--facility-id", help="Facility identifier (for DEPLOYMENT)")
    parser.add_argument("--month", type=int, help="Month (for HOSTING_PAYMENT)")
    parser.add_argument("--year", type=int, help="Year (for HOSTING_PAYMENT, SHIELD_RENEWAL)")
    parser.add_argument("--new-wallet-hash", help="New wallet hash (for TRANSFER)")
    parser.add_argument("--timestamp", type=int, default=0, help="Unix timestamp (for DEPLOYMENT, EXIT)")
    parser.add_argument("--proof", required=True, help="Path to proof JSON file")
    parser.add_argument("--root", required=True, help="Hex-encoded expected Merkle root")
    args = parser.parse_args()

    with open(args.proof) as f:
        proof = json.load(f)

    expected_root = bytes.fromhex(args.root)
    leaf_hash, desc = compute_leaf(args)

    print(f"Event:                 {desc}")
    print(f"Leaf hash:             {leaf_hash.hex()}")
    print(f"Expected root:         {expected_root.hex()}")
    print(f"Proof steps:           {len(proof)}")
    print()

    current = leaf_hash
    for i, step in enumerate(proof):
        sibling = bytes.fromhex(step["hash"])
        pos = step["position"]
        if pos == "right":
            current = hash_node(current, sibling)
        else:
            current = hash_node(sibling, current)
        print(f"  Step {i}: sibling={step['hash'][:16]}... ({pos}) -> {current.hex()[:16]}...")

    print()
    if current == expected_root:
        print("VERIFIED. Proof is valid. Leaf is included in the published root.")
        sys.exit(0)
    else:
        print(f"FAILED. Computed root: {current.hex()}")
        print(f"         Expected:     {expected_root.hex()}")
        sys.exit(1)


if __name__ == "__main__":
    main()
