#!/usr/bin/env python3
"""
ZAP1 Independent Verifier
===================================
Verify a Merkle inclusion proof without trusting the operator's server.

Usage:
  python3 verify_proof.py --leaf-hash <hex> --proof <json_file> --root <hex>
  python3 verify_proof.py --wallet-hash <str> --serial <str> --proof <json_file> --root <hex>
  python3 verify_proof.py --event-type HOSTING_PAYMENT --serial <str> --month 7 --year 2026 --proof <json_file> --root <hex>

The proof JSON file should contain an array of steps:
  [{"hash": "aabb...", "position": "left|right"}, ...]

Supports all 12 ZAP1 event types (ONCHAIN_PROTOCOL.md):
  0x01 PROGRAM_ENTRY, 0x02 OWNERSHIP_ATTEST, 0x03 CONTRACT_ANCHOR,
  0x04 DEPLOYMENT, 0x05 HOSTING_PAYMENT, 0x06 SHIELD_RENEWAL,
  0x07 TRANSFER, 0x08 EXIT, 0x09 MERKLE_ROOT,
  0x40 AGENT_REGISTER, 0x41 AGENT_POLICY, 0x42 AGENT_ACTION

Hash: BLAKE2b-256, personalization "NordicShield_" (leaf),
"NordicShield_MRK" (node), and "NordicShield_RTK" (root commitment).
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
ROOT_PERSONAL = b"NordicShield_RTK"  # 16 bytes
COUNT_BOUND_SCHEME = "ZAP1_COUNT_BOUND_V2"
LEGACY_SCHEME = "ZAP1_LEGACY_DUPLICATE_ODD"
LEGACY_ROOT_MAX_ANCHOR_HEIGHT = 3317133


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


def hash_agent_register(agent_id: str, pubkey_hash: str, model_hash: str, policy_hash: str) -> bytes:
    return _hash(
        0x40,
        _len_prefix(agent_id) + _len_prefix(pubkey_hash) + _len_prefix(model_hash) + _len_prefix(policy_hash),
    )


def hash_agent_policy(agent_id: str, policy_version: int, rules_hash: str) -> bytes:
    return _hash(0x41, _len_prefix(agent_id) + struct.pack(">I", policy_version) + _len_prefix(rules_hash))


def hash_agent_action(agent_id: str, action_type: str, input_hash: str, output_hash: str) -> bytes:
    return _hash(
        0x42,
        _len_prefix(agent_id) + _len_prefix(action_type) + _len_prefix(input_hash) + _len_prefix(output_hash),
    )


def hash_node(left: bytes, right: bytes) -> bytes:
    return blake2b(left + right, digest_size=32, person=NODE_PERSONAL).digest()


def commit_root(leaf_count: int, raw_root: bytes) -> bytes:
    if leaf_count <= 0:
        raise ValueError("leaf_count must be positive")
    return blake2b(
        b"\x01" + int(leaf_count).to_bytes(8, "big") + raw_root,
        digest_size=32,
        person=ROOT_PERSONAL,
    ).digest()


def walk_proof(leaf_hash: bytes, proof: list) -> bytes:
    current = leaf_hash
    for step in proof:
        sibling = bytes.fromhex(step["hash"])
        if step["position"] == "right":
            current = hash_node(current, sibling)
        else:
            current = hash_node(sibling, current)
    return current


def historical_legacy_allowed(scheme, anchor_height, allow_flag) -> bool:
    return (
        (allow_flag or scheme == LEGACY_SCHEME)
        and anchor_height is not None
        and int(anchor_height) <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT
    )


def verify_proof(
    leaf_hash: bytes,
    proof: list,
    expected_root: bytes,
    leaf_count: int,
    scheme=None,
    anchor_height=None,
    allow_historical_legacy: bool = False,
) -> tuple:
    raw_root = walk_proof(leaf_hash, proof)
    count_bound_root = commit_root(leaf_count, raw_root)

    if count_bound_root == expected_root:
        return True, COUNT_BOUND_SCHEME, count_bound_root, raw_root

    if raw_root == expected_root and historical_legacy_allowed(
        scheme, anchor_height, allow_historical_legacy
    ):
        return True, LEGACY_SCHEME, count_bound_root, raw_root

    return False, "INVALID", count_bound_root, raw_root


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

    if et == "AGENT_REGISTER":
        h = hash_agent_register(args.agent_id, args.pubkey_hash, args.model_hash, args.policy_hash)
        return h, f"AGENT_REGISTER agent={args.agent_id}"

    if et == "AGENT_POLICY":
        h = hash_agent_policy(args.agent_id, args.policy_version, args.rules_hash)
        return h, f"AGENT_POLICY agent={args.agent_id} version={args.policy_version}"

    if et == "AGENT_ACTION":
        h = hash_agent_action(args.agent_id, args.action_type, args.input_hash, args.output_hash)
        return h, f"AGENT_ACTION agent={args.agent_id} action={args.action_type}"

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
    parser = argparse.ArgumentParser(description="ZAP1 Merkle Proof Verifier (all 9 event types)")
    parser.add_argument("--leaf-hash", help="Hex-encoded leaf hash (if known)")
    parser.add_argument("--event-type", help="Event type: PROGRAM_ENTRY, OWNERSHIP_ATTEST, CONTRACT_ANCHOR, DEPLOYMENT, HOSTING_PAYMENT, SHIELD_RENEWAL, TRANSFER, EXIT, AGENT_REGISTER, AGENT_POLICY, AGENT_ACTION")
    parser.add_argument("--wallet-hash", help="Wallet hash string")
    parser.add_argument("--serial", help="Serial number")
    parser.add_argument("--contract-sha256", help="Contract SHA-256 (for CONTRACT_ANCHOR)")
    parser.add_argument("--facility-id", help="Facility identifier (for DEPLOYMENT)")
    parser.add_argument("--month", type=int, help="Month (for HOSTING_PAYMENT)")
    parser.add_argument("--year", type=int, help="Year (for HOSTING_PAYMENT, SHIELD_RENEWAL)")
    parser.add_argument("--new-wallet-hash", help="New wallet hash (for TRANSFER)")
    parser.add_argument("--timestamp", type=int, default=0, help="Unix timestamp (for DEPLOYMENT, EXIT)")
    parser.add_argument("--agent-id", help="Agent identifier (for AGENT_* types)")
    parser.add_argument("--pubkey-hash", help="Agent pubkey hash (for AGENT_REGISTER)")
    parser.add_argument("--model-hash", help="Agent model hash (for AGENT_REGISTER)")
    parser.add_argument("--policy-hash", help="Agent policy hash (for AGENT_REGISTER)")
    parser.add_argument("--policy-version", type=int, help="Policy version (for AGENT_POLICY)")
    parser.add_argument("--rules-hash", help="Policy rules hash (for AGENT_POLICY)")
    parser.add_argument("--action-type", help="Action type label (for AGENT_ACTION)")
    parser.add_argument("--input-hash", help="Action input hash (for AGENT_ACTION)")
    parser.add_argument("--output-hash", help="Action output hash (for AGENT_ACTION)")
    parser.add_argument("--proof", required=True, help="Path to proof JSON file")
    parser.add_argument("--root", help="Hex-encoded expected Merkle root")
    parser.add_argument("--leaf-count", type=int, help="Leaf count bound into the ZAP1 v2 root")
    parser.add_argument("--anchor-height", type=int, help="Anchor height for historical legacy roots")
    parser.add_argument(
        "--allow-historical-legacy",
        action="store_true",
        help=f"Permit legacy raw-root verification only when --anchor-height <= {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}",
    )
    args = parser.parse_args()

    with open(args.proof) as f:
        proof_doc = json.load(f)

    bundle = proof_doc if isinstance(proof_doc, dict) and "proof" in proof_doc else None
    proof = bundle["proof"] if bundle else proof_doc
    if not isinstance(proof, list):
        print("Error: proof file must contain a proof array or ZAP1 proof bundle")
        sys.exit(1)

    bundle_root = bundle.get("root", {}) if bundle else {}
    bundle_anchor = bundle.get("anchor", {}) if bundle else {}
    bundle_leaf = bundle.get("leaf", {}) if bundle else {}

    root_hex = args.root or bundle_root.get("hash")
    if not root_hex:
        print("Error: provide --root or a proof bundle with root.hash")
        sys.exit(1)

    leaf_count = args.leaf_count if args.leaf_count is not None else bundle_root.get("leaf_count")
    if leaf_count is None:
        print("Error: provide --leaf-count or a proof bundle with root.leaf_count")
        sys.exit(1)

    anchor_height = (
        args.anchor_height
        if args.anchor_height is not None
        else bundle_anchor.get("height")
    )
    scheme = bundle_root.get("scheme")

    expected_root = bytes.fromhex(root_hex)
    if bundle_leaf.get("hash") and not any(
        [
            args.leaf_hash,
            args.wallet_hash,
            args.serial,
            args.event_type,
            args.contract_sha256,
            args.facility_id,
            args.new_wallet_hash,
            args.agent_id,
        ]
    ):
        leaf_hash = bytes.fromhex(bundle_leaf["hash"])
        desc = f"bundle leaf event={bundle_leaf.get('event_type', 'unknown')}"
    else:
        leaf_hash, desc = compute_leaf(args)

    print(f"Event:                 {desc}")
    print(f"Leaf hash:             {leaf_hash.hex()}")
    print(f"Expected root:         {expected_root.hex()}")
    print(f"Leaf count:            {int(leaf_count)}")
    if anchor_height is not None:
        print(f"Anchor height:         {anchor_height}")
    if scheme:
        print(f"Bundle root scheme:    {scheme}")
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

    count_bound_root = commit_root(int(leaf_count), current)
    legacy_allowed = historical_legacy_allowed(
        scheme, anchor_height, args.allow_historical_legacy
    )

    print()
    print(f"Computed v2 root:      {count_bound_root.hex()}")
    print(f"Legacy raw root:       {current.hex()}")
    if count_bound_root == expected_root:
        print("VERIFIED. Count-bound proof is valid. Leaf is included in the published root.")
        sys.exit(0)
    if current == expected_root and legacy_allowed:
        print("VERIFIED. Historical legacy proof is valid for the supplied pre-fix anchor height.")
        print(f"WARNING: legacy roots do not bind leaf_count; accepted only through height {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}.")
        sys.exit(0)

    if current == expected_root:
        print("FAILED. Proof resolves only to the legacy raw root.")
        print(
            f"        Legacy requires root.scheme={LEGACY_SCHEME!r} or --allow-historical-legacy, "
            f"plus anchor height <= {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}."
        )
    else:
        print("FAILED. Computed root does not match the expected root.")
    print(f"        Expected:      {expected_root.hex()}")
    sys.exit(1)


if __name__ == "__main__":
    main()
