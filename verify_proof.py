#!/usr/bin/env python3
"""
ZAP1 Merkle-Bundle Verifier
===================================
Verify a Merkle inclusion proof against a supplied root after download.

This proves bundle consistency only. It does not establish the origin or
publication of the supplied root, decrypt a shielded memo, or prove the
underlying event claim.

When a bundle supplies only leaf.hash, its displayed event type is claimed
server metadata. It is not authenticated unless matching typed fields are
provided and recomputed to the same leaf hash.

Usage:
  python3 verify_proof.py --leaf-hash <hex> --proof <json_file> --root <hex>
  python3 verify_proof.py --wallet-hash <str> --serial <str> --proof <json_file> --root <hex>
  python3 verify_proof.py --event-type HOSTING_PAYMENT --serial <str> --month 7 --year 2026 --proof <json_file> --root <hex>

The proof JSON file should contain an array of steps:
  [{"hash": "aabb...", "position": "left|right"}, ...]

Typed reconstruction helpers cover these event types:
  0x01 PROGRAM_ENTRY, 0x02 OWNERSHIP_ATTEST, 0x03 CONTRACT_ANCHOR,
  0x04 DEPLOYMENT, 0x05 HOSTING_PAYMENT, 0x06 SHIELD_RENEWAL,
  0x07 TRANSFER, 0x08 EXIT,
  0x40 AGENT_REGISTER, 0x41 AGENT_POLICY, 0x42 AGENT_ACTION

Hash: BLAKE2b-256, personalization "NordicShield_" (leaf),
"NordicShield_MRK" (node), and "NordicShield_RTK" (root commitment).
"""

import argparse
import json
import re
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
CURRENT_BUNDLE_VERSION = "2"
HISTORICAL_BUNDLE_VERSION = "1.0.0"
MAX_U64 = (1 << 64) - 1
HEX32_RE = re.compile(r"[0-9a-f]{64}\Z")


def require_hex32(value, label: str) -> str:
    if not isinstance(value, str) or HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be exactly 32-byte lowercase hex")
    return value


def decode_hex32(value, label: str) -> bytes:
    return bytes.fromhex(require_hex32(value, label))


def require_leaf_count(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_U64:
        raise ValueError("leaf_count must be an integer from 1 through 2^64-1")
    return value


def require_anchor_height(value, label: str = "anchor.height"):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{label} must be a nonnegative u32 or null")
    return value


def validate_bundle(bundle: object) -> tuple:
    if not isinstance(bundle, dict):
        raise ValueError("proof bundle must be a JSON object")
    if bundle.get("protocol") != "ZAP1":
        raise ValueError("bundle protocol must be exactly 'ZAP1'")

    version = bundle.get("version")
    leaf = bundle.get("leaf")
    proof = bundle.get("proof")
    root = bundle.get("root")
    anchor = bundle.get("anchor")
    if not isinstance(leaf, dict) or not isinstance(root, dict) or not isinstance(anchor, dict):
        raise ValueError("bundle leaf, root, and anchor must be objects")
    if not isinstance(proof, list):
        raise ValueError("bundle proof must be an array")

    scheme = root.get("scheme")
    if scheme not in (COUNT_BOUND_SCHEME, LEGACY_SCHEME):
        raise ValueError("root.scheme is not an admitted ZAP1 Merkle scheme")
    if version == CURRENT_BUNDLE_VERSION:
        pass
    elif version == HISTORICAL_BUNDLE_VERSION and scheme == LEGACY_SCHEME:
        pass
    else:
        raise ValueError("bundle version and root.scheme are not an admitted pair")

    leaf_hex = require_hex32(leaf.get("hash"), "leaf.hash")
    root_hex = require_hex32(root.get("hash"), "root.hash")
    leaf_count = require_leaf_count(root.get("leaf_count"))
    for index, step in enumerate(proof):
        if not isinstance(step, dict):
            raise ValueError(f"proof[{index}] must be an object")
        require_hex32(step.get("hash"), f"proof[{index}].hash")
        if step.get("position") not in ("left", "right"):
            raise ValueError(f"proof[{index}].position must be 'left' or 'right'")

    txid = anchor.get("txid")
    if txid is not None:
        require_hex32(txid, "anchor.txid")
    height = require_anchor_height(anchor.get("height"))
    if scheme == LEGACY_SCHEME and (
        height is None or height > LEGACY_ROOT_MAX_ANCHOR_HEIGHT
    ):
        raise ValueError("historical legacy bundle lacks an admitted anchor height")
    return leaf_hex, proof, root_hex, leaf_count, scheme, height


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
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle node inputs must each be 32 bytes")
    return blake2b(left + right, digest_size=32, person=NODE_PERSONAL).digest()


def commit_root(leaf_count: int, raw_root: bytes) -> bytes:
    leaf_count = require_leaf_count(leaf_count)
    if len(raw_root) != 32:
        raise ValueError("raw Merkle root must be 32 bytes")
    return blake2b(
        b"\x01" + leaf_count.to_bytes(8, "big") + raw_root,
        digest_size=32,
        person=ROOT_PERSONAL,
    ).digest()


def walk_proof(leaf_hash: bytes, proof: list) -> bytes:
    if not isinstance(leaf_hash, bytes) or len(leaf_hash) != 32:
        raise ValueError("leaf hash must be exactly 32 bytes")
    if not isinstance(proof, list):
        raise ValueError("proof must be an array")
    current = leaf_hash
    for index, step in enumerate(proof):
        if not isinstance(step, dict):
            raise ValueError(f"proof[{index}] must be an object")
        sibling = decode_hex32(step.get("hash"), f"proof[{index}].hash")
        position = step.get("position")
        if position == "right":
            current = hash_node(current, sibling)
        elif position == "left":
            current = hash_node(sibling, current)
        else:
            raise ValueError(f"proof[{index}].position must be 'left' or 'right'")
    return current


def historical_legacy_allowed(scheme, anchor_height, allow_flag) -> bool:
    if scheme not in (None, COUNT_BOUND_SCHEME, LEGACY_SCHEME):
        raise ValueError("unrecognized Merkle scheme")
    anchor_height = require_anchor_height(anchor_height, "anchor height")
    return (
        (scheme == LEGACY_SCHEME or (scheme is None and allow_flag))
        and anchor_height is not None
        and anchor_height <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT
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
    if not isinstance(expected_root, bytes) or len(expected_root) != 32:
        raise ValueError("expected root must be exactly 32 bytes")
    leaf_count = require_leaf_count(leaf_count)
    raw_root = walk_proof(leaf_hash, proof)
    count_bound_root = commit_root(leaf_count, raw_root)
    if scheme not in (None, COUNT_BOUND_SCHEME, LEGACY_SCHEME):
        return False, "INVALID", count_bound_root, raw_root

    if scheme in (None, COUNT_BOUND_SCHEME) and count_bound_root == expected_root:
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
        return decode_hex32(args.leaf_hash, "--leaf-hash"), "provided"

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
    parser = argparse.ArgumentParser(description="ZAP1 Merkle-Bundle Verifier")
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

    try:
        with open(args.proof) as f:
            proof_doc = json.load(f)

        bundle = proof_doc if isinstance(proof_doc, dict) and "proof" in proof_doc else None
        if bundle is not None:
            (
                bundle_leaf_hex,
                proof,
                bundle_root_hex,
                bundle_leaf_count,
                scheme,
                bundle_anchor_height,
            ) = validate_bundle(bundle)
            bundle_leaf = bundle["leaf"]
            if args.root is not None and require_hex32(args.root, "--root") != bundle_root_hex:
                raise ValueError("--root does not match bundle root.hash")
            if args.leaf_count is not None and args.leaf_count != bundle_leaf_count:
                raise ValueError("--leaf-count does not match bundle root.leaf_count")
            if args.anchor_height is not None and args.anchor_height != bundle_anchor_height:
                raise ValueError("--anchor-height does not match bundle anchor.height")
            root_hex = bundle_root_hex
            leaf_count = bundle_leaf_count
            anchor_height = bundle_anchor_height
        else:
            if not isinstance(proof_doc, list):
                raise ValueError("proof file must contain a proof array or ZAP1 proof bundle")
            proof = proof_doc
            bundle_leaf = {}
            scheme = None
            if args.root is None:
                raise ValueError("provide --root or a proof bundle with root.hash")
            if args.leaf_count is None:
                raise ValueError("provide --leaf-count or a proof bundle with root.leaf_count")
            root_hex = require_hex32(args.root, "--root")
            leaf_count = require_leaf_count(args.leaf_count)
            anchor_height = require_anchor_height(args.anchor_height, "--anchor-height")

        expected_root = decode_hex32(root_hex, "expected root")
        if bundle is not None and not any(
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
            leaf_hash = decode_hex32(bundle_leaf_hex, "bundle leaf.hash")
            desc = f"claimed bundle type={bundle_leaf.get('event_type', 'unknown')}"
            typed_leaf_verified = None
        else:
            leaf_hash, desc = compute_leaf(args)
            typed_leaf_verified = (
                leaf_hash.hex() == bundle_leaf_hex if bundle is not None else None
            )

        raw_root = walk_proof(leaf_hash, proof)
        count_bound_root = commit_root(leaf_count, raw_root)
        legacy_allowed = historical_legacy_allowed(
            scheme, anchor_height, args.allow_historical_legacy
        )
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1

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

    if typed_leaf_verified is None:
        print("Typed leaf:            UNVERIFIED claimed metadata; no typed witness was recomputed")
    elif typed_leaf_verified:
        print("Typed leaf:            MATCH; supplied fields recompute to the bundle leaf")
    else:
        print("Typed leaf:            MISMATCH; supplied fields do not recompute to the bundle leaf")
        print("FAILED. Typed witness does not match the bundle leaf hash.")
        sys.exit(1)

    current = leaf_hash
    for i, step in enumerate(proof):
        sibling = decode_hex32(step.get("hash"), f"proof[{i}].hash")
        pos = step["position"]
        if pos == "right":
            current = hash_node(current, sibling)
        elif pos == "left":
            current = hash_node(sibling, current)
        else:
            print(f"FAILED. Invalid proof position at step {i}: {pos!r}")
            sys.exit(1)
        print(f"  Step {i}: sibling={step['hash'][:16]}... ({pos}) -> {current.hex()[:16]}...")

    if current != raw_root:
        print("FAILED. Internal proof walk mismatch.")
        return 1

    print()
    print(f"Computed v2 root:      {count_bound_root.hex()}")
    print(f"Legacy raw root:       {current.hex()}")
    if scheme in (None, COUNT_BOUND_SCHEME) and count_bound_root == expected_root:
        print("MERKLE MATCH. Count-bound proof includes the supplied leaf hash under the supplied root.")
        if typed_leaf_verified is None:
            print("CLAIMED TYPE UNVERIFIED. Provide and recompute a typed witness to authenticate it.")
        return 0
    if current == expected_root and legacy_allowed:
        print("MERKLE MATCH. Historical legacy proof includes the supplied leaf hash under the supplied pre-fix root.")
        if typed_leaf_verified is None:
            print("CLAIMED TYPE UNVERIFIED. Provide and recompute a typed witness to authenticate it.")
        print(f"WARNING: legacy roots do not bind leaf_count; accepted only through height {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}.")
        return 0

    if current == expected_root:
        print("FAILED. Proof resolves only to the legacy raw root.")
        print(
            f"        Legacy requires root.scheme={LEGACY_SCHEME!r} or --allow-historical-legacy, "
            f"plus anchor height <= {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}."
        )
    else:
        print("FAILED. Computed root does not match the expected root.")
    print(f"        Expected:      {expected_root.hex()}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
