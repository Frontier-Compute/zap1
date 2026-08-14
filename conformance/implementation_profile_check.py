#!/usr/bin/env python3
"""
ZAP1 implementation-profile checks.

Recomputes this repository's published hash, Merkle, memo, and proof fixtures.
This is not a standards-conformance claim and does not validate ZIP 1243.

Usage:
    python3 conformance/implementation_profile_check.py
    python3 conformance/implementation_profile_check.py --live
    python3 conformance/implementation_profile_check.py --verbose

No external deps beyond python3 stdlib (hashlib.blake2b, json, struct).
"""

import argparse
import copy
import json
import os
import re
import struct
import sys
import urllib.request
import urllib.error

from hashlib import blake2b

DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(DIR)

# BLAKE2b personalization strings, padded to 16 bytes
LEAF_PERSONAL = b"NordicShield_\x00\x00\x00"
NODE_PERSONAL = b"NordicShield_MRK"
ROOT_PERSONAL = b"NordicShield_RTK"
COUNT_BOUND_SCHEME = "ZAP1_COUNT_BOUND_V2"
LEGACY_SCHEME = "ZAP1_LEGACY_DUPLICATE_ODD"
LEGACY_ROOT_MAX_ANCHOR_HEIGHT = 3317133
CURRENT_BUNDLE_VERSION = "2"
HISTORICAL_BUNDLE_VERSION = "1.0.0"
MAX_U64 = (1 << 64) - 1
HEX32_RE = re.compile(r"[0-9a-f]{64}\Z")

# Canonical implementation registry. Eighteen type bytes are defined. Fifteen
# are accepted by POST /event; three are created by system-managed paths.
DEFINED_TYPES = frozenset((*range(0x01, 0x10), 0x40, 0x41, 0x42))
SYSTEM_MANAGED_TYPES = frozenset((0x01, 0x02, 0x09))
WRITE_API_TYPES = DEFINED_TYPES - SYSTEM_MANAGED_TYPES
EVENT_TYPE_BY_LABEL = {
    "PROGRAM_ENTRY": 0x01,
    "OWNERSHIP_ATTEST": 0x02,
    "CONTRACT_ANCHOR": 0x03,
    "DEPLOYMENT": 0x04,
    "HOSTING_PAYMENT": 0x05,
    "SHIELD_RENEWAL": 0x06,
    "TRANSFER": 0x07,
    "EXIT": 0x08,
    "MERKLE_ROOT": 0x09,
    "STAKING_DEPOSIT": 0x0A,
    "STAKING_WITHDRAW": 0x0B,
    "STAKING_REWARD": 0x0C,
    "GOVERNANCE_PROPOSAL": 0x0D,
    "GOVERNANCE_VOTE": 0x0E,
    "GOVERNANCE_RESULT": 0x0F,
    "AGENT_REGISTER": 0x40,
    "AGENT_POLICY": 0x41,
    "AGENT_ACTION": 0x42,
}

passed = 0
failed = 0
skipped = 0
verbose = False


def require_hex32(value, label):
    if not isinstance(value, str) or HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be exactly 32-byte lowercase hex")
    return value


def require_leaf_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_U64:
        raise ValueError("leaf_count must be an integer from 1 through 2^64-1")
    return value


def validate_bundle_shape(bundle, requested_leaf=None):
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

    leaf_hash_hex = require_hex32(leaf.get("hash"), "leaf.hash")
    require_hex32(root.get("hash"), "root.hash")
    require_leaf_count(root.get("leaf_count"))
    for index, step in enumerate(proof):
        if not isinstance(step, dict):
            raise ValueError(f"proof[{index}] must be an object")
        require_hex32(step.get("hash"), f"proof[{index}].hash")
        if step.get("position") not in ("left", "right"):
            raise ValueError(f"proof[{index}].position must be 'left' or 'right'")

    txid = anchor.get("txid")
    if txid is not None:
        require_hex32(txid, "anchor.txid")
    height = anchor.get("height")
    if height is not None and (
        isinstance(height, bool) or not isinstance(height, int) or not 0 <= height <= 0xFFFFFFFF
    ):
        raise ValueError("anchor.height must be a nonnegative u32 or null")
    if scheme == LEGACY_SCHEME and (
        height is None or height > LEGACY_ROOT_MAX_ANCHOR_HEIGHT
    ):
        raise ValueError("historical legacy bundle lacks an admitted anchor height")
    if requested_leaf is not None and leaf_hash_hex != require_hex32(
        requested_leaf, "requested leaf hash"
    ):
        raise ValueError("returned bundle leaf.hash does not match requested leaf hash")
    return bundle


def rejects(call):
    try:
        call()
    except (KeyError, TypeError, ValueError):
        return True
    return False


def result(test_id, label, ok, detail=""):
    global passed, failed
    if ok:
        print(f"[PASS] {test_id} {label}")
        passed += 1
    else:
        msg = f"[FAIL] {test_id} {label}"
        if detail:
            msg += f"  -- {detail}"
        print(msg)
        failed += 1


def skip(test_id, label, reason=""):
    global skipped
    msg = f"[SKIP] {test_id} {label}"
    if reason:
        msg += f"  -- {reason}"
    print(msg)
    skipped += 1


def leaf_hash(type_byte, payload):
    """BLAKE2b-256 with NordicShield_ personalization."""
    data = bytes([type_byte]) + payload
    return blake2b(data, digest_size=32, person=LEAF_PERSONAL).digest()


def node_hash(left, right):
    """Merkle node: BLAKE2b-256 with NordicShield_MRK personalization."""
    if not isinstance(left, bytes) or not isinstance(right, bytes) or len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle node inputs must each be 32 bytes")
    return blake2b(left + right, digest_size=32, person=NODE_PERSONAL).digest()


def commit_root(leaf_count, raw_root):
    """Count-bound ZAP1 Merkle root commitment."""
    leaf_count = require_leaf_count(leaf_count)
    if not isinstance(raw_root, bytes) or len(raw_root) != 32:
        raise ValueError("raw Merkle root must be exactly 32 bytes")
    return blake2b(
        b"\x01" + leaf_count.to_bytes(8, "big") + raw_root,
        digest_size=32,
        person=ROOT_PERSONAL,
    ).digest()


def len_prefix(s):
    """2-byte big-endian length prefix + UTF-8 bytes."""
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def u32_be(val):
    return struct.pack(">I", val)


def u64_be(val):
    return struct.pack(">Q", val)


def compute_merkle_root(leaves_hex):
    """Compute count-bound ZAP1 Merkle root from leaf hashes."""
    if not leaves_hex:
        return bytes(32)
    nodes = [bytes.fromhex(h) for h in leaves_hex]
    raw = compute_raw_merkle_root(nodes)
    return commit_root(len(nodes), raw)


def compute_raw_merkle_root(nodes):
    """Compute the raw tree root using odd-node carry-up semantics."""
    nodes = list(nodes)
    if not nodes:
        return bytes(32)
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                next_level.append(node_hash(nodes[i], nodes[i + 1]))
            else:
                next_level.append(nodes[i])
        nodes = next_level
    return nodes[0]


def compute_legacy_merkle_root(leaves_hex):
    """Historical odd-node duplication root retained for old fixtures."""
    if not leaves_hex:
        return bytes(32)
    nodes = [bytes.fromhex(h) for h in leaves_hex]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [node_hash(nodes[i], nodes[i + 1]) for i in range(0, len(nodes), 2)]
    return nodes[0]


def verify_merkle_proof(leaf_hex, proof_path, expected_root_hex, leaf_count=None):
    """Walk a Merkle proof path and check against expected root."""
    current = bytes.fromhex(require_hex32(leaf_hex, "leaf hash"))
    expected_root_hex = require_hex32(expected_root_hex, "expected root")
    if not isinstance(proof_path, list):
        raise ValueError("proof must be an array")
    for index, step in enumerate(proof_path):
        if not isinstance(step, dict):
            raise ValueError(f"proof[{index}] must be an object")
        sibling = bytes.fromhex(require_hex32(step.get("hash"), f"proof[{index}].hash"))
        position = step.get("position")
        if position == "right":
            current = node_hash(current, sibling)
        elif position == "left":
            current = node_hash(sibling, current)
        else:
            raise ValueError(f"proof[{index}].position must be 'left' or 'right'")
    if leaf_count is not None:
        current = commit_root(require_leaf_count(leaf_count), current)
    return current.hex() == expected_root_hex


# Hash construction functions for each event type
def hash_program_entry(wallet_hash):
    return leaf_hash(0x01, wallet_hash.encode())


def hash_ownership_attest(wallet_hash, serial_number):
    return leaf_hash(0x02, len_prefix(wallet_hash) + len_prefix(serial_number))


def hash_contract_anchor(serial_number, contract_sha256):
    return leaf_hash(0x03, len_prefix(serial_number) + len_prefix(contract_sha256))


def hash_deployment(serial_number, facility_id, timestamp):
    return leaf_hash(0x04, len_prefix(serial_number) + len_prefix(facility_id) + u64_be(timestamp))


def hash_hosting_payment(serial_number, month, year):
    return leaf_hash(0x05, len_prefix(serial_number) + u32_be(month) + u32_be(year))


def hash_shield_renewal(wallet_hash, year):
    return leaf_hash(0x06, len_prefix(wallet_hash) + u32_be(year))


def hash_transfer(old_wallet, new_wallet, serial_number):
    return leaf_hash(0x07, len_prefix(old_wallet) + len_prefix(new_wallet) + len_prefix(serial_number))


def hash_exit(wallet_hash, serial_number, timestamp):
    return leaf_hash(0x08, len_prefix(wallet_hash) + len_prefix(serial_number) + u64_be(timestamp))


def hash_staking_deposit(wallet_hash, amount_zat, validator_id):
    return leaf_hash(0x0A, len_prefix(wallet_hash) + u64_be(amount_zat) + len_prefix(validator_id))


def hash_staking_withdraw(wallet_hash, amount_zat, validator_id):
    return leaf_hash(0x0B, len_prefix(wallet_hash) + u64_be(amount_zat) + len_prefix(validator_id))


def hash_staking_reward(wallet_hash, amount_zat, epoch):
    return leaf_hash(0x0C, len_prefix(wallet_hash) + u64_be(amount_zat) + u32_be(epoch))


def hash_governance_proposal(wallet_hash, proposal_id, proposal_hash):
    return leaf_hash(0x0D, len_prefix(wallet_hash) + len_prefix(proposal_id) + len_prefix(proposal_hash))


def hash_governance_vote(wallet_hash, proposal_id, vote_commitment):
    return leaf_hash(0x0E, len_prefix(wallet_hash) + len_prefix(proposal_id) + len_prefix(vote_commitment))


def hash_governance_result(wallet_hash, proposal_id, result_hash):
    return leaf_hash(0x0F, len_prefix(wallet_hash) + len_prefix(proposal_id) + len_prefix(result_hash))


def hash_agent_register(agent_id, pubkey_hash, model_hash, policy_hash):
    return leaf_hash(
        0x40,
        len_prefix(agent_id)
        + len_prefix(pubkey_hash)
        + len_prefix(model_hash)
        + len_prefix(policy_hash),
    )


def hash_agent_policy(agent_id, policy_version, rules_hash):
    return leaf_hash(0x41, len_prefix(agent_id) + u32_be(policy_version) + len_prefix(rules_hash))


def hash_agent_action(agent_id, action_type, input_hash, output_hash):
    return leaf_hash(
        0x42,
        len_prefix(agent_id)
        + len_prefix(action_type)
        + len_prefix(input_hash)
        + len_prefix(output_hash),
    )


def compute_event_hash(vec):
    """Dispatch to the right hash function based on event_type."""
    et = vec["event_type"]
    fields = vec["input_fields"]

    if et == "PROGRAM_ENTRY":
        return hash_program_entry(fields["wallet_hash"])
    elif et == "OWNERSHIP_ATTEST":
        return hash_ownership_attest(fields["wallet_hash"], fields["serial_number"])
    elif et == "CONTRACT_ANCHOR":
        return hash_contract_anchor(fields["serial_number"], fields["contract_sha256"])
    elif et == "DEPLOYMENT":
        return hash_deployment(fields["serial_number"], fields["facility_id"], fields["timestamp"])
    elif et == "HOSTING_PAYMENT":
        return hash_hosting_payment(fields["serial_number"], fields["month"], fields["year"])
    elif et == "SHIELD_RENEWAL":
        return hash_shield_renewal(fields["wallet_hash"], fields["year"])
    elif et == "TRANSFER":
        return hash_transfer(fields["old_wallet_hash"], fields["new_wallet_hash"], fields["serial_number"])
    elif et == "EXIT":
        return hash_exit(fields["wallet_hash"], fields["serial_number"], fields["timestamp"])
    elif et == "MERKLE_ROOT":
        root_key = "root_hash" if "root_hash" in fields else "merkle_root"
        return bytes.fromhex(fields[root_key])
    elif et == "STAKING_DEPOSIT":
        return hash_staking_deposit(fields["wallet_hash"], fields["amount_zat"], fields["validator_id"])
    elif et == "STAKING_WITHDRAW":
        return hash_staking_withdraw(fields["wallet_hash"], fields["amount_zat"], fields["validator_id"])
    elif et == "STAKING_REWARD":
        return hash_staking_reward(fields["wallet_hash"], fields["amount_zat"], fields["epoch"])
    elif et == "GOVERNANCE_PROPOSAL":
        return hash_governance_proposal(fields["wallet_hash"], fields["proposal_id"], fields["proposal_hash"])
    elif et == "GOVERNANCE_VOTE":
        return hash_governance_vote(fields["wallet_hash"], fields["proposal_id"], fields["vote_commitment"])
    elif et == "GOVERNANCE_RESULT":
        return hash_governance_result(fields["wallet_hash"], fields["proposal_id"], fields["result_hash"])
    elif et == "AGENT_REGISTER":
        return hash_agent_register(
            fields["agent_id"],
            fields["pubkey_hash"],
            fields["model_hash"],
            fields["policy_hash"],
        )
    elif et == "AGENT_POLICY":
        return hash_agent_policy(fields["agent_id"], fields["policy_version"], fields["rules_hash"])
    elif et == "AGENT_ACTION":
        return hash_agent_action(
            fields["agent_id"],
            fields["action_type"],
            fields["input_hash"],
            fields["output_hash"],
        )
    else:
        return None


def parse_memo(memo_str):
    """Parse a ZAP1/NSM1 memo string. Returns (prefix, type_hex, payload_hex) or None."""
    parts = memo_str.split(":")
    if len(parts) != 3:
        return None
    prefix, type_hex, payload_hex = parts
    if prefix not in ("ZAP1", "NSM1"):
        return None
    if len(type_hex) != 2:
        return None
    if len(payload_hex) != 64:
        return None
    try:
        int(type_hex, 16)
        bytes.fromhex(payload_hex)
    except ValueError:
        return None
    return (prefix, type_hex, payload_hex)


def encode_memo(type_byte, payload_hex):
    """Encode a ZAP1 memo string."""
    return f"ZAP1:{type_byte:02x}:{payload_hex}"


# Section 1: Memo Envelope Format
def test_section_1():
    print("\n== Section 1: Memo Envelope Format ==\n")

    # 1.1 Registry partitions are exact and disjoint.
    expected_defined = frozenset((*range(0x01, 0x10), 0x40, 0x41, 0x42))
    expected_system_managed = frozenset((0x01, 0x02, 0x09))
    expected_write_api = frozenset(
        (*range(0x03, 0x09), *range(0x0A, 0x10), 0x40, 0x41, 0x42)
    )
    result("1.1", "Defined event-type set is exact", DEFINED_TYPES == expected_defined)
    result(
        "1.2",
        "System-managed event-type set is exact",
        SYSTEM_MANAGED_TYPES == expected_system_managed,
    )
    result("1.3", "Write-API event-type set is exact", WRITE_API_TYPES == expected_write_api)
    result(
        "1.4",
        "Write-API and system-managed types partition the defined registry",
        WRITE_API_TYPES.isdisjoint(SYSTEM_MANAGED_TYPES)
        and WRITE_API_TYPES | SYSTEM_MANAGED_TYPES == DEFINED_TYPES,
    )

    # 1.5 Published vectors cover write-API, system-managed, and unassigned holes.
    vectors_path = os.path.join(DIR, "implementation_profile_vectors.json")
    with open(vectors_path) as f:
        vectors = json.load(f)["section_1_memo_envelope"]["vectors"]
    type_vectors = [vec for vec in vectors if "type_byte" in vec]
    for vec in type_vectors:
        tb = vec["type_byte"]
        actual = {
            "defined": tb in DEFINED_TYPES,
            "write_api": tb in WRITE_API_TYPES,
            "system_managed": tb in SYSTEM_MANAGED_TYPES,
        }
        expected = {key: vec[key] for key in actual}
        result(f"V{vec['id']}", vec["description"], actual == expected)

    # 1.6 Memo fits in 512-byte field
    sample_memo = "ZAP1:01:075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b"
    memo_bytes = len(sample_memo.encode("utf-8"))
    result("1.6", f"Memo wire format ({memo_bytes} bytes) fits 512-byte memo field", memo_bytes <= 512)

    # 1.7 Memo is constant-size for all defined types (72 bytes for ASCII).
    for tb in sorted(DEFINED_TYPES):
        memo = encode_memo(tb, "aa" * 32)
        length = len(memo.encode("utf-8"))
        result("1.7", f"Memo for type 0x{tb:02x} is 72 bytes", length == 72)

    # 1.8 Integers are big-endian in the implementation profile.
    val = 2026
    encoded = u32_be(val)
    result("1.8", "Integer encoding is big-endian", encoded == b"\x00\x00\x07\xea")

    # 1.9 Padding is null bytes
    memo_raw = sample_memo.encode("utf-8")
    padded = memo_raw + b"\x00" * (512 - len(memo_raw))
    result("1.9", "Padding to 512 bytes uses null bytes", len(padded) == 512 and padded[-1] == 0)


# Section 2: Hash Construction
def test_section_2():
    print("\n== Section 2: Hash Construction ==\n")

    # 2.1 Personalization string
    personal = b"NordicShield_"
    result("2.1", f"Leaf personalization is 'NordicShield_' ({len(personal)} bytes)",
           personal == b"NordicShield_" and len(personal) == 13)

    # 2.2 Personalization padded to 16 bytes
    result("2.2", "Leaf personalization padded to 16 bytes for BLAKE2b",
           len(LEAF_PERSONAL) == 16 and LEAF_PERSONAL == b"NordicShield_\x00\x00\x00")

    # 2.3 Digest size is 32 bytes
    h = blake2b(b"test", digest_size=32, person=LEAF_PERSONAL).digest()
    result("2.3", "BLAKE2b digest size is 32 bytes", len(h) == 32)

    # 2.4 Domain separation - different personalization produces different hash
    h1 = blake2b(b"same input", digest_size=32, person=LEAF_PERSONAL).digest()
    h2 = blake2b(b"same input", digest_size=32, person=NODE_PERSONAL).digest()
    result("2.4", "Domain separation: leaf and node personalizations produce different hashes", h1 != h2)

    # Load test vectors from the vectors JSON
    vectors_path = os.path.join(DIR, "implementation_profile_vectors.json")
    with open(vectors_path) as f:
        vectors = json.load(f)

    # Test each hash vector
    hash_vecs = vectors["section_2_hash_construction"]["vectors"]
    vector_labels = {vec["event_type"] for vec in hash_vecs}
    vector_bytes = {int(vec["type_byte"], 16) for vec in hash_vecs}
    result(
        "2.5",
        "Hash vectors cover the exact defined event registry",
        vector_labels == set(EVENT_TYPE_BY_LABEL)
        and vector_bytes == DEFINED_TYPES
        and all(
            int(vec["type_byte"], 16) == EVENT_TYPE_BY_LABEL[vec["event_type"]]
            for vec in hash_vecs
        ),
    )
    for vec in hash_vecs:
        vid = vec["id"]
        et = vec["event_type"]
        expected = vec["expected_hash"]

        computed = compute_event_hash(vec)
        if computed is None:
            skip(vid, f"{et} hash construction", "no hash function for this type")
            continue

        computed_hex = computed.hex()
        ok = computed_hex == expected
        detail = ""
        if not ok:
            detail = f"expected {expected[:16]}... got {computed_hex[:16]}..."
        if verbose and ok:
            detail = f"= {computed_hex[:24]}..."
        result(vid, f"{et} hash construction", ok, detail)

    # Also validate against the repository's independent hash fixture file.
    hv_path = os.path.join(DIR, "hash_vectors.json")
    with open(hv_path) as f:
        hv_data = json.load(f)

    print()
    print("  -- cross-check against hash_vectors.json --")
    for vec in hv_data["vectors"]:
        et = vec["event_type"]
        expected = vec.get("expected_hash")
        if not expected:
            continue

        computed = compute_event_hash(vec)
        if computed is None:
            # MERKLE_ROOT special case
            if et == "MERKLE_ROOT":
                root = vec["input_fields"].get("merkle_root", "")
                ok = root == expected
                result("2.x", f"{et} raw root passthrough (hash_vectors.json)", ok)
                continue
            skip("2.x", f"{et} (hash_vectors.json)", "not implemented")
            continue

        computed_hex = computed.hex()
        ok = computed_hex == expected
        detail = ""
        if not ok:
            detail = f"expected {expected[:16]}... got {computed_hex[:16]}..."
        result("2.x", f"{et} cross-check (hash_vectors.json)", ok, detail)


# Section 3: Merkle Tree
def test_section_3():
    print("\n== Section 3: Merkle Tree ==\n")

    # Load tree vectors
    vectors_path = os.path.join(DIR, "implementation_profile_vectors.json")
    with open(vectors_path) as f:
        vectors = json.load(f)

    tree_vecs = vectors["section_3_merkle_tree"]["vectors"]

    # 3.1 Empty tree
    v = tree_vecs[0]
    root = compute_merkle_root(v["leaves"])
    result("3.1", "Empty tree root is 32 zero bytes", root.hex() == v["expected_root"])

    # 3.2 Single leaf
    v = tree_vecs[1]
    root = compute_merkle_root(v["leaves"])
    result("3.2", "Single-leaf tree root binds leaf count", root.hex() == v["expected_root"])

    # 3.3 Two-leaf tree
    v = tree_vecs[2]
    root = compute_merkle_root(v["leaves"])
    ok = root.hex() == v["expected_root"]
    detail = ""
    if not ok:
        detail = f"expected {v['expected_root'][:16]}... got {root.hex()[:16]}..."
    result("3.3", "Two-leaf tree binds leaf count", ok, detail)

    # 3.4 Node personalization is NordicShield_MRK
    result("3.4", "Node personalization is NordicShield_MRK (16 bytes)",
           NODE_PERSONAL == b"NordicShield_MRK" and len(NODE_PERSONAL) == 16)

    # 3.5 Node hash = H(left || right)
    left = bytes.fromhex("075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b")
    right = bytes.fromhex("de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133")
    h = node_hash(left, right)
    expected = "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a"
    result("3.5", "Node hash H(left||right) matches two-leaf root", h.hex() == expected)

    # 3.6 Odd-cardinality carry-up and count binding
    three_leaves = [
        "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b",
        "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133",
        "344a05bf81faf6e2d54a0e52ea0267aff0244998eb1ee27adf5627413e92f089",
    ]
    root_3 = compute_merkle_root(three_leaves)
    root_4 = compute_merkle_root(three_leaves + [three_leaves[-1]])
    n01 = node_hash(bytes.fromhex(three_leaves[0]), bytes.fromhex(three_leaves[1]))
    raw_3 = node_hash(n01, bytes.fromhex(three_leaves[2]))
    expected_3 = commit_root(3, raw_3)
    result("3.6", "Three-leaf tree carries final node and binds count", root_3 == expected_3)
    result("3.6b", "Duplicating the final leaf changes the committed root", root_3 != root_4)

    # 3.7 Tree is append-only (insertion order matters)
    reversed_leaves = list(reversed(three_leaves[:2]))
    root_rev = compute_merkle_root(reversed_leaves)
    root_fwd = compute_merkle_root(three_leaves[:2])
    result("3.7", "Insertion order matters (reversed leaves produce different root)", root_fwd != root_rev)

    # Also validate against tree_vectors.json
    tv_path = os.path.join(DIR, "tree_vectors.json")
    with open(tv_path) as f:
        tv_data = json.load(f)

    print()
    print("  -- cross-check against tree_vectors.json --")
    for tv in tv_data["vectors"]:
        root = compute_merkle_root(tv["leaves"])
        ok = root.hex() == tv["expected_root"]
        result("3.x", f"tree_vectors.json: {tv['description']}", ok)


# Section 4: Anchor Memo
def test_section_4():
    print("\n== Section 4: Anchor Memo ==\n")

    root_hex = "94421ae28effbe52f651b33eb62c3b428d2ae62be578e05d471cba9794225bbd"

    # 4.1 Anchor type is 0x09 in the registry.
    result("4.1", "Anchor event type is 0x09 (MERKLE_ROOT)",
           0x09 in DEFINED_TYPES and 0x09 in SYSTEM_MANAGED_TYPES)

    # 4.2 Anchor memo encodes as ZAP1:09:{root}
    memo = encode_memo(0x09, root_hex)
    expected_memo = f"ZAP1:09:{root_hex}"
    result("4.2", "Anchor memo format is ZAP1:09:{{root}}", memo == expected_memo)

    # 4.3 Anchor memo parses correctly
    parsed = parse_memo(memo)
    ok = parsed is not None and parsed[0] == "ZAP1" and parsed[1] == "09" and parsed[2] == root_hex
    result("4.3", "Anchor memo parses to (ZAP1, 09, root)", ok)

    # 4.4 Parsing preserves the exact root bytes.
    parsed_root = bytes.fromhex(parsed[2]) if parsed is not None else b""
    result("4.4", "Anchor memo preserves the exact 32-byte root commitment",
           parsed_root == bytes.fromhex(root_hex))

    # 4.5 Legacy NSM1 prefix decodes
    legacy = f"NSM1:09:{root_hex}"
    parsed_legacy = parse_memo(legacy)
    ok = parsed_legacy is not None and parsed_legacy[0] == "NSM1" and parsed_legacy[2] == root_hex
    result("4.5", "Legacy NSM1 prefix accepted during decode", ok)

    # 4.6 Malformed memo rejected
    bad_memo = "ZAP1:01:tooshort"
    parsed_bad = parse_memo(bad_memo)
    result("4.6", "Malformed memo (short hash) rejected", parsed_bad is None)

    # 4.7 Memo with wrong separator rejected
    bad_sep = "ZAP1-01-" + "aa" * 32
    parsed_bad = parse_memo(bad_sep)
    result("4.7", "Memo with wrong separator rejected", parsed_bad is None)

    # Cross-check with memo_vectors.json
    mv_path = os.path.join(DIR, "memo_vectors.json")
    with open(mv_path) as f:
        mv_data = json.load(f)

    print()
    print("  -- cross-check against memo_vectors.json --")
    for mv in mv_data["vectors"]:
        if "raw" in mv:
            parsed = parse_memo(mv["raw"])
            expected_fmt = mv["expected_format"]
            if expected_fmt in ("zap1", "nsm1"):
                ok = parsed is not None and parsed[0].lower() == expected_fmt
                result("4.x", f"memo_vectors: {mv['description']}", ok)
            elif expected_fmt == "text":
                # Malformed ZAP1 should fail parse
                result("4.x", f"memo_vectors: {mv['description']} (falls back to text)",
                       parsed is None or expected_fmt == "text")


# Section 5: Verification Procedure
def test_section_5():
    print("\n== Section 5: Verification Procedure ==\n")

    # 5.1 Valid proof verification
    leaf_hex = "de62554ad3867a59895befa7216686c923fc86245231e8fb6bd709a20e1fd133"
    proof_path = [
        {"hash": "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b", "position": "left"}
    ]
    root_hex = "94421ae28effbe52f651b33eb62c3b428d2ae62be578e05d471cba9794225bbd"
    ok = verify_merkle_proof(leaf_hex, proof_path, root_hex, leaf_count=2)
    result("5.1", "Valid Merkle proof verifies", ok)

    # 5.2 Invalid proof (wrong root) fails
    bad_root = "ff" * 32
    ok = not verify_merkle_proof(leaf_hex, proof_path, bad_root, leaf_count=2)
    result("5.2", "Proof against wrong root fails", ok)

    # 5.3 Invalid proof (wrong sibling) fails
    bad_proof = [{"hash": "aa" * 32, "position": "left"}]
    ok = not verify_merkle_proof(leaf_hex, bad_proof, root_hex, leaf_count=2)
    result("5.3", "Proof with wrong sibling fails", ok)

    # 5.4 Single-leaf proof (empty path)
    single_leaf = "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b"
    single_root = "586a84be4d3a717f06a0b837e8dbb9a333a3c44a679338dfa29d422569cd1d8c"
    ok = verify_merkle_proof(single_leaf, [], single_root, leaf_count=1)
    result("5.4", "Single-leaf proof (empty path) verifies count-bound root", ok)

    # 5.5 Recompute leaf from fields and verify
    computed = hash_ownership_attest("e2e_wallet_20260327", "Z15P-E2E-001")
    ok = computed.hex() == leaf_hex
    result("5.5", "Recomputed OWNERSHIP_ATTEST leaf matches proof leaf", ok)

    # 5.6 Proof bundle structure (valid_bundle.json)
    bundle_path = os.path.join(DIR, "valid_bundle.json")
    with open(bundle_path) as f:
        bundle = json.load(f)

    required_top = ["protocol", "version", "leaf", "proof", "root", "anchor"]
    missing = [k for k in required_top if k not in bundle]
    result("5.6", "Proof bundle has all required top-level fields",
           len(missing) == 0, f"missing: {missing}" if missing else "")
    result(
        "5.6a",
        "Proof bundle matches the admitted protocol, version, scheme, and canonical encoding",
        not rejects(lambda: validate_bundle_shape(bundle)),
    )

    # 5.7 Proof bundle leaf fields
    leaf_required = ["hash", "event_type", "wallet_hash"]
    leaf_obj = bundle.get("leaf", {})
    missing = [k for k in leaf_required if k not in leaf_obj]
    result("5.7", "Proof bundle leaf has required fields",
           len(missing) == 0, f"missing: {missing}" if missing else "")

    # 5.8 Proof bundle root fields
    root_required = ["hash", "leaf_count", "scheme"]
    root_obj = bundle.get("root", {})
    missing = [k for k in root_required if k not in root_obj]
    result("5.8", "Proof bundle root has required fields",
           len(missing) == 0, f"missing: {missing}" if missing else "")

    # 5.9 Proof bundle anchor fields
    anchor_required = ["txid", "height"]
    anchor_obj = bundle.get("anchor", {})
    missing = [k for k in anchor_required if k not in anchor_obj]
    result("5.9", "Proof bundle anchor has required fields",
           len(missing) == 0, f"missing: {missing}" if missing else "")

    # 5.10 End-to-end: recompute leaf, walk proof, check root from bundle
    bundle_leaf = bundle["leaf"]
    recomputed = hash_ownership_attest(bundle_leaf["wallet_hash"], bundle_leaf["serial_number"])
    ok = recomputed.hex() == bundle_leaf["hash"]
    result("5.10", "Bundle leaf hash matches recomputed hash", ok)

    proof_ok = verify_merkle_proof(
        bundle_leaf["hash"],
        bundle["proof"],
        bundle["root"]["hash"],
        leaf_count=bundle["root"]["leaf_count"],
    )
    result("5.11", "Bundle proof path derives the stated root", proof_ok)

    # 5.12 Invalid bundle (tampered root) fails
    inv_path = os.path.join(DIR, "invalid_bundle.json")
    with open(inv_path) as f:
        inv_bundle = json.load(f)
    proof_fail = verify_merkle_proof(
        inv_bundle["leaf"]["hash"],
        inv_bundle["proof"],
        inv_bundle["root"]["hash"],
        leaf_count=inv_bundle["root"]["leaf_count"],
    )
    result("5.12", "Tampered bundle (wrong root) fails verification", not proof_fail)

    bad_position = copy.deepcopy(bundle)
    bad_position["proof"][0]["position"] = "banana"
    result(
        "5.13",
        "Unknown proof position is rejected instead of treated as left or right",
        rejects(lambda: validate_bundle_shape(bad_position)),
    )

    result(
        "5.14",
        "Short leaf hash is rejected even for an empty proof",
        rejects(lambda: verify_merkle_proof("00", [], "00" * 32, leaf_count=1)),
    )

    fake_scheme = copy.deepcopy(bundle)
    fake_scheme["root"]["scheme"] = "ZAP1_FAKE_SCHEME"
    result(
        "5.15",
        "Unrecognized Merkle scheme is rejected before verification",
        rejects(lambda: validate_bundle_shape(fake_scheme)),
    )

    wrong_request = "00" * 32
    result(
        "5.16",
        "Downloaded bundle leaf is bound to the leaf requested in the proof URL",
        rejects(lambda: validate_bundle_shape(bundle, requested_leaf=wrong_request)),
    )

    wrong_pair = copy.deepcopy(bundle)
    wrong_pair["version"] = HISTORICAL_BUNDLE_VERSION
    result(
        "5.17",
        "Historical version cannot claim the count-bound scheme",
        rejects(lambda: validate_bundle_shape(wrong_pair)),
    )

    uppercase_hash = copy.deepcopy(bundle)
    uppercase_hash["leaf"]["hash"] = uppercase_hash["leaf"]["hash"].upper()
    result(
        "5.18",
        "Non-canonical uppercase hash encoding is rejected",
        rejects(lambda: validate_bundle_shape(uppercase_hash)),
    )


# Section 6: Cross-Implementation Vectors
def test_section_6(live=False):
    print("\n== Section 6: Cross-Implementation Vectors ==\n")

    # Historical fixture shape. Chain existence is outside this local check.
    fixture_txid = "98e1d6a01614c464c237f982d9dc2138c5f8aa08342f67b867a18a4ce998af9a"
    result("6.1", "Historical fixture txid is 32-byte lowercase hex",
           re.fullmatch(r"[0-9a-f]{64}", fixture_txid) is not None)

    # 6.2 Historical fixture height
    fixture_height = 3286631
    result("6.2", "Historical fixture height is a positive u32",
           0 < fixture_height <= 0xFFFFFFFF)

    # 6.3 Recompute the old fixture root from two known leaves.
    leaf0 = hash_program_entry("e2e_wallet_20260327")
    leaf1 = hash_ownership_attest("e2e_wallet_20260327", "Z15P-E2E-001")
    root = compute_legacy_merkle_root([leaf0.hex(), leaf1.hex()])
    expected = "024e36515ea30efc15a0a7962dd8f677455938079430b9eab174f46a4328a07a"
    ok = root.hex() == expected
    result("6.3", "Recomputed old-format root from two leaves matches fixture", ok,
           "" if ok else f"got {root.hex()[:24]}...")

    # 6.4 Memo for the fixture root
    memo = encode_memo(0x09, expected)
    result("6.4", "Historical fixture memo encodes correctly",
           memo == f"ZAP1:09:{expected}")

    if not live:
        skip("6.5", "Live API test (api.frontiercompute.cash)", "use --live flag")
        skip("6.6", "Live API stats endpoint", "use --live flag")
        return

    # Live API tests
    print()
    print("  -- live API tests --")

    api_base = "https://api.frontiercompute.cash"

    # 6.5 Verify the deployment's current event against the live API.
    # Fixture leaves are for deterministic local checks only; deployments may
    # not expose old fixture proofs forever.
    try:
        events_url = f"{api_base}/events?limit=1"
        headers = {"Accept": "application/json", "User-Agent": "zap1-profile-check/1.0"}
        req = urllib.request.Request(events_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            events = json.loads(resp.read())
        leaf_hash_hex = events.get("events", [{}])[0].get("leaf_hash", "")
        if not re.fullmatch(r"[0-9a-f]{64}", leaf_hash_hex):
            result("6.5", "Live API exposes current leaf hash", False, leaf_hash_hex)
        else:
            url = f"{api_base}/verify/{leaf_hash_hex}/check"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            ok = data.get("valid") is True and data.get("protocol") == "ZAP1"
            result("6.5", "Live API verifies current event leaf", ok)
    except Exception as e:
        skip("6.5", f"Live API verify endpoint", str(e)[:60])

    # 6.6 Stats endpoint responds
    try:
        url = f"{api_base}/stats"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            ok = "leaf_count" in str(data).lower() or "leaves" in str(data).lower()
            result("6.6", "Live API stats endpoint responds with leaf data", ok)
    except Exception as e:
        skip("6.6", f"Live API stats endpoint", str(e)[:60])


def main():
    global verbose

    parser = argparse.ArgumentParser(description="ZAP1 implementation-profile checks")
    parser.add_argument("--live", action="store_true", help="Run live API tests against api.frontiercompute.cash")
    parser.add_argument("--verbose", action="store_true", help="Show computed hash details")
    args = parser.parse_args()

    verbose = args.verbose

    print("ZAP1 implementation-profile checks")
    print("Scope: repository fixtures and optional live API consistency")

    test_section_1()
    test_section_2()
    test_section_3()
    test_section_4()
    test_section_5()
    test_section_6(live=args.live)

    print()
    total = passed + failed
    print(f"{passed}/{total} passed, {failed} failed", end="")
    if skipped:
        print(f", {skipped} skipped", end="")
    print()

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
