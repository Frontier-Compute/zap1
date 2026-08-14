#!/usr/bin/env python3
"""
Verify a ZAP1 proof bundle and check the referenced transaction exists.

Takes a proof.json file (or URL) and:
1. Treats the supplied leaf hash as input
2. Walks the Merkle proof path to the supplied root
3. Fetches the referenced transaction from a Zebra node
4. Confirms the referenced transaction exists when an RPC is available

It does not recompute a typed leaf from disclosed preimages. It therefore does
not authenticate the bundle's event-type label. Use a separate disclosure
bundle and the matching typed witness verifier for that layer.

Normal Orchard memo plaintext is encrypted and is not present in raw
transaction hex. This command deliberately does not scan raw hex for plaintext.
Without a safe disclosure/opening artifact it exits incomplete rather than
treating transaction existence as root-to-memo proof.

Usage:
  python3 verify_onchain.py
  python3 verify_onchain.py examples/proof_bundle_example.json
  python3 verify_onchain.py https://api.example/verify/LEAF/proof.json
  python3 verify_onchain.py proof.json --rpc http://127.0.0.1:8232
"""
import argparse
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

LEAF_PERSONAL = b"NordicShield_\x00\x00\x00"
NODE_PERSONAL = b"NordicShield_MRK"
ROOT_PERSONAL = b"NordicShield_RTK"
DEFAULT_BUNDLE = Path(__file__).with_name("proof_bundle_example.json")
HTTP_HEADERS = {"Accept": "application/json", "User-Agent": "zap1-example-onchain-verifier/1.0"}
COUNT_BOUND_SCHEME = "ZAP1_COUNT_BOUND_V2"
LEGACY_SCHEME = "ZAP1_LEGACY_DUPLICATE_ODD"
LEGACY_ROOT_MAX_ANCHOR_HEIGHT = 3317133
CURRENT_BUNDLE_VERSION = "2"
HISTORICAL_BUNDLE_VERSION = "1.0.0"
MAX_U64 = (1 << 64) - 1
HEX32_RE = re.compile(r"[0-9a-f]{64}\Z")


def require_hex32(value, label):
    if not isinstance(value, str) or HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be exactly 32-byte lowercase hex")
    return value


def require_leaf_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_U64:
        raise ValueError("root.leaf_count must be an integer from 1 through 2^64-1")
    return value


def requested_leaf_from_source(source):
    if not source.startswith(("http://", "https://")):
        return None
    path = urllib.parse.urlparse(source).path
    match = re.search(r"/verify/([0-9A-Fa-f]{64})/proof\.json\Z", path)
    if match:
        return require_hex32(match.group(1), "requested leaf hash")
    return None


def validate_bundle(bundle, requested_leaf=None):
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

    leaf_hash = require_hex32(leaf.get("hash"), "leaf.hash")
    root_hash = require_hex32(root.get("hash"), "root.hash")
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
    height = anchor.get("height")
    if height is not None and (
        isinstance(height, bool) or not isinstance(height, int) or not 0 <= height <= 0xFFFFFFFF
    ):
        raise ValueError("anchor.height must be a nonnegative u32 or null")
    if scheme == LEGACY_SCHEME and (
        height is None or height > LEGACY_ROOT_MAX_ANCHOR_HEIGHT
    ):
        raise ValueError("historical legacy bundle lacks an admitted anchor height")
    if requested_leaf is not None and leaf_hash != requested_leaf:
        raise ValueError("returned bundle leaf.hash does not match the requested leaf hash")
    return leaf_hash, proof, root_hash, leaf_count, scheme, anchor

def blake2b_256(data, personal):
    return hashlib.blake2b(data, digest_size=32, person=personal).digest()

def commit_root(leaf_count, raw_root):
    leaf_count = require_leaf_count(leaf_count)
    if len(raw_root) != 32:
        raise ValueError("raw Merkle root must be 32 bytes")
    return blake2b_256(b"\x01" + leaf_count.to_bytes(8, "big") + raw_root, ROOT_PERSONAL)

def walk_proof(leaf_hash_hex, proof_path):
    current = bytes.fromhex(require_hex32(leaf_hash_hex, "leaf.hash"))
    if not isinstance(proof_path, list):
        raise ValueError("proof must be an array")
    for index, step in enumerate(proof_path):
        if not isinstance(step, dict):
            raise ValueError(f"proof[{index}] must be an object")
        sibling = bytes.fromhex(require_hex32(step.get("hash"), f"proof[{index}].hash"))
        position = step.get("position")
        if position == "left":
            current = blake2b_256(sibling + current, NODE_PERSONAL)
        elif position == "right":
            current = blake2b_256(current + sibling, NODE_PERSONAL)
        else:
            raise ValueError(f"proof[{index}].position must be 'left' or 'right'")
    return current.hex()

def historical_legacy_allowed(bundle):
    root = bundle.get("root", {})
    anchor = bundle.get("anchor", {})
    scheme = root.get("scheme")
    height = anchor.get("height")
    return (
        scheme == LEGACY_SCHEME
        and height is not None
        and int(height) <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT
    )

def fetch_tx_exists(rpc_url, txid):
    """Return True when the RPC returns the referenced transaction."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "getrawtransaction",
        "params": [txid, 0]
    }).encode()
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
    return bool(resp.get("result"))

def main():
    parser = argparse.ArgumentParser(
        description="Verify a ZAP1 proof bundle locally and check transaction existence"
    )
    parser.add_argument("source", nargs="?", default=str(DEFAULT_BUNDLE), help="Proof bundle path or explicit proof-bundle URL")
    parser.add_argument("--rpc", default="http://127.0.0.1:8232", help="Zebra RPC URL for optional transaction-existence check")
    args = parser.parse_args()
    source = args.source
    rpc_url = args.rpc

    try:
        requested_leaf = requested_leaf_from_source(source)
        if source.startswith(("http://", "https://")):
            req = urllib.request.Request(source, headers=HTTP_HEADERS)
            with urllib.request.urlopen(req, timeout=15) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "json" not in content_type.lower():
                    raise RuntimeError(f"{source} returned {content_type or 'unknown content-type'}, not JSON")
                bundle = json.loads(resp.read())
        else:
            with open(source) as f:
                bundle = json.load(f)

        leaf_hash, proof_path, expected_root, leaf_count, scheme, anchor = validate_bundle(
            bundle, requested_leaf
        )
        raw_root = bytes.fromhex(walk_proof(leaf_hash, proof_path))
        computed_root = commit_root(leaf_count, raw_root).hex()
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    anchor_txid = anchor.get("txid")
    anchor_height = anchor.get("height")

    print(f"Leaf:   {leaf_hash[:32]}...")
    print(f"Root:   {expected_root[:32]}...")
    print()

    # Step 1: Walk Merkle proof
    legacy_root = raw_root.hex()
    root_ok_v2 = scheme == COUNT_BOUND_SCHEME and computed_root == expected_root
    root_ok_legacy = legacy_root == expected_root
    legacy_ok = root_ok_legacy and historical_legacy_allowed(bundle)
    root_ok = root_ok_v2 or legacy_ok
    if root_ok_v2:
        print("[OK] Merkle proof: computed count-bound v2 root matches bundle root")
    elif root_ok_legacy:
        if legacy_ok:
            print("[OK] Merkle proof: computed explicitly historical legacy raw root matches bundle root")
            print(f"[WARN] Legacy root accepted only because anchor height <= {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}")
        else:
            print("[FAIL] Merkle proof: bundle root is only a legacy raw root")
            print(
                f"  legacy requires root.scheme={LEGACY_SCHEME!r} "
                f"and anchor.height <= {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}"
            )
    else:
        print("[FAIL] Merkle proof: computed root does not match bundle root")
    if not root_ok:
        print(f"  computed_v2: {computed_root or 'unavailable'}")
        print(f"  computed_legacy: {legacy_root}")
        print(f"  expected: {expected_root}")

    # Step 2: Check transaction existence. This is intentionally incomplete:
    # a transaction ID does not expose encrypted Orchard memo plaintext.
    if anchor_txid:
        print(f"\nAnchor: txid {anchor_txid[:24]}... height {anchor_height}")
        try:
            if fetch_tx_exists(rpc_url, anchor_txid):
                print("[OK] Referenced transaction exists")
                print("[INCOMPLETE] Encrypted Orchard memo was not opened")
                print("  A safe note-specific disclosure artifact is required")
            else:
                print("[INCOMPLETE] RPC did not return the referenced transaction")
        except Exception as e:
            print(f"[INCOMPLETE] Could not fetch the transaction: {e}")
            print(f"  Try: --rpc http://your-zebra-node:8232")
    else:
        print("\n[INCOMPLETE] No recorded transaction reference for this root")

    print()
    if not root_ok:
        print("VERIFICATION FAILED.")
        return 1
    print("MERKLE PROOF VALID, ON-CHAIN BINDING NOT VERIFIED.")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
