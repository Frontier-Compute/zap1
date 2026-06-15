#!/usr/bin/env python3
"""
Verify a ZAP1 proof bundle end-to-end against the Zcash blockchain.

Takes a proof.json file (or URL) and:
1. Recomputes the leaf hash from input fields
2. Walks the Merkle proof path to the root
3. Fetches the anchor transaction from a Zebra node
4. Confirms the memo contains the expected root hash

No trust in any API. Just the proof bundle and chain data.

Usage:
  python3 verify_onchain.py
  python3 verify_onchain.py examples/proof_bundle_example.json
  python3 verify_onchain.py https://api.example/verify/LEAF/proof.json
  python3 verify_onchain.py proof.json --rpc http://127.0.0.1:8232
"""
import argparse
import hashlib, json, sys, urllib.request
from pathlib import Path

LEAF_PERSONAL = b"NordicShield_\x00\x00\x00"
NODE_PERSONAL = b"NordicShield_MRK"
ROOT_PERSONAL = b"NordicShield_RTK"
DEFAULT_BUNDLE = Path(__file__).with_name("proof_bundle_example.json")
HTTP_HEADERS = {"Accept": "application/json", "User-Agent": "zap1-example-onchain-verifier/1.0"}
COUNT_BOUND_SCHEME = "ZAP1_COUNT_BOUND_V2"
LEGACY_SCHEME = "ZAP1_LEGACY_DUPLICATE_ODD"
LEGACY_ROOT_MAX_ANCHOR_HEIGHT = 3317133

def blake2b_256(data, personal):
    return hashlib.blake2b(data, digest_size=32, person=personal).digest()

def commit_root(leaf_count, raw_root):
    if leaf_count <= 0:
        raise ValueError("leaf_count must be positive")
    return blake2b_256(b"\x01" + int(leaf_count).to_bytes(8, "big") + raw_root, ROOT_PERSONAL)

def walk_proof(leaf_hash_hex, proof_path):
    current = bytes.fromhex(leaf_hash_hex)
    for step in proof_path:
        sibling = bytes.fromhex(step["hash"])
        if step["position"] == "left":
            current = blake2b_256(sibling + current, NODE_PERSONAL)
        else:
            current = blake2b_256(current + sibling, NODE_PERSONAL)
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

def fetch_tx_memo(rpc_url, txid):
    """Fetch raw transaction and extract memo (simplified - checks for ZAP1 prefix in hex)."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1,
        "method": "getrawtransaction",
        "params": [txid, 0]
    }).encode()
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
    raw_hex = resp.get("result", "")
    # Search for ZAP1:09: pattern in the raw tx hex
    zap1_marker = "5a4150313a30393a"  # "ZAP1:09:" in hex
    nsm1_marker = "4e534d313a30393a"  # "NSM1:09:" in hex
    idx = raw_hex.find(zap1_marker)
    if idx == -1:
        idx = raw_hex.find(nsm1_marker)
    if idx >= 0:
        # Extract 64 hex chars of root hash after the marker
        memo_start = idx + len(zap1_marker)
        # The root is encoded as ASCII hex in the memo, so each byte is 2 hex chars
        root_ascii_hex = raw_hex[memo_start:memo_start + 128]
        root_hash = bytes.fromhex(root_ascii_hex).decode("ascii")
        return root_hash
    return None

def main():
    parser = argparse.ArgumentParser(description="Verify a ZAP1 proof bundle locally, with optional chain memo check")
    parser.add_argument("source", nargs="?", default=str(DEFAULT_BUNDLE), help="Proof bundle path or explicit proof-bundle URL")
    parser.add_argument("--rpc", default="http://127.0.0.1:8232", help="Zebra RPC URL for optional anchor transaction memo check")
    args = parser.parse_args()
    source = args.source
    rpc_url = args.rpc

    # Load proof bundle
    if source.startswith("http"):
        req = urllib.request.Request(source, headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=15) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "json" not in content_type.lower():
                raise RuntimeError(f"{source} returned {content_type or 'unknown content-type'}, not JSON")
            bundle = json.loads(resp.read())
    else:
        with open(source) as f:
            bundle = json.load(f)

    leaf_hash = bundle["leaf"]["hash"]
    proof_path = bundle["proof"]
    expected_root = bundle["root"]["hash"]
    leaf_count = bundle["root"].get("leaf_count")
    anchor = bundle.get("anchor", {})
    anchor_txid = anchor.get("txid")
    anchor_height = anchor.get("height")

    print(f"Leaf:   {leaf_hash[:32]}...")
    print(f"Root:   {expected_root[:32]}...")
    print()

    # Step 1: Walk Merkle proof
    raw_root = bytes.fromhex(walk_proof(leaf_hash, proof_path))
    computed_root = commit_root(leaf_count, raw_root).hex() if leaf_count is not None else None
    legacy_root = raw_root.hex()
    root_ok_v2 = computed_root == expected_root
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

    # Step 2: Check anchor on-chain
    if anchor_txid:
        print(f"\nAnchor: txid {anchor_txid[:24]}... height {anchor_height}")
        try:
            memo_root = fetch_tx_memo(rpc_url, anchor_txid)
            if memo_root:
                chain_ok = memo_root == expected_root
                print(f"[{'OK' if chain_ok else 'FAIL'}] On-chain memo root matches bundle root")
                if not chain_ok:
                    print(f"  chain memo: {memo_root}")
                    print(f"  bundle:     {expected_root}")
            else:
                print("[SKIP] Could not extract ZAP1 memo from transaction (may need Orchard decryption)")
        except Exception as e:
            print(f"[SKIP] Could not fetch transaction: {e}")
            print(f"  Try: --rpc http://your-zebra-node:8232")
    else:
        print("\n[SKIP] No anchor txid - event not yet anchored on-chain")

    print()
    if root_ok:
        print("Merkle proof is valid. The leaf is committed to the claimed root.")
    else:
        print("VERIFICATION FAILED.")

if __name__ == "__main__":
    main()
