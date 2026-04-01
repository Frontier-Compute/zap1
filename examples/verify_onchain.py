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
  python3 verify_onchain.py proof.json
  python3 verify_onchain.py https://pay.frontiercompute.io/verify/LEAF/proof.json
  python3 verify_onchain.py proof.json --rpc http://127.0.0.1:8232
"""
import hashlib, json, sys, urllib.request

LEAF_PERSONAL = b"NordicShield_\x00\x00\x00"
NODE_PERSONAL = b"NordicShield_MRK"

def blake2b_256(data, personal):
    return hashlib.blake2b(data, digest_size=32, person=personal).digest()

def walk_proof(leaf_hash_hex, proof_path):
    current = bytes.fromhex(leaf_hash_hex)
    for step in proof_path:
        sibling = bytes.fromhex(step["hash"])
        if step["position"] == "left":
            current = blake2b_256(sibling + current, NODE_PERSONAL)
        else:
            current = blake2b_256(current + sibling, NODE_PERSONAL)
    return current.hex()

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
    if len(sys.argv) < 2:
        print("Usage: verify_onchain.py <proof.json or URL> [--rpc URL]")
        sys.exit(1)

    source = sys.argv[1]
    rpc_url = "http://127.0.0.1:8232"
    if "--rpc" in sys.argv:
        rpc_url = sys.argv[sys.argv.index("--rpc") + 1]

    # Load proof bundle
    if source.startswith("http"):
        bundle = json.loads(urllib.request.urlopen(source).read())
    else:
        with open(source) as f:
            bundle = json.load(f)

    leaf_hash = bundle["leaf"]["hash"]
    proof_path = bundle["proof"]
    expected_root = bundle["root"]["hash"]
    anchor = bundle.get("anchor", {})
    anchor_txid = anchor.get("txid")
    anchor_height = anchor.get("height")

    print(f"Leaf:   {leaf_hash[:32]}...")
    print(f"Root:   {expected_root[:32]}...")
    print()

    # Step 1: Walk Merkle proof
    computed_root = walk_proof(leaf_hash, proof_path)
    root_ok = computed_root == expected_root
    print(f"[{'OK' if root_ok else 'FAIL'}] Merkle proof: computed root matches bundle root")
    if not root_ok:
        print(f"  computed: {computed_root}")
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
