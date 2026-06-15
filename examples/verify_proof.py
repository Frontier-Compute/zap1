#!/usr/bin/env python3
"""
Verify a ZAP1 proof bundle without trusting a live server.

Default reviewer path:
  python3 examples/verify_proof.py

Optional inputs:
  python3 examples/verify_proof.py examples/live_ownership_attest_proof.json
  python3 examples/verify_proof.py <leaf_hash> --api-base https://api.frontiercompute.cash

The default path is offline-first. A live API is only used when the input is a
leaf hash or an explicit URL.
"""

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

LEAF_PERSONAL = b"NordicShield_\x00\x00\x00"
NODE_PERSONAL = b"NordicShield_MRK"
ROOT_PERSONAL = b"NordicShield_RTK"
DEFAULT_API = "https://api.frontiercompute.cash"
DEFAULT_BUNDLE = Path(__file__).with_name("proof_bundle_example.json")
HTTP_HEADERS = {"Accept": "application/json", "User-Agent": "zap1-example-verifier/1.0"}
COUNT_BOUND_SCHEME = "ZAP1_COUNT_BOUND_V2"
LEGACY_SCHEME = "ZAP1_LEGACY_DUPLICATE_ODD"
LEGACY_ROOT_MAX_ANCHOR_HEIGHT = 3317133


def blake2b_256(data: bytes, personal: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32, person=personal).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    return blake2b_256(left + right, NODE_PERSONAL)


def commit_root(leaf_count: int, raw_root: bytes) -> bytes:
    if leaf_count <= 0:
        raise ValueError("leaf_count must be positive")
    return blake2b_256(b"\x01" + leaf_count.to_bytes(8, "big") + raw_root, ROOT_PERSONAL)


def hash_program_entry(wallet_hash: str) -> bytes:
    return blake2b_256(bytes([0x01]) + wallet_hash.encode(), LEAF_PERSONAL)


def len_prefix(value: str) -> bytes:
    encoded = value.encode()
    return len(encoded).to_bytes(2, "big") + encoded


def hash_ownership_attest(wallet_hash: str, serial_number: str) -> bytes:
    payload = len_prefix(wallet_hash) + len_prefix(serial_number)
    return blake2b_256(bytes([0x02]) + payload, LEAF_PERSONAL)


def recompute_leaf(bundle: dict) -> str | None:
    leaf = bundle.get("leaf", {})
    event_type = leaf.get("event_type")
    wallet_hash = leaf.get("wallet_hash")
    serial_number = leaf.get("serial_number")

    if event_type == "PROGRAM_ENTRY" and wallet_hash:
        return hash_program_entry(wallet_hash).hex()

    if event_type == "OWNERSHIP_ATTEST" and wallet_hash and serial_number:
        return hash_ownership_attest(wallet_hash, serial_number).hex()

    return None


def walk_proof(leaf_hash: str, proof_path: list[dict]) -> str:
    current = bytes.fromhex(leaf_hash)
    for step in proof_path:
        sibling = bytes.fromhex(step["hash"])
        position = step["position"]
        if position == "left":
            current = hash_node(sibling, current)
        elif position == "right":
            current = hash_node(current, sibling)
        else:
            raise ValueError(f"invalid proof position: {position!r}")
    return current.hex()


def load_url_json(url: str) -> dict:
    req = urllib.request.Request(url, headers=HTTP_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{url} returned HTTP {exc.code}") from exc

    if "json" not in content_type.lower():
        raise RuntimeError(f"{url} returned {content_type or 'unknown content-type'}, not JSON")

    return json.loads(body)


def load_bundle(source: str, api_base: str) -> tuple[dict, str]:
    if len(source) == 64 and all(c in "0123456789abcdefABCDEF" for c in source):
        url = f"{api_base.rstrip('/')}/verify/{source}/proof.json"
        return load_url_json(url), url

    if source.startswith(("http://", "https://")):
        return load_url_json(source), source

    path = Path(source)
    with path.open() as f:
        return json.load(f), str(path)


def fetch_live_status(api_base: str) -> None:
    status = load_url_json(f"{api_base.rstrip('/')}/anchor/status")
    health = load_url_json(f"{api_base.rstrip('/')}/health")
    print()
    print("Live API status (freshness only, not required for offline proof):")
    print(f"  scanner_operational: {health.get('scanner_operational')}")
    print(f"  sync_lag:            {health.get('sync_lag')}")
    print(f"  needs_anchor:        {status.get('needs_anchor')}")
    print(f"  unanchored_leaves:   {status.get('unanchored_leaves')}")
    print(f"  recommendation:      {status.get('recommendation')}")


def historical_legacy_allowed(bundle: dict) -> bool:
    root = bundle.get("root", {})
    anchor = bundle.get("anchor", {})
    scheme = root.get("scheme")
    height = anchor.get("height")
    return (
        scheme == LEGACY_SCHEME
        and height is not None
        and int(height) <= LEGACY_ROOT_MAX_ANCHOR_HEIGHT
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline-first ZAP1 proof verifier")
    parser.add_argument(
        "source",
        nargs="?",
        default=str(DEFAULT_BUNDLE),
        help="Proof bundle path, proof-bundle URL, or leaf hash to fetch from --api-base",
    )
    parser.add_argument("--api-base", default=DEFAULT_API, help="Canonical API base for explicit live fetches")
    parser.add_argument("--live-status", action="store_true", help="Also print current API health/anchor freshness")
    args = parser.parse_args()

    try:
        bundle, loaded_from = load_bundle(args.source, args.api_base)
        leaf_hash = bundle["leaf"]["hash"]
        proof_path = bundle["proof"]
        expected_root = bundle["root"]["hash"]
        raw_root = bytes.fromhex(walk_proof(leaf_hash, proof_path))
        leaf_count = bundle["root"].get("leaf_count")
        computed_root = (
            commit_root(int(leaf_count), raw_root).hex()
            if leaf_count is not None
            else None
        )
        legacy_root = raw_root.hex()
        recomputed_leaf = recompute_leaf(bundle)
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    anchor = bundle.get("anchor", {})
    print(f"Loaded:      {loaded_from}")
    print(f"Protocol:    {bundle.get('protocol', 'unknown')}")
    print(f"Event:       {bundle.get('leaf', {}).get('event_type', 'unknown')}")
    print(f"Leaf:        {leaf_hash}")
    print(f"Root:        {expected_root}")
    print(f"Proof steps: {len(proof_path)}")
    if leaf_count is not None:
        print(f"Leaf count:  {leaf_count}")
    print(f"Anchor txid: {anchor.get('txid') or 'none'}")
    print(f"Anchor h:    {anchor.get('height') if anchor.get('height') is not None else 'pending/unknown'}")

    leaf_ok = recomputed_leaf is None or recomputed_leaf == leaf_hash
    root_ok_v2 = computed_root == expected_root
    root_ok_legacy = legacy_root == expected_root
    legacy_ok = root_ok_legacy and historical_legacy_allowed(bundle)
    root_ok = root_ok_v2 or legacy_ok

    if recomputed_leaf is None:
        print("[SKIP] Leaf preimage recompute unavailable for this event type")
    else:
        print(f"[{'OK' if leaf_ok else 'FAIL'}] Leaf preimage recomputes to bundle leaf")

    if root_ok_v2:
        print("[OK] Merkle proof resolves to count-bound ZAP1 v2 root")
    elif root_ok_legacy:
        if legacy_ok:
            print("[OK] Merkle proof resolves to explicitly historical legacy raw root")
            print(f"[WARN] Legacy root accepted only because anchor height <= {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}")
        else:
            print("[FAIL] Merkle proof resolves only to legacy raw root")
            print(
                f"[FAIL] Legacy roots are accepted only with root.scheme={LEGACY_SCHEME!r} "
                f"and anchor.height <= {LEGACY_ROOT_MAX_ANCHOR_HEIGHT}"
            )
    else:
        print("[FAIL] Merkle proof does not resolve to bundle root")

    if args.live_status:
        try:
            fetch_live_status(args.api_base)
        except Exception as exc:
            print(f"[SKIP] Live status fetch failed: {exc}")

    if leaf_ok and root_ok:
        print()
        print("VERIFIED: bundle is internally consistent. Server trust was not required.")
        return 0

    print()
    print("VERIFICATION FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
