#!/usr/bin/env python3
"""
Verify a ZAP1 proof bundle against its supplied root after download.

Default reviewer path:
  python3 examples/verify_proof.py

Optional inputs:
  python3 examples/verify_proof.py examples/live_ownership_attest_proof.json
  python3 examples/verify_proof.py <leaf_hash> --api-base https://api.frontiercompute.cash

The default path is offline-first. A live API is only used when the input is a
leaf hash or an explicit URL. This checks bundle consistency; it does not prove
the root's publication or the underlying event claim. When a typed witness is
not disclosed and recomputed, the displayed event type is claimed metadata.
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
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
CURRENT_BUNDLE_VERSION = "2"
HISTORICAL_BUNDLE_VERSION = "1.0.0"
MAX_U64 = (1 << 64) - 1
HEX32_RE = re.compile(r"[0-9a-f]{64}\Z")


def require_hex32(value: object, label: str) -> str:
    if not isinstance(value, str) or HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be exactly 32-byte lowercase hex")
    return value


def require_leaf_count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_U64:
        raise ValueError("root.leaf_count must be an integer from 1 through 2^64-1")
    return value


def requested_leaf_from_source(source: str) -> str | None:
    if re.fullmatch(r"[0-9A-Fa-f]{64}", source):
        return require_hex32(source, "requested leaf hash")
    if source.startswith(("http://", "https://")):
        path = urllib.parse.urlparse(source).path
        match = re.search(r"/verify/([0-9A-Fa-f]{64})/proof\.json\Z", path)
        if match:
            return require_hex32(match.group(1), "requested leaf hash")
    return None


def validate_bundle(
    bundle: object, requested_leaf: str | None = None
) -> tuple[str, list[dict], str, int, str]:
    if not isinstance(bundle, dict):
        raise ValueError("proof bundle must be a JSON object")
    if bundle.get("protocol") != "ZAP1":
        raise ValueError("bundle protocol must be exactly 'ZAP1'")

    version = bundle.get("version")
    root = bundle.get("root")
    leaf = bundle.get("leaf")
    proof = bundle.get("proof")
    anchor = bundle.get("anchor")
    if not isinstance(root, dict) or not isinstance(leaf, dict) or not isinstance(anchor, dict):
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

    return leaf_hash, proof, root_hash, leaf_count, scheme


def blake2b_256(data: bytes, personal: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32, person=personal).digest()


def hash_node(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle node inputs must each be 32 bytes")
    return blake2b_256(left + right, NODE_PERSONAL)


def commit_root(leaf_count: int, raw_root: bytes) -> bytes:
    leaf_count = require_leaf_count(leaf_count)
    if len(raw_root) != 32:
        raise ValueError("raw Merkle root must be 32 bytes")
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
    current = bytes.fromhex(require_hex32(leaf_hash, "leaf.hash"))
    if not isinstance(proof_path, list):
        raise ValueError("proof must be an array")
    for index, step in enumerate(proof_path):
        if not isinstance(step, dict):
            raise ValueError(f"proof[{index}] must be an object")
        sibling = bytes.fromhex(require_hex32(step.get("hash"), f"proof[{index}].hash"))
        position = step.get("position")
        if position == "left":
            current = hash_node(sibling, current)
        elif position == "right":
            current = hash_node(current, sibling)
        else:
            raise ValueError(f"proof[{index}].position must be 'left' or 'right'")
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


def load_bundle(source: str, api_base: str) -> tuple[dict, str, str | None]:
    requested_leaf = requested_leaf_from_source(source)
    if re.fullmatch(r"[0-9A-Fa-f]{64}", source):
        url = f"{api_base.rstrip('/')}/verify/{requested_leaf}/proof.json"
        return load_url_json(url), url, requested_leaf

    if source.startswith(("http://", "https://")):
        return load_url_json(source), source, requested_leaf

    path = Path(source)
    with path.open() as f:
        return json.load(f), str(path), None


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
        bundle, loaded_from, requested_leaf = load_bundle(args.source, args.api_base)
        leaf_hash, proof_path, expected_root, leaf_count, scheme = validate_bundle(
            bundle, requested_leaf
        )
        raw_root = bytes.fromhex(walk_proof(leaf_hash, proof_path))
        computed_root = commit_root(leaf_count, raw_root).hex()
        legacy_root = raw_root.hex()
        recomputed_leaf = recompute_leaf(bundle)
    except Exception as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    anchor = bundle.get("anchor", {})
    print(f"Loaded:      {loaded_from}")
    print(f"Protocol:    {bundle.get('protocol', 'unknown')}")
    print(f"Claimed type:{bundle.get('leaf', {}).get('event_type', 'unknown'):>17}")
    print(f"Leaf:        {leaf_hash}")
    print(f"Root:        {expected_root}")
    print(f"Proof steps: {len(proof_path)}")
    print(f"Leaf count:  {leaf_count}")
    print(f"Root scheme: {scheme}")
    print(f"Anchor txid: {anchor.get('txid') or 'none'}")
    print(f"Anchor h:    {anchor.get('height') if anchor.get('height') is not None else 'pending/unknown'}")

    typed_leaf_verified = recomputed_leaf == leaf_hash if recomputed_leaf is not None else None
    leaf_ok = typed_leaf_verified is not False
    root_ok_v2 = scheme == COUNT_BOUND_SCHEME and computed_root == expected_root
    root_ok_legacy = legacy_root == expected_root
    legacy_ok = root_ok_legacy and historical_legacy_allowed(bundle)
    root_ok = root_ok_v2 or legacy_ok

    if recomputed_leaf is None:
        print("[UNVERIFIED] Claimed event type lacks a recomputed typed witness")
    else:
        print(f"[{'OK' if typed_leaf_verified else 'FAIL'}] Typed witness recomputes to bundle leaf")

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
        print("MERKLE MATCH: supplied leaf hash is included under the supplied root.")
        if typed_leaf_verified is None:
            print("The claimed event type is not authenticated without a typed witness.")
        print("Root publication and the underlying event claim are not verified.")
        return 0

    print()
    print("VERIFICATION FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
