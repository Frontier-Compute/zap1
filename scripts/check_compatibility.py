#!/usr/bin/env python3
"""
Validate compatibility test vectors against the live ZAP1 schema validator.
Run from the repo root: python3 scripts/check_compatibility.py
"""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
NODE_PERSONAL = b"NordicShield_MRK"
ROOT_PERSONAL = b"NordicShield_RTK"


def blake2b_256(data, *, personal):
    return hashlib.blake2b(data, digest_size=32, person=personal).digest()


def count_bound_merkle_root(leaves):
    if not leaves:
        raise ValueError("Merkle vector must contain at least one leaf")

    level = [bytes.fromhex(leaf) for leaf in leaves]
    leaf_count = len(level)
    while len(level) > 1:
        next_level = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(blake2b_256(left + right, personal=NODE_PERSONAL))
        level = next_level

    return blake2b_256(
        b"\x01" + leaf_count.to_bytes(8, "big") + level[0],
        personal=ROOT_PERSONAL,
    ).hex()


def main():
    with (REPO / "examples" / "compatibility_vectors.json").open() as f:
        vectors = json.load(f)

    passed = 0
    failed = 0

    print("ZAP1 compatibility check")
    print("========================")
    print()

    with tempfile.TemporaryDirectory(prefix="zap1-compat-") as temp_dir:
        temp_root = Path(temp_dir)
        for index, vec in enumerate(vectors["vectors"]):
            if vec["expected_hash"] is None:
                continue

            witness = {"events": [{"event_type": vec["event_type"]}]}
            event = witness["events"][0]

            fields = vec.get("input_fields", {})
            for key, value in fields.items():
                event[key] = value
            event["expected_hash"] = vec["expected_hash"]

            witness_path = temp_root / f"witness-{index}.json"
            witness_path.write_text(json.dumps(witness), encoding="utf-8")

            result = subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--locked",
                    "--bin",
                    "zap1_schema",
                    "--",
                    "--witness",
                    str(witness_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=REPO,
            )

            if result.returncode != 0:
                detail = result.stderr.strip().splitlines()
                detail = detail[-1] if detail else f"exit {result.returncode}"
                print(f"  FAIL {vec['event_type']}: schema validator error: {detail}")
                failed += 1
                continue

            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                print(f"  FAIL {vec['event_type']}: invalid validator JSON: {exc}")
                failed += 1
                continue

            if output and output[0].get("valid") is True:
                print(f"  pass {vec['event_type']} {vec['expected_hash'][:16]}...")
                passed += 1
            else:
                print(f"  FAIL {vec['event_type']} hash mismatch")
                failed += 1

    # merkle tree vectors
    for tree_vec in vectors.get("merkle_tree_vectors", []):
        leaves = tree_vec["leaves"]
        expected_root = tree_vec["expected_root"]
        try:
            computed_root = count_bound_merkle_root(leaves)
        except (TypeError, ValueError) as exc:
            print(f"  FAIL tree ({len(leaves)} leaves): {exc}")
            failed += 1
            continue

        if computed_root == expected_root:
            print(f"  pass tree ({len(leaves)} leaves) {expected_root[:16]}...")
            passed += 1
        else:
            print(
                f"  FAIL tree ({len(leaves)} leaves): "
                f"expected {expected_root}, got {computed_root}"
            )
            failed += 1

    print()
    print(f"{passed} pass, {failed} fail")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
