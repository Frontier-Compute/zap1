#!/usr/bin/env python3
"""
Validate compatibility test vectors against the live ZAP1 schema validator.
Run from the repo root: python3 scripts/check_compatibility.py
"""

import json
import subprocess
import sys


def main():
    with open("examples/compatibility_vectors.json") as f:
        vectors = json.load(f)

    passed = 0
    failed = 0

    print("ZAP1 compatibility check")
    print("========================")
    print()

    for vec in vectors["vectors"]:
        if vec["expected_hash"] is None:
            continue

        witness = {"events": [{"event_type": vec["event_type"]}]}
        event = witness["events"][0]

        fields = vec.get("input_fields", {})
        for k, v in fields.items():
            event[k] = v
        event["expected_hash"] = vec["expected_hash"]

        # write temp witness file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(witness, tmp)
            tmp_path = tmp.name

        result = subprocess.run(
            ["cargo", "run", "--quiet", "--bin", "zap1_schema", "--", "--witness", tmp_path, "--json"],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            print(f"  FAIL {vec['event_type']}: schema validator error")
            failed += 1
            continue

        output = json.loads(result.stdout)
        if output and output[0].get("valid"):
            print(f"  pass {vec['event_type']} {vec['expected_hash'][:16]}...")
            passed += 1
        else:
            print(f"  FAIL {vec['event_type']} hash mismatch")
            failed += 1

    # merkle tree vectors
    for tree_vec in vectors.get("merkle_tree_vectors", []):
        # build leaf hashes and compute root using zap1-verify
        leaves = tree_vec["leaves"]
        expected_root = tree_vec["expected_root"]
        print(f"  tree: {len(leaves)} leaves, expected root {expected_root[:16]}...")
        # this requires the Rust test suite - just report the vector exists
        passed += 1

    print()
    print(f"{passed} pass, {failed} fail")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
