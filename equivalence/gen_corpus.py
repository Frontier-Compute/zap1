#!/usr/bin/env python3
"""
Developer generator for equivalence/corpus.json.

Builds the frozen verifier corpus deterministically from the Python ZAP1
primitives, so every leaf hash and root in the corpus is computed, not pasted.
Run this by hand after changing the case set, then regenerate the reference
digests:

    python3 equivalence/gen_corpus.py
    python3 equivalence/fingerprint.py > equivalence/fingerprints.expected.txt

Not run in CI. CI only consumes corpus.json and fingerprints.expected.txt.
The trailing verdict print is for human review of the case set.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from verify_proof import (  # noqa: E402
    commit_root,
    hash_node,
    hash_ownership_attest,
    hash_program_entry,
    verify_proof as zap1_verify,
)

LEGACY = "ZAP1_LEGACY_DUPLICATE_ODD"
CUTOFF = 3317133


def h(b: bytes) -> str:
    return b.hex()


# Two-leaf tree (matches zap1-verify e2e vectors).
leaf1 = hash_program_entry("e2e_wallet_20260327")
leaf2 = hash_ownership_attest("e2e_wallet_20260327", "Z15P-E2E-001")
raw2 = hash_node(leaf1, leaf2)
root2 = commit_root(2, raw2)

# Four-leaf tree.
a = hash_program_entry("w1")
b = hash_program_entry("w2")
c = hash_program_entry("w3")
d = hash_program_entry("w4")
ab = hash_node(a, b)
cd = hash_node(c, d)
raw4 = hash_node(ab, cd)
root4 = commit_root(4, raw4)

# Single-leaf tree.
root1 = commit_root(1, leaf1)


def case(cid, leaf, leaf_count, proof, expected_root, note,
         scheme=None, anchor_height=None, allow=False):
    return {
        "id": cid,
        "leaf_hash": h(leaf),
        "leaf_count": leaf_count,
        "proof": proof,
        "expected_root": expected_root,
        "scheme": scheme,
        "anchor_height": anchor_height,
        "allow_historical_legacy": allow,
        "note": note,
    }


cases = [
    case("v2_valid_program_entry", leaf1, 2,
         [{"hash": h(leaf2), "position": "right"}], h(root2),
         "v2 count-bound valid: leaf1, sibling leaf2 on the right"),
    case("v2_valid_ownership_attest", leaf2, 2,
         [{"hash": h(leaf1), "position": "left"}], h(root2),
         "v2 count-bound valid: leaf2, sibling leaf1 on the left"),
    case("v2_valid_multilevel_4leaf", c, 4,
         [{"hash": h(d), "position": "right"}, {"hash": h(ab), "position": "left"}],
         h(root4), "v2 valid: leaf c in a four-leaf tree, two-step proof"),
    case("v2_valid_single_leaf", leaf1, 1, [], h(root1),
         "v2 valid: single-leaf tree, empty proof"),
    case("legacy_gated_valid", leaf1, 2,
         [{"hash": h(leaf2), "position": "right"}], h(raw2),
         "historical legacy raw root, scheme-gated, height at cutoff: valid legacy",
         scheme=LEGACY, anchor_height=CUTOFF),
    case("neg_wrong_root", leaf1, 2,
         [{"hash": h(leaf2), "position": "right"}], "ff" * 32,
         "wrong expected root: invalid"),
    case("neg_wrong_leaf_count", leaf1, 3,
         [{"hash": h(leaf2), "position": "right"}], h(root2),
         "correct raw root but leaf_count 3 != bound 2: invalid (count-binding)"),
    case("neg_legacy_ungated_downgrade", leaf1, 2,
         [{"hash": h(leaf2), "position": "right"}], h(raw2),
         "raw root matches but no legacy scheme, height, or flag: downgrade rejected"),
    case("neg_legacy_height_too_high", leaf1, 2,
         [{"hash": h(leaf2), "position": "right"}], h(raw2),
         "legacy scheme but anchor height above cutoff: invalid",
         scheme=LEGACY, anchor_height=CUTOFF + 1),
    case("neg_tampered_sibling", leaf1, 2,
         [{"hash": "00" * 32, "position": "right"}], h(root2),
         "tampered sibling: raw root changes: invalid"),
]

corpus = {
    "domain": "zap1-verifier-equiv-v1",
    "description": (
        "Frozen ZAP1 verifier conformance and cross-implementation equivalence "
        "corpus. Inputs only. Verdicts are recomputed by each verifier."
    ),
    "cases": cases,
}

with open(os.path.join(HERE, "corpus.json"), "w") as f:
    json.dump(corpus, f, indent=2)
    f.write("\n")

print(f"wrote corpus.json with {len(cases)} cases\n")
print("verdict review (recomputed by the Python verifier):")
for cs in cases:
    valid, scheme, _cb, _raw = zap1_verify(
        bytes.fromhex(cs["leaf_hash"]),
        cs["proof"],
        bytes.fromhex(cs["expected_root"]),
        int(cs["leaf_count"]),
        scheme=cs.get("scheme"),
        anchor_height=cs.get("anchor_height"),
        allow_historical_legacy=bool(cs.get("allow_historical_legacy")),
    )
    print(f"  {cs['id']:32} valid={str(valid):5} scheme={scheme}")
