#!/usr/bin/env python3
"""
ZAP1 verifier cross-implementation fingerprint (Python side).

Reads equivalence/corpus.json, runs the Python ZAP1 verifier on each case, and
prints one canonical line per case: "<id> <sha256_hex>", sorted by id.

The fingerprint is a SHA-256 over a domain-separated, injective encoding of each
case's verification INPUTS and the verifier's OUTPUTS (verdict, result scheme,
and the computed count-bound and raw roots). A second independent implementation
(Rust zap1-verify, see equivalence/rust/src/main.rs) computes the same lines from
a separately written verifier. CI compares the two outputs and the committed
fingerprints.expected.txt. A match shows the two verifiers agree on the frozen
corpus. It does not show either verifier is correct against intent: see
equivalence/README.md, "Trust assumptions".

Pattern borrowed from the Tachyon/Ragu fingerprint-equivalence check
(github.com/tachyon-zcash/ragu, qa/lean/docs/src/ragu/fingerprint.md). Cited,
not claimed: that work ties a formal proof to a circuit; this ties two verifier
implementations to each other.
"""
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from verify_proof import verify_proof as zap1_verify  # noqa: E402

DOMAIN = b"zap1-verifier-equiv-v1"
HEX32_RE = __import__("re").compile(r"[0-9a-f]{64}\Z")


def _hex32(value: str, label: str) -> bytes:
    if not isinstance(value, str) or HEX32_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be exactly 32-byte lowercase hex")
    return bytes.fromhex(value)


def _u32(n: int) -> bytes:
    return struct.pack(">I", n)


def _u64(n: int) -> bytes:
    return struct.pack(">Q", n)


def _lp(s: str) -> bytes:
    b = s.encode()
    return _u32(len(b)) + b


def encode_case(case, valid, result_scheme, count_bound_root, raw_root) -> bytes:
    buf = bytearray()
    buf += DOMAIN
    buf += _lp(case["id"])
    buf += _hex32(case["leaf_hash"], "leaf_hash")
    leaf_count = case["leaf_count"]
    if isinstance(leaf_count, bool) or not isinstance(leaf_count, int) or not 1 <= leaf_count < 1 << 64:
        raise ValueError("leaf_count must be an integer from 1 through 2^64-1")
    buf += _u64(leaf_count)
    proof = case["proof"]
    buf += _u64(len(proof))
    for step in proof:
        position = step.get("position")
        if position == "right":
            buf += b"\x01"
        elif position == "left":
            buf += b"\x00"
        else:
            raise ValueError("proof position must be exactly 'left' or 'right'")
        buf += _hex32(step.get("hash"), "proof step hash")
    buf += _hex32(case["expected_root"], "expected_root")
    scheme = case.get("scheme")
    if scheme is None:
        buf += b"\x00"
    else:
        buf += b"\x01" + _lp(scheme)
    anchor_height = case.get("anchor_height")
    if anchor_height is None:
        buf += b"\x00"
    else:
        buf += b"\x01" + _u64(int(anchor_height))
    buf += b"\x01" if case.get("allow_historical_legacy") else b"\x00"
    # verifier outputs
    buf += b"\x01" if valid else b"\x00"
    buf += _lp(result_scheme)
    buf += count_bound_root
    buf += raw_root
    return bytes(buf)


def fingerprint_case(case) -> str:
    leaf = _hex32(case["leaf_hash"], "leaf_hash")
    proof = case["proof"]
    expected = _hex32(case["expected_root"], "expected_root")
    leaf_count = case["leaf_count"]
    valid, result_scheme, count_bound_root, raw_root = zap1_verify(
        leaf,
        proof,
        expected,
        leaf_count,
        scheme=case.get("scheme"),
        anchor_height=case.get("anchor_height"),
        allow_historical_legacy=bool(case.get("allow_historical_legacy")),
    )
    preimage = encode_case(case, valid, result_scheme, count_bound_root, raw_root)
    return hashlib.sha256(preimage).hexdigest()


def main():
    with open(os.path.join(HERE, "corpus.json")) as f:
        corpus = json.load(f)
    lines = [f"{case['id']} {fingerprint_case(case)}" for case in corpus["cases"]]
    for line in sorted(lines):
        print(line)


if __name__ == "__main__":
    main()
