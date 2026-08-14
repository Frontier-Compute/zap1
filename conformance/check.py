#!/usr/bin/env python3
"""
ZAP1 conformance checker. Validates fixtures against the reference implementation.

Run from the repo root:
    python3 conformance/check.py
"""

import json
import os
import subprocess
import sys
import tempfile

DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(DIR)

passed = 0
failed = 0

EVENT_LABELS = {
    0x01: "PROGRAM_ENTRY",
    0x02: "OWNERSHIP_ATTEST",
    0x03: "CONTRACT_ANCHOR",
    0x04: "DEPLOYMENT",
    0x05: "HOSTING_PAYMENT",
    0x06: "SHIELD_RENEWAL",
    0x07: "TRANSFER",
    0x08: "EXIT",
    0x09: "MERKLE_ROOT",
    0x0A: "STAKING_DEPOSIT",
    0x0B: "STAKING_WITHDRAW",
    0x0C: "STAKING_REWARD",
    0x0D: "GOVERNANCE_PROPOSAL",
    0x0E: "GOVERNANCE_VOTE",
    0x0F: "GOVERNANCE_RESULT",
    0x40: "AGENT_REGISTER",
    0x41: "AGENT_POLICY",
    0x42: "AGENT_ACTION",
}


def check(label, ok, detail=""):
    global passed, failed
    if ok:
        print(f"  pass  {label}")
        passed += 1
    else:
        print(f"  FAIL  {label}  {detail}")
        failed += 1


def run_bin(name, args):
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--bin", name, "--"] + args,
        capture_output=True, text=True, cwd=REPO
    )
    return result


def classify_memo_fixture(vec):
    if "hex" in vec:
        raw = bytes.fromhex(vec["hex"])
    else:
        raw = vec["raw"].encode("utf-8")

    if not raw or all(byte == 0 for byte in raw):
        return {"format": "empty"}
    if raw[0] == 0xF6:
        return {"format": "empty" if all(byte == 0 for byte in raw[1:]) else "unknown"}
    if raw[0] == 0xFF:
        return {"format": "binary"}
    if raw[0] == 0xF7 or raw[0] == 0xF5 or raw[0] in range(0xF8, 0xFF):
        return {"format": "unknown"}

    try:
        text = raw.rstrip(b"\x00").decode("utf-8")
    except UnicodeDecodeError:
        return {"format": "unknown"}

    for prefix, fmt in (("ZAP1:", "zap1"), ("NSM1:", "nsm1")):
        if text.startswith(prefix):
            parts = text.split(":")
            if (
                len(parts) == 3
                and len(parts[1]) == 2
                and len(parts[2]) == 64
                and all(ch in "0123456789abcdefABCDEF" for ch in parts[1] + parts[2])
            ):
                event_type = int(parts[1], 16)
                return {
                    "format": fmt,
                    "type": f"0x{event_type:02x}",
                    "label": EVENT_LABELS.get(event_type, "UNKNOWN"),
                }
    return {"format": "text", "text": text}


def main():
    print("ZAP1 conformance check")
    print("======================")
    print()

    # 1. hash vectors
    print("[hash vectors]")
    with open(os.path.join(DIR, "hash_vectors.json")) as f:
        data = json.load(f)

    for vec in data["vectors"]:
        if vec.get("expected_hash") is None:
            continue

        witness = {"events": [{"event_type": vec["event_type"]}]}
        for k, v in vec.get("input_fields", {}).items():
            witness["events"][0][k] = v
        witness["events"][0]["expected_hash"] = vec["expected_hash"]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(witness, tmp)
            tmp_path = tmp.name

        result = run_bin("zap1_schema", ["--witness", tmp_path, "--json"])
        os.unlink(tmp_path)

        if result.returncode == 0:
            output = json.loads(result.stdout)
            ok = output and output[0].get("valid", False)
            check(f"{vec['event_type']} {vec['expected_hash'][:16]}", ok)
        else:
            check(f"{vec['event_type']}", False, result.stderr[:80])

    # 2. proof bundle verification
    print()
    print("[proof bundles]")
    valid_path = os.path.join(DIR, "valid_bundle.json")
    result = run_bin("zap1_audit", ["--bundle", valid_path])
    check("valid bundle passes", result.returncode == 0)

    invalid_path = os.path.join(DIR, "invalid_bundle.json")
    result = run_bin("zap1_audit", ["--bundle", invalid_path])
    check("invalid bundle fails", result.returncode != 0)

    # 3. export package
    print()
    print("[export packages]")
    export_path = os.path.join(DIR, "valid_export.json")
    result = run_bin("zap1_audit", ["--export", export_path])
    check("valid export verifies", result.returncode == 0 and "0 fail" in result.stdout)

    # 4. memo wire format
    print()
    print("[memo format]")
    with open(os.path.join(DIR, "memo_vectors.json")) as f:
        memo_data = json.load(f)

    for vec in memo_data["vectors"]:
        if "hex" in vec:
            hex_input = vec["hex"]
        elif "raw" in vec:
            hex_input = vec["raw"].encode().hex()
        else:
            continue

        observed = classify_memo_fixture(vec)
        expected = {
            "format": vec["expected_format"],
            **({"type": vec["expected_type"]} if "expected_type" in vec else {}),
            **({"label": vec["expected_label"]} if "expected_label" in vec else {}),
            **({"text": vec["expected_text"]} if "expected_text" in vec else {}),
        }
        observed_contract = {key: observed.get(key) for key in expected}
        check(
            f"memo vector: {vec['description'][:40]}",
            observed_contract == expected,
            f"expected {expected}, got {observed_contract}",
        )

    decoder_tests = subprocess.run(
        [
            "cargo",
            "test",
            "--quiet",
            "--locked",
            "--offline",
            "--manifest-path",
            os.path.join(REPO, "zcash-memo-decode", "Cargo.toml"),
        ],
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    check(
        "zcash-memo-decode crate tests",
        decoder_tests.returncode == 0,
        decoder_tests.stderr[-160:].strip(),
    )

    print()
    print(f"{passed} pass, {failed} fail")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
