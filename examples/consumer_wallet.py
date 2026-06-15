#!/usr/bin/env python3
"""
Wallet consumer example.

Shows how a wallet displays ZAP1 attestation data in transaction history.
After trial decryption, the wallet checks memo format and enriches the UI.
"""

import json
import urllib.request

API = "https://api.frontiercompute.cash"


def classify_memo(hex_bytes: str) -> dict:
    """Call the /memo/decode endpoint to classify a memo."""
    req = urllib.request.Request(
        f"{API}/memo/decode",
        data=hex_bytes.encode(),
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.load(resp)


def main():
    # simulate a wallet that received a ZAP1 attestation memo
    # this is the hex encoding of "ZAP1:01:075b00df..."
    memo_hex = (
        "5a4150313a30313a3037356230306466323836303338613762336636"
        "6262373030353464663631333433653334383166626135373935393133"
        "35346130303231346539653031396200"
    )

    result = classify_memo(memo_hex)
    fmt = result.get("format", "unknown")

    print(f"memo format: {fmt}")

    if fmt == "zap1":
        print(f"  event: {result['event_label']}")
        print(f"  payload: {result['payload_hash'][:16]}...")
        print(f"  verify: {API}/verify/{result['payload_hash']}")
        print()
        print("wallet UI: show attestation badge in transaction detail")

    elif fmt == "text":
        print(f"  text: {result['text']}")
        print()
        print("wallet UI: show as transaction note")

    elif fmt == "zip302":
        print(f"  parts: {len(result['parts'])}")
        print()
        print("wallet UI: parse structured memo parts")

    elif fmt == "empty":
        print("wallet UI: no memo content")

    else:
        print(f"wallet UI: unknown format ({result.get('first_byte', '??')})")


if __name__ == "__main__":
    main()
