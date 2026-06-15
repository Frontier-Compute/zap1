#!/usr/bin/env python3
"""
Explorer consumer example.

Shows how a block explorer indexes ZAP1 attestation events.
Polls the /events endpoint and builds a local index of attestations.
"""

import json
import urllib.request

API = "https://api.frontiercompute.cash"


def fetch_events(limit: int = 50) -> list:
    """Fetch recent attestation events."""
    url = f"{API}/events?limit={limit}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        data = json.load(resp)
    return data.get("events", [])


def fetch_proof(leaf_hash: str) -> dict:
    """Fetch a proof bundle for verification."""
    url = f"{API}/verify/{leaf_hash}/proof.json"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)


def main():
    events = fetch_events(limit=20)
    print(f"found {len(events)} attestation events\n")

    for event in events:
        print(f"  {event['event_type']:20s} {event['leaf_hash'][:16]}... wallet={event['wallet_hash'][:16]}")

        if event.get("serial_number"):
            print(f"  {'':20s} serial={event['serial_number']}")

    # fetch one proof bundle to show the data path
    if events:
        leaf = events[0]["leaf_hash"]
        proof = fetch_proof(leaf)
        print(f"\nproof bundle for {leaf[:16]}:")
        print(f"  root: {proof['root']['hash'][:16]}...")
        print(f"  anchor: block {proof['anchor'].get('height', 'unknown')}")
        print(f"  steps: {len(proof['proof'])}")
        print(f"  (cryptographic verification: use zap1_audit --bundle)")


if __name__ == "__main__":
    main()
