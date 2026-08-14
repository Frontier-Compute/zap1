#!/usr/bin/env python3
"""Explorer example for the redacted public commitment feed."""

import json
import urllib.request
from urllib.parse import quote

API = "https://api.frontiercompute.cash"


def fetch_events(limit: int = 50) -> list:
    """Fetch recent attestation events."""
    url = f"{API}/events?limit={quote(str(limit), safe='')}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        data = json.load(resp)
    return data.get("events", [])


def fetch_proof(leaf_hash: str) -> dict:
    """Fetch a proof bundle for verification."""
    url = f"{API}/verify/{quote(leaf_hash, safe='')}/proof.json"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)


def main():
    events = fetch_events(limit=20)
    print(f"found {len(events)} public commitment records\n")

    for event in events:
        print(
            f"  claimed type {event['event_type']:20s} "
            f"{event['leaf_hash'][:16]}..."
        )

    # fetch one proof bundle to show the data path
    if events:
        leaf = events[0]["leaf_hash"]
        proof = fetch_proof(leaf)
        print(f"\nproof bundle for {leaf[:16]}:")
        print(f"  root: {proof['root']['hash'][:16]}...")
        print(f"  anchor: block {proof['anchor'].get('height', 'unknown')}")
        print(f"  steps: {len(proof['proof'])}")
        print("  local bundle consistency: use examples/verify_proof.py")
        print("  event type and subject preimages are withheld from this public feed")


if __name__ == "__main__":
    main()
