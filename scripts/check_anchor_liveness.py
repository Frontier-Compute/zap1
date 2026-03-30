#!/usr/bin/env python3
import json
import sys
import urllib.error
import urllib.request


BASE = "https://pay.frontiercompute.io"


def fetch(path: str):
    try:
        with urllib.request.urlopen(f"{BASE}{path}", timeout=20) as resp:
            return json.load(resp)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"fetch failed for {path}: {exc}") from exc


def main():
    try:
        protocol = fetch("/protocol/info")
        stats = fetch("/stats")
        history = fetch("/anchor/history")
        status = fetch("/anchor/status")
    except RuntimeError as exc:
        print(json.dumps({"errors": [str(exc)]}, indent=2))
        sys.exit(1)

    errors = []

    if protocol.get("protocol") != "ZAP1":
        errors.append(f"protocol/info returned protocol={protocol.get('protocol')!r}")

    anchors = history.get("anchors", [])
    if history.get("total") != len(anchors):
        errors.append(
            f"anchor/history total={history.get('total')} does not match anchors len={len(anchors)}"
        )

    if stats.get("total_anchors") != history.get("total"):
        errors.append(
            f"stats total_anchors={stats.get('total_anchors')} does not match history total={history.get('total')}"
        )

    last_age = history.get("last_anchor_age_hours")
    if last_age is None or last_age < 0:
        errors.append(f"invalid last_anchor_age_hours={last_age}")
    elif last_age > 72:
        errors.append(f"last anchor is stale: {last_age}h old")

    if anchors:
        last_anchor = anchors[-1]
        if stats.get("last_anchor_block") != last_anchor.get("height"):
            errors.append(
                f"stats last_anchor_block={stats.get('last_anchor_block')} does not match latest anchor height={last_anchor.get('height')}"
            )
        if status.get("last_anchor_txid") != last_anchor.get("txid"):
            errors.append(
                f"anchor/status txid={status.get('last_anchor_txid')} does not match latest anchor txid={last_anchor.get('txid')}"
            )

    summary = {
        "protocol": protocol.get("protocol"),
        "anchors": history.get("total"),
        "leaves": stats.get("total_leaves"),
        "last_anchor_age_hours": last_age,
        "last_anchor_block": stats.get("last_anchor_block"),
        "needs_anchor": status.get("needs_anchor"),
        "errors": errors,
    }

    print(json.dumps(summary, indent=2))
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
