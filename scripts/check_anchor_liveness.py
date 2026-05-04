#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.request


BASE = os.environ.get("ZAP1_API_BASE", "https://api.frontiercompute.cash").rstrip("/")
MAX_ANCHOR_AGE_HOURS = int(os.environ.get("ZAP1_MAX_ANCHOR_AGE_HOURS", "72"))
USER_AGENT = os.environ.get("ZAP1_USER_AGENT", "zap1-anchor-liveness/1.0")


def fetch(path: str):
    try:
        req = urllib.request.Request(
            f"{BASE}{path}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            try:
                return json.load(resp)
            except json.JSONDecodeError as exc:
                content_type = resp.headers.get("Content-Type", "")
                raise RuntimeError(
                    f"fetch failed for {path}: expected JSON, got {content_type or 'unknown content type'}"
                ) from exc
    except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
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
    warnings = []

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
    if anchors:
        if last_age is None or last_age < 0:
            errors.append(f"invalid last_anchor_age_hours={last_age}")
        elif last_age > MAX_ANCHOR_AGE_HOURS:
            message = f"last anchor age {last_age}h exceeds threshold {MAX_ANCHOR_AGE_HOURS}h"
            if status.get("needs_anchor") or status.get("unanchored_leaves", 0) > 0:
                errors.append(message)
            else:
                warnings.append(message)

    confirmed = [a for a in anchors if a.get("height") is not None]
    if confirmed:
        last_confirmed = confirmed[-1]
        if stats.get("last_anchor_block") != last_confirmed.get("height"):
            errors.append(
                f"stats last_anchor_block={stats.get('last_anchor_block')} does not match latest confirmed anchor height={last_confirmed.get('height')}"
            )
    elif anchors:
        errors.append("no confirmed anchors in history (all entries pending mainnet)")
    if anchors:
        latest_submission = anchors[-1]
        if status.get("last_anchor_txid") != latest_submission.get("txid"):
            errors.append(
                f"anchor/status txid={status.get('last_anchor_txid')} does not match latest submission txid={latest_submission.get('txid')}"
            )

    summary = {
        "protocol": protocol.get("protocol"),
        "anchors": history.get("total"),
        "leaves": stats.get("total_leaves"),
        "last_anchor_age_hours": last_age,
        "last_anchor_block": stats.get("last_anchor_block"),
        "needs_anchor": status.get("needs_anchor"),
        "unanchored_leaves": status.get("unanchored_leaves"),
        "warnings": warnings,
        "errors": errors,
    }

    print(json.dumps(summary, indent=2))
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
