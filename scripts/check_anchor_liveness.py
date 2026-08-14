#!/usr/bin/env python3
import json
import os
import sys
import time
import urllib.error
import urllib.request


BASE = os.environ.get("ZAP1_API_BASE", "https://api.frontiercompute.cash").rstrip("/")
MAX_ANCHOR_AGE_HOURS = int(os.environ.get("ZAP1_MAX_ANCHOR_AGE_HOURS", "72"))
USER_AGENT = os.environ.get("ZAP1_USER_AGENT", "zap1-anchor-liveness/1.0")
API_RETRIES = int(os.environ.get("ZAP1_API_RETRIES", "3"))
API_RETRY_DELAY_SECONDS = float(os.environ.get("ZAP1_API_RETRY_DELAY_SECONDS", "1"))
JSON_HEADERS = {"User-Agent": USER_AGENT, "Accept": "application/json"}


def env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


REQUIRE_FRESH_ANCHOR = env_flag("ZAP1_REQUIRE_FRESH_ANCHOR", True)


def fetch(path: str):
    last_exc = None
    for attempt in range(1, API_RETRIES + 1):
        try:
            req = urllib.request.Request(
                f"{BASE}{path}",
                headers=JSON_HEADERS,
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                try:
                    return json.load(resp)
                except json.JSONDecodeError as exc:
                    content_type = resp.headers.get("Content-Type", "")
                    raise RuntimeError(
                        f"expected JSON, got {content_type or 'unknown content type'}"
                    ) from exc
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            last_exc = exc
            if attempt < API_RETRIES:
                time.sleep(API_RETRY_DELAY_SECONDS)

    raise RuntimeError(f"fetch failed for {path}: {last_exc}") from last_exc


def build_summary(
    protocol,
    stats,
    history,
    status,
    *,
    require_fresh_anchor=REQUIRE_FRESH_ANCHOR,
    max_anchor_age_hours=MAX_ANCHOR_AGE_HOURS,
):
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
        elif last_age > max_anchor_age_hours:
            message = f"last anchor age {last_age}h exceeds threshold {max_anchor_age_hours}h"
            if status.get("needs_anchor") or status.get("unanchored_leaves", 0) > 0:
                if require_fresh_anchor:
                    errors.append(message)
                else:
                    warnings.append(
                        f"{message}; fresh-anchor requirement disabled by monitor policy"
                    )
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

    return {
        "protocol": protocol.get("protocol"),
        "anchors": history.get("total"),
        "leaves": stats.get("total_leaves"),
        "last_anchor_age_hours": last_age,
        "last_anchor_block": stats.get("last_anchor_block"),
        "needs_anchor": status.get("needs_anchor"),
        "unanchored_leaves": status.get("unanchored_leaves"),
        "fresh_anchor_required": require_fresh_anchor,
        "warnings": warnings,
        "errors": errors,
    }


def main():
    try:
        protocol = fetch("/protocol/info")
        stats = fetch("/stats")
        history = fetch("/anchor/history")
        status = fetch("/anchor/status")
    except RuntimeError as exc:
        print(json.dumps({"errors": [str(exc)]}, indent=2))
        sys.exit(1)

    summary = build_summary(protocol, stats, history, status)

    print(json.dumps(summary, indent=2))
    if summary["errors"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
