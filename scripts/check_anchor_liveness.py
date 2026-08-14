#!/usr/bin/env python3
import json
import os
import re
from datetime import datetime
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
    normalized = value.strip().lower()
    if normalized in {"1", "true"}:
        return True
    if normalized in {"0", "false"}:
        return False
    raise SystemExit(f"{name} must be exactly true, false, 1, or 0")


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
    if not isinstance(anchors, list):
        errors.append("anchor/history anchors must be a list")
        anchors = []
    if history.get("total") != len(anchors):
        errors.append(
            f"anchor/history total={history.get('total')} does not match anchors len={len(anchors)}"
        )

    leaves = stats.get("total_leaves")
    if type(leaves) is not int or leaves < 0:
        errors.append(f"invalid stats total_leaves={leaves!r}")
        leaves = None

    status_leaf_count = status.get("leaf_count")
    if type(status_leaf_count) is not int or status_leaf_count < 0:
        errors.append(f"invalid anchor/status leaf_count={status_leaf_count!r}")
    elif leaves is not None and status_leaf_count != leaves:
        errors.append(
            f"anchor/status leaf_count={status_leaf_count} does not match stats total_leaves={leaves}"
        )

    needs_anchor = status.get("needs_anchor")
    if type(needs_anchor) is not bool:
        errors.append(f"invalid anchor/status needs_anchor={needs_anchor!r}")

    unanchored = status.get("unanchored_leaves")
    if type(unanchored) is not int or unanchored < 0:
        errors.append(f"invalid anchor/status unanchored_leaves={unanchored!r}")
    elif leaves is not None and unanchored > leaves:
        errors.append(
            f"anchor/status unanchored_leaves={unanchored} exceeds total_leaves={leaves}"
        )
    if type(needs_anchor) is bool and type(unanchored) is int:
        if unanchored > 0 and not needs_anchor:
            errors.append("anchor/status has pending leaves but needs_anchor=false")

    current_root = status.get("current_root")
    if leaves is not None and leaves > 0:
        if not isinstance(current_root, str) or re.fullmatch(r"[0-9a-f]{64}", current_root) is None:
            errors.append(f"invalid anchor/status current_root={current_root!r} for nonempty tree")
    elif current_root not in {None, "none"}:
        if not isinstance(current_root, str) or re.fullmatch(r"[0-9a-f]{64}", current_root) is None:
            errors.append(f"invalid anchor/status current_root={current_root!r}")

    if stats.get("total_anchors") != history.get("total"):
        errors.append(
            f"stats total_anchors={stats.get('total_anchors')} does not match history total={history.get('total')}"
        )

    previous_created = None
    previous_leaf_count = 0
    for index, anchor in enumerate(anchors):
        label = f"anchor/history anchors[{index}]"
        if not isinstance(anchor, dict):
            errors.append(f"{label} must be an object")
            continue
        root = anchor.get("root")
        txid = anchor.get("txid")
        anchor_leaves = anchor.get("leaf_count")
        height = anchor.get("height")
        created_at = anchor.get("created_at")
        if not isinstance(root, str) or re.fullmatch(r"[0-9a-f]{64}", root) is None:
            errors.append(f"{label} has invalid root={root!r}")
        if not isinstance(txid, str) or re.fullmatch(r"[0-9a-f]{64}", txid) is None:
            errors.append(f"{label} has invalid txid={txid!r}")
        if type(anchor_leaves) is not int or anchor_leaves <= 0:
            errors.append(f"{label} has invalid leaf_count={anchor_leaves!r}")
        elif leaves is not None and anchor_leaves > leaves:
            errors.append(f"{label} leaf_count={anchor_leaves} exceeds total_leaves={leaves}")
        elif anchor_leaves <= previous_leaf_count:
            errors.append(f"{label} leaf_count is not strictly increasing")
        else:
            previous_leaf_count = anchor_leaves
        if height is not None and (type(height) is not int or height <= 0):
            errors.append(f"{label} has invalid height={height!r}")
        try:
            parsed_created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            if parsed_created.tzinfo is None:
                raise ValueError("timezone missing")
        except (AttributeError, TypeError, ValueError):
            errors.append(f"{label} has invalid created_at={created_at!r}")
        else:
            if previous_created is not None and parsed_created < previous_created:
                errors.append(f"{label} created_at is out of order")
            previous_created = parsed_created
        if anchor.get("scheme") not in {"ZAP1_COUNT_BOUND_V2", "ZAP1_LEGACY_DUPLICATE_ODD"}:
            errors.append(f"{label} has invalid scheme={anchor.get('scheme')!r}")
    last_age = history.get("last_anchor_age_hours")
    if anchors:
        if type(last_age) is not int or last_age < 0:
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

    if leaves is not None and leaves > 0 and not anchors:
        message = "nonempty Merkle tree has no recorded anchor"
        if require_fresh_anchor:
            errors.append(message)
        else:
            warnings.append(f"{message}; fresh-anchor requirement disabled by monitor policy")

    confirmed = [a for a in anchors if a.get("height") is not None]
    if confirmed:
        last_confirmed = confirmed[-1]
        if stats.get("last_anchor_block") != last_confirmed.get("height"):
            errors.append(
                f"stats last_anchor_block={stats.get('last_anchor_block')} does not match latest confirmed anchor height={last_confirmed.get('height')}"
            )
    elif anchors:
        errors.append("no confirmed anchors in history (all entries pending mainnet)")
    if anchors and status.get("unanchored_leaves") == 0:
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
