#!/usr/bin/env python3
"""
Validate live ZAP1 API responses against the schema contract.

    python3 conformance/check_api.py [base_url]
"""

import json
import os
import sys
import urllib.request

DIR = os.path.dirname(os.path.abspath(__file__))
BASE = sys.argv[1] if len(sys.argv) > 1 else "https://pay.frontiercompute.io"

passed = 0
failed = 0


def check(label, ok, detail=""):
    global passed, failed
    if ok:
        print(f"  pass  {label}")
        passed += 1
    else:
        print(f"  FAIL  {label}  {detail}")
        failed += 1


def fetch(path):
    url = f"{BASE}{path}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.load(resp)
    except Exception as e:
        return None


def validate_required(data, schema, path):
    if data is None:
        check(path, False, "fetch failed")
        return False

    required = schema.get("required", [])
    for field in required:
        if field not in data:
            check(f"{path} has {field}", False, "missing required field")
            return False

    check(f"{path} required fields", True)
    return True


def validate_type(value, expected_type, field_name):
    if isinstance(expected_type, list):
        types = expected_type
    else:
        types = [expected_type]

    type_map = {"string": str, "integer": int, "boolean": bool, "array": list, "null": type(None)}
    return any(isinstance(value, type_map.get(t, object)) for t in types)


def main():
    with open(os.path.join(DIR, "api_schemas.json")) as f:
        schemas = json.load(f)["schemas"]

    print(f"ZAP1 API schema validation against {BASE}")
    print("=" * 50)
    print()

    # /protocol/info
    data = fetch("/protocol/info")
    if validate_required(data, schemas["/protocol/info"], "/protocol/info"):
        check("/protocol/info protocol=ZAP1", data.get("protocol") == "ZAP1")
        check("/protocol/info hash=BLAKE2b-256", data.get("hash_function") == "BLAKE2b-256")

    # /stats
    data = fetch("/stats")
    if validate_required(data, schemas["/stats"], "/stats"):
        check("/stats anchors >= 0", data.get("total_anchors", -1) >= 0)
        check("/stats leaves >= 0", data.get("total_leaves", -1) >= 0)

    # /health
    data = fetch("/health")
    if validate_required(data, schemas["/health"], "/health"):
        check("/health scanner bool", isinstance(data.get("scanner_operational"), bool))
        check("/health rpc bool", isinstance(data.get("rpc_reachable"), bool))

    # /events
    data = fetch("/events?limit=3")
    if validate_required(data, schemas["/events"], "/events"):
        check("/events protocol=ZAP1", data.get("protocol") == "ZAP1")
        events = data.get("events", [])
        if events:
            ev = events[0]
            check("/events[0] has leaf_hash", "leaf_hash" in ev and len(ev["leaf_hash"]) == 64)
            check("/events[0] has verify_url", "verify_url" in ev)

    # /anchor/history
    data = fetch("/anchor/history")
    if validate_required(data, schemas["/anchor/history"], "/anchor/history"):
        anchors = data.get("anchors", [])
        check("/anchor/history has anchors", len(anchors) > 0)
        if anchors:
            check("/anchor/history[0] has root", len(anchors[0].get("root", "")) >= 64)

    # /verify/{hash}/check
    test_hash = "075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b"
    data = fetch(f"/verify/{test_hash}/check")
    if validate_required(data, schemas["/verify/{hash}/check"], "/verify/check"):
        check("/verify/check valid=true", data.get("valid") is True)
        check("/verify/check protocol=ZAP1", data.get("protocol") == "ZAP1")

    # /memo/decode
    hex_body = "5a4150313a30313a30373562303064663238363033386137623366366262373030353464663631333433653334383166626135373935393133353461303032313465396530313962"
    try:
        req = urllib.request.Request(f"{BASE}/memo/decode", data=hex_body.encode(), method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
        check("/memo/decode returns format", "format" in data)
        check("/memo/decode format=zap1", data.get("format") == "zap1")
    except Exception as e:
        check("/memo/decode", False, str(e))

    print()
    print(f"{passed} pass, {failed} fail")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
