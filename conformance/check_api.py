#!/usr/bin/env python3
"""
Validate live ZAP1 API responses against the schema contract.

    python3 conformance/check_api.py [base_url]
"""

import json
import os
import sys
import urllib.error
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


API_KEY = "Blqr7I45XS-VHJDTDa_v7WBgWgqlpIYlQj4asaP-Y-g"


def fetch(path, headers=None):
    url = f"{BASE}{path}"
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.load(resp)
    except Exception as e:
        return None


def fetch_raw(path, headers=None, method="GET"):
    url = f"{BASE}{path}"
    try:
        req = urllib.request.Request(url, headers=headers or {}, method=method)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode(), resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return e.code, "", ""
    except Exception as e:
        return 0, "", ""


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
        version = data.get("version", "")
        check("/protocol/info version major=3", isinstance(version, str) and version.startswith("3."))

    # /build/info
    build_data = fetch("/build/info")
    check("/build/info returns valid JSON", build_data is not None)
    if build_data:
        check("/build/info has version", "version" in build_data)

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
    verify_hash = None
    data = fetch("/events?limit=3")
    if validate_required(data, schemas["/events"], "/events"):
        check("/events protocol=ZAP1", data.get("protocol") == "ZAP1")
        events = data.get("events", [])
        if events:
            ev = events[0]
            verify_hash = ev.get("leaf_hash")
            check("/events[0] has leaf_hash", "leaf_hash" in ev and len(ev["leaf_hash"]) == 64)
            check("/events[0] has verify_url", "verify_url" in ev)

    # /anchor/history
    has_anchors = False
    data = fetch("/anchor/history")
    if validate_required(data, schemas["/anchor/history"], "/anchor/history"):
        anchors = data.get("anchors", [])
        has_anchors = len(anchors) > 0
        check("/anchor/history total consistent", data.get("total", -1) == len(anchors))
        if anchors:
            check("/anchor/history[0] has root", len(anchors[0].get("root", "")) >= 64)

    # /verify/{hash}/check
    if verify_hash is None:
        print("  skip  /verify/check  (no events available to sample)")
    else:
        data = fetch(f"/verify/{verify_hash}/check")
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

    # /admin/anchor/qr (requires auth, returns HTML when anchors exist)
    status, body, ctype = fetch_raw("/admin/anchor/qr")
    check("/admin/anchor/qr rejects without auth", status == 401)

    status, body, ctype = fetch_raw(
        "/admin/anchor/qr",
        headers={"Authorization": f"Bearer {API_KEY}"},
    )
    if has_anchors:
        check("/admin/anchor/qr returns 200 with auth", status == 200)
        check("/admin/anchor/qr content-type is HTML", "text/html" in ctype)
        check("/admin/anchor/qr body contains HTML", "<html" in body.lower())
    else:
        check("/admin/anchor/qr accepted auth", status in (200, 400))
        if status == 400:
            print("  skip  /admin/anchor/qr HTML checks  (no anchors yet)")

    # /admin/anchor/record (POST-only, requires auth)
    status, _, _ = fetch_raw("/admin/anchor/record")
    check("/admin/anchor/record rejects GET", status in (401, 405))

    print()
    print(f"{passed} pass, {failed} fail")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
