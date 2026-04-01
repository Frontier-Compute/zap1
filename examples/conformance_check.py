#!/usr/bin/env python3
"""
ZAP1 conformance checker. Run against any ZAP1 instance.
No dependencies. No clone needed. Just this one file.

Usage:
  python3 conformance_check.py https://pay.frontiercompute.io
  python3 conformance_check.py http://localhost:3081
  python3 conformance_check.py http://localhost:3081 --key YOUR_API_KEY
"""
import json, sys, urllib.request, urllib.error, hashlib

API = sys.argv[1] if len(sys.argv) > 1 else "https://pay.frontiercompute.io"
KEY = ""
if "--key" in sys.argv:
    KEY = sys.argv[sys.argv.index("--key") + 1]

GREEN = "\033[32m"
RED = "\033[31m"
RST = "\033[0m"
passed = 0
failed = 0

def check(label, ok, detail=""):
    global passed, failed
    if ok:
        print(f"{GREEN}pass{RST}  {label}")
        passed += 1
    else:
        print(f"{RED}FAIL{RST}  {label} ({detail})")
        failed += 1

def get(path):
    try:
        headers = {}
        if KEY:
            headers["Authorization"] = f"Bearer {KEY}"
        req = urllib.request.Request(f"{API}{path}", headers=headers)
        return json.loads(urllib.request.urlopen(req, timeout=15).read())
    except Exception as e:
        return None

def get_status(path):
    try:
        req = urllib.request.Request(f"{API}{path}")
        return urllib.request.urlopen(req, timeout=15).status
    except urllib.error.HTTPError as e:
        return e.code
    except:
        return 0

print(f"ZAP1 conformance check: {API}")
print()

# 1. Health
h = get("/health")
check("health reachable", h is not None)
check("scanner operational", h and h.get("scanner_operational") == True)
check("sync lag zero", h and h.get("sync_lag", 99) < 5, f"lag={h.get('sync_lag') if h else '?'}")

# 2. Protocol
p = get("/protocol/info")
check("protocol is ZAP1", p and p.get("protocol") == "ZAP1")
check("version present", p and p.get("version"))
check("hash is BLAKE2b-256", p and p.get("hash_function") == "BLAKE2b-256")
types = p.get("deployed_types", 0) if p else 0
check("event types > 0", types > 0, f"types={types}")

# 3. Stats
s = get("/stats")
check("stats reachable", s is not None)
anchors = s.get("total_anchors", 0) if s else 0
leaves = s.get("total_leaves", 0) if s else 0
check("has type_counts", s and "type_counts" in s)

# 4. Anchor
ah = get("/anchor/history")
check("anchor history reachable", ah is not None)
total = ah.get("total", 0) if ah else 0

ast = get("/anchor/status")
check("anchor status reachable", ast is not None)
check("has current_root", ast and ast.get("current_root"))

# 5. Events
ev = get("/events?limit=1")
check("events endpoint", ev is not None)

# 6. Memo decode
try:
    memo_hex = "5a4150313a30393a30303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030"
    req = urllib.request.Request(f"{API}/memo/decode", data=memo_hex.encode(), method="POST")
    resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
    check("memo decode returns zap1", resp.get("format") == "zap1")
except:
    check("memo decode", False, "error")

# 7. Build info
b = get("/build/info")
check("build info reachable", b is not None)

# 8. Proof verification (if anchors exist)
if total > 0 and ev and ev.get("events"):
    leaf = ev["events"][0].get("leaf_hash", "")
    if leaf:
        vc = get(f"/verify/{leaf}/check")
        check("proof verification works", vc is not None and "valid" in vc)
        pb = get(f"/verify/{leaf}/proof.json")
        check("proof bundle has root", pb and "root" in pb)
        check("proof bundle has anchor", pb and "anchor" in pb)

# 9. Badge
badge_code = get_status("/badge/status.svg")
check("badge endpoint", badge_code == 200, f"HTTP {badge_code}")

# 10. Auth (if key provided)
if KEY:
    admin_code = get_status("/admin/overview")
    check("admin auth works", admin_code == 200, f"HTTP {admin_code}")

print()
print(f"{passed} pass, {failed} fail")
print(f"anchors: {anchors} | leaves: {leaves} | types: {types}")
if failed > 0:
    sys.exit(1)
