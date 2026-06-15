#!/usr/bin/env python3
"""Decode a Zcash memo via the ZAP1 API."""
import json, urllib.request, sys

API = "https://api.frontiercompute.cash"
# Example: ZAP1:09 memo
HEX = sys.argv[1] if len(sys.argv) > 1 else "5a4150313a30393a62303962313662656363323030343763666335623937363733393034643364663937383335356262383531303832623362653466333666363862396561636631"

data = urllib.request.urlopen(urllib.request.Request(
    f"{API}/memo/decode", data=HEX.encode(), method="POST"
)).read()
result = json.loads(data)
print(json.dumps(result, indent=2))
