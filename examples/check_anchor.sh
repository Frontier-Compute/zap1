#!/usr/bin/env bash
# Check whether the ZAP1 API records an anchor transaction.
# Usage: ./check_anchor.sh [txid_prefix]
set -euo pipefail
API="${ZAP1_API_BASE:-https://api.frontiercompute.cash}"
PREFIX="${1:-59e8fe14}"
echo "Checking anchor with txid prefix: $PREFIX"
curl -fsS "$API/anchor/history" | python3 -c '
import json, sys
prefix = sys.argv[1].lower()
rows = json.load(sys.stdin).get("anchors", [])
matches = [row for row in rows if str(row.get("txid", "")).lower().startswith(prefix)]
if not matches:
    raise SystemExit(1)
row = matches[-1]
print("RECORDED: txid={} height={}".format(row.get("txid"), row.get("height")))
' "$PREFIX" || { echo "NOT FOUND"; exit 1; }
echo "This checks the API record only. Transaction existence can be checked independently; encrypted Orchard memo contents require separate disclosure material."
echo ""
echo "Full anchor history:"
curl -s "$API/anchor/history" | python3 -m json.tool
