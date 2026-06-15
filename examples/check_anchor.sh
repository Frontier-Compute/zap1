#!/usr/bin/env bash
# Check if a ZAP1 anchor exists on Zcash mainnet.
# Usage: ./check_anchor.sh [txid_prefix]
set -euo pipefail
API="${ZAP1_API_BASE:-https://api.frontiercompute.cash}"
PREFIX="${1:-59e8fe14}"
echo "Checking anchor with txid prefix: $PREFIX"
curl -s "$API/badge/anchor/$PREFIX" | grep -q "anchored at" && echo "VERIFIED: anchor found on-chain" || echo "NOT FOUND"
echo ""
echo "Full anchor history:"
curl -s "$API/anchor/history" | python3 -m json.tool
