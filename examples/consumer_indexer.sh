#!/usr/bin/env bash
# Indexer consumer example.
#
# Shows how an indexer (Zaino-backed or standalone) ingests ZAP1 data.
# Fetches events, verifies a proof via API, demonstrates the polling pattern.

set -euo pipefail

API="${1:-${ZAP1_API_BASE:-https://api.frontiercompute.cash}}"

echo "ZAP1 indexer consumer"
echo "api: $API"
echo

# 1. discover protocol
protocol=$(curl -sf "$API/protocol/info" | python3 -c "import sys,json; print(json.load(sys.stdin)['protocol'])")
echo "protocol: $protocol"

# 2. get stats
stats=$(curl -sf "$API/stats")
anchors=$(echo "$stats" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_anchors'])")
leaves=$(echo "$stats" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_leaves'])")
echo "anchors: $anchors | leaves: $leaves"

# 3. fetch recent events
events=$(curl -sf "$API/events?limit=10")
count=$(echo "$events" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_returned'])")
echo "recent events: $count"
echo

# 4. verify first event
first_hash=$(echo "$events" | python3 -c "import sys,json; print(json.load(sys.stdin)['events'][0]['leaf_hash'])")
check=$(curl -sf "$API/verify/$first_hash/check")
valid=$(echo "$check" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
echo "verify $first_hash: valid=$valid"

# 5. decode the memo format
first_type=$(echo "$events" | python3 -c "import sys,json; print(json.load(sys.stdin)['events'][0]['event_type'])")
echo "event type: $first_type"

echo
echo "indexer pattern:"
echo "  1. poll /events?limit=N for new attestations"
echo "  2. verify each via /verify/{hash}/check"
echo "  3. fetch proof bundles via /verify/{hash}/proof.json"
echo "  4. store locally for query serving"
echo "  5. optionally use memo_scan binary for Zaino-direct scanning"
