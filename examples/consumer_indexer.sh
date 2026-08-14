#!/usr/bin/env bash
# Indexer consumer example.
#
# Shows how an indexer ingests the redacted public commitment feed.
# Fetches records and server-computed bundle checks.

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
echo "API-recorded transaction references: $anchors | leaves: $leaves"

# 3. fetch recent events
events=$(curl -sf "$API/events?limit=10")
count=$(echo "$events" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_returned'])")
echo "recent events: $count"
echo

if [ "$count" -gt 0 ]; then
  first_hash=$(echo "$events" | python3 -c "import sys,json; print(json.load(sys.stdin)['events'][0]['leaf_hash'])")
  check=$(curl -sf "$API/verify/$first_hash/check")
  valid=$(echo "$check" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])")
  first_type=$(echo "$events" | python3 -c "import sys,json; print(json.load(sys.stdin)['events'][0]['event_type'])")
  echo "server bundle-consistency check $first_hash: valid=$valid"
  echo "operator-claimed event type: $first_type"
else
  echo "no current record available to sample"
fi

echo
echo "indexer pattern:"
echo "  1. poll /events?limit=N for new commitment records"
echo "  2. treat /verify/{hash}/check as a server result, not independent verification"
echo "  3. fetch proof bundles via /verify/{hash}/proof.json"
echo "  4. verify bundle consistency locally before storing"
echo "  5. keep event labels, transaction existence, memo binding, and claim truth separate"
