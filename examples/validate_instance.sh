#!/usr/bin/env bash
set -euo pipefail

# Validate any ZAP1 instance. Takes a base URL and runs protocol checks.
# Usage: ./validate_instance.sh https://pay.frontiercompute.io
#        ./validate_instance.sh http://localhost:3081

API="${1:?Usage: $0 <base_url>}"
GREEN='\033[0;32m'
RED='\033[0;31m'
RST='\033[0m'
pass=0
fail=0

check() {
  if [ "$2" = "ok" ]; then
    printf "${GREEN}pass${RST}  %s\n" "$1"
    pass=$((pass + 1))
  else
    printf "${RED}FAIL${RST}  %s (%s)\n" "$1" "$2"
    fail=$((fail + 1))
  fi
}

echo "ZAP1 instance validation: $API"
echo ""

# 1. Health
health=$(curl -sf "$API/health" 2>/dev/null) || health=""
scanner=$(echo "$health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('scanner_operational', False))" 2>/dev/null || echo "false")
check "health endpoint reachable" "$([ -n "$health" ] && echo ok || echo "unreachable")"
check "scanner operational" "$([ "$scanner" = "True" ] && echo ok || echo "$scanner")"

# 2. Protocol
proto=$(curl -sf "$API/protocol/info" 2>/dev/null) || proto=""
protocol=$(echo "$proto" | python3 -c "import json,sys; print(json.load(sys.stdin)['protocol'])" 2>/dev/null || echo "")
version=$(echo "$proto" | python3 -c "import json,sys; print(json.load(sys.stdin)['version'])" 2>/dev/null || echo "")
check "protocol is ZAP1" "$([ "$protocol" = "ZAP1" ] && echo ok || echo "$protocol")"
check "version reported" "$([ -n "$version" ] && echo ok || echo "missing")"

# 3. Stats
stats=$(curl -sf "$API/stats" 2>/dev/null) || stats=""
anchors=$(echo "$stats" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_anchors'])" 2>/dev/null || echo "0")
leaves=$(echo "$stats" | python3 -c "import json,sys; print(json.load(sys.stdin)['total_leaves'])" 2>/dev/null || echo "0")
check "stats endpoint" "$([ -n "$stats" ] && echo ok || echo "unreachable")"

# 4. Anchor history
history=$(curl -sf "$API/anchor/history" 2>/dev/null) || history=""
total=$(echo "$history" | python3 -c "import json,sys; print(json.load(sys.stdin)['total'])" 2>/dev/null || echo "0")
check "anchor history" "$([ -n "$history" ] && echo ok || echo "unreachable")"

# 5. Events feed
events=$(curl -sf "$API/events?limit=1" 2>/dev/null) || events=""
check "events endpoint" "$([ -n "$events" ] && echo ok || echo "unreachable")"

# 6. Memo decode
memo_result=$(curl -sf -X POST "$API/memo/decode" -d "5a4150313a30393a62303962313662656363323030343763666335623937363733393034643364663937383335356262383531303832623362653466333666363862396561636631" 2>/dev/null) || memo_result=""
memo_fmt=$(echo "$memo_result" | python3 -c "import json,sys; print(json.load(sys.stdin)['format'])" 2>/dev/null || echo "")
check "memo decode" "$([ "$memo_fmt" = "zap1" ] && echo ok || echo "$memo_fmt")"

# 7. Build info
build=$(curl -sf "$API/build/info" 2>/dev/null) || build=""
check "build info" "$([ -n "$build" ] && echo ok || echo "unreachable")"

# 8. Anchor status
anchor_status=$(curl -sf "$API/anchor/status" 2>/dev/null) || anchor_status=""
check "anchor status" "$([ -n "$anchor_status" ] && echo ok || echo "unreachable")"

echo ""
echo "$pass pass, $fail fail"
echo "anchors: $anchors | leaves: $leaves | protocol: $protocol $version"

if [ "$fail" -gt 0 ]; then exit 1; fi
