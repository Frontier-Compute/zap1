#!/usr/bin/env bash
set -euo pipefail

# ZAP1 validation script. Run this from the repo root to verify all claims.
# No arguments needed. Checks live API, runs tests, validates proofs.

API="https://pay.frontiercompute.io"
RED='\033[0;31m'
GRN='\033[0;32m'
RST='\033[0m'

pass=0
fail=0

check() {
  local label="$1"
  local result="$2"
  if [ "$result" = "ok" ]; then
    printf "${GRN}pass${RST}  %s\n" "$label"
    pass=$((pass + 1))
  else
    printf "${RED}FAIL${RST}  %s (%s)\n" "$label" "$result"
    fail=$((fail + 1))
  fi
}

echo "ZAP1 validation check"
echo "===================="
echo

# 1. protocol info
protocol=$(curl -sf "$API/protocol/info" | python3 -c "import sys,json; print(json.load(sys.stdin)['protocol'])" 2>/dev/null || echo "error")
check "protocol/info returns ZAP1" "$([ "$protocol" = "ZAP1" ] && echo ok || echo "$protocol")"

# 2. anchor count
anchors=$(curl -sf "$API/stats" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_anchors'])" 2>/dev/null || echo "0")
check "mainnet anchors > 0" "$([ "$anchors" -gt 0 ] 2>/dev/null && echo ok || echo "$anchors")"

# 3. leaf count
leaves=$(curl -sf "$API/stats" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_leaves'])" 2>/dev/null || echo "0")
check "mainnet leaves > 0" "$([ "$leaves" -gt 0 ] 2>/dev/null && echo ok || echo "$leaves")"

# 4. proof verification
valid=$(curl -sf "$API/verify/075b00df286038a7b3f6bb70054df61343e3481fba579591354a00214e9e019b/check" | python3 -c "import sys,json; print(json.load(sys.stdin)['valid'])" 2>/dev/null || echo "error")
check "live proof verifies" "$([ "$valid" = "True" ] && echo ok || echo "$valid")"

# 5. memo decode endpoint
memo_fmt=$(curl -sf -X POST "$API/memo/decode" -d "5a4150313a30313a30373562303064663238363033386137623366366262373030353464663631333433653334383166626135373935393133353461303032313465396530313962" | python3 -c "import sys,json; print(json.load(sys.stdin)['format'])" 2>/dev/null || echo "error")
check "memo decode returns zap1" "$([ "$memo_fmt" = "zap1" ] && echo ok || echo "$memo_fmt")"

# 6. explorer up
explorer=$(curl -sf -o /dev/null -w "%{http_code}" "https://explorer.frontiercompute.io" 2>/dev/null || echo "000")
check "explorer reachable" "$([ "$explorer" = "200" ] && echo ok || echo "HTTP $explorer")"

# 7. simulator up
sim=$(curl -sf -o /dev/null -w "%{http_code}" "https://simulator.frontiercompute.io" 2>/dev/null || echo "000")
check "simulator reachable" "$([ "$sim" = "200" ] && echo ok || echo "HTTP $sim")"

# 8. crates.io
crate_ver=$(curl -sf "https://crates.io/api/v1/crates/zap1-verify" | python3 -c "import sys,json; print(json.load(sys.stdin)['crate']['max_version'])" 2>/dev/null || echo "error")
check "zap1-verify on crates.io" "$([ -n "$crate_ver" ] && [ "$crate_ver" != "error" ] && echo ok || echo "$crate_ver")"

# 9. events feed
events_count=$(curl -sf "$API/events?limit=5" | python3 -c "import sys,json; print(json.load(sys.stdin)['total_returned'])" 2>/dev/null || echo "0")
check "events feed returns data" "$([ "$events_count" -gt 0 ] 2>/dev/null && echo ok || echo "$events_count")"

# 10. crates.io
memo_crate=$(curl -sf "https://crates.io/api/v1/crates/zcash-memo-decode" | python3 -c "import sys,json; print(json.load(sys.stdin)['crate']['max_version'])" 2>/dev/null || echo "error")
check "zcash-memo-decode on crates.io" "$([ -n "$memo_crate" ] && [ "$memo_crate" != "error" ] && echo ok || echo "$memo_crate")"

# 9. local tests
if command -v cargo > /dev/null 2>&1; then
  test_result=$(cargo test --quiet --all-targets 2>&1 | grep -c "FAILED" || true)
  check "cargo test passes" "$([ "$test_result" = "0" ] && echo ok || echo "$test_result failures")"

  # 10. proof bundle audit
  if [ -f examples/live_ownership_attest_proof.json ]; then
    audit_result=$(cargo run --quiet --bin zap1_audit -- --bundle examples/live_ownership_attest_proof.json 2>&1 | head -1)
    check "zap1_audit verifies proof bundle" "$(echo "$audit_result" | grep -q "proof: ok" && echo ok || echo "$audit_result")"
  fi

  # 11. export -> offline audit loop
  if [ -f examples/demo_audit_package.json ]; then
    export_result=$(cargo run --quiet --bin zap1_audit -- --export examples/demo_audit_package.json 2>&1 | tail -1)
    check "zap1_audit verifies export package" "$(echo "$export_result" | grep -q "0 fail" && echo ok || echo "$export_result")"
  fi

  # 12. schema validator
  if [ -f examples/schema_witness.json ]; then
    schema_result=$(cargo run --quiet --bin zap1_schema -- --witness examples/schema_witness.json 2>&1 | tail -1)
    check "zap1_schema validates witness" "$(echo "$schema_result" | grep -q "0 fail" && echo ok || echo "$schema_result")"
  fi
fi

echo
echo "===================="
echo "$pass pass, $fail fail"
echo "anchors: $anchors | leaves: $leaves | protocol: $protocol"

if [ "$fail" -gt 0 ]; then
  exit 1
fi
