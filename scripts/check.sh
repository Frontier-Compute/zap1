#!/usr/bin/env bash
set -euo pipefail

# ZAP1 validation script. Run this from the repo root to verify all claims.
# No arguments needed. Checks live API, runs tests, validates proofs.

API="${ZAP1_API_BASE:-https://api.frontiercompute.cash}"
USER_AGENT="${ZAP1_USER_AGENT:-zap1-anchor-liveness/1.0}"
PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
  if command -v python3 > /dev/null 2>&1; then
    PYTHON=python3
  elif command -v python > /dev/null 2>&1; then
    PYTHON=python
  else
    PYTHON=python3
  fi
fi
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

curl_json() {
  curl -sf -A "$USER_AGENT" -H "Accept: application/json" "$@"
}

echo "ZAP1 validation check"
echo "===================="
echo

# 1. protocol info
protocol=$(curl_json "$API/protocol/info" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['protocol'])" 2>/dev/null || echo "error")
check "protocol/info returns ZAP1" "$([ "$protocol" = "ZAP1" ] && echo ok || echo "$protocol")"

# 2. anchor count
anchors=$(curl_json "$API/stats" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['total_anchors'])" 2>/dev/null || echo "0")
check "mainnet anchors > 0" "$([ "$anchors" -gt 0 ] 2>/dev/null && echo ok || echo "$anchors")"

# 3. leaf count
leaves=$(curl_json "$API/stats" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['total_leaves'])" 2>/dev/null || echo "0")
check "mainnet leaves > 0" "$([ "$leaves" -gt 0 ] 2>/dev/null && echo ok || echo "$leaves")"

# 4. offline proof verification from bundled proof material
offline_proof=$("$PYTHON" examples/verify_proof.py examples/proof_bundle_example.json 2>&1 | tail -1 || true)
check "offline proof bundle verifies" "$(echo "$offline_proof" | grep -q "VERIFIED" && echo ok || echo "$offline_proof")"

# 5. memo decode endpoint
memo_fmt=$(curl_json -X POST -H "Content-Type: text/plain; charset=utf-8" --data "5a4150313a30313a30373562303064663238363033386137623366366262373030353464663631333433653334383166626135373935393133353461303032313465396530313962" "$API/memo/decode" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['format'])" 2>/dev/null || echo "error")
check "memo decode returns zap1" "$([ "$memo_fmt" = "zap1" ] && echo ok || echo "$memo_fmt")"

# 6. explorer up
explorer=$(curl -sf -A "$USER_AGENT" -o /dev/null -w "%{http_code}" "https://explorer.frontiercompute.io" 2>/dev/null || echo "000")
if [ "$explorer" = "200" ]; then
  check "explorer reachable" ok
else
  echo "skip  explorer reachable (optional web surface HTTP $explorer)"
fi

# 7. simulator up
sim=$(curl -sf -A "$USER_AGENT" -o /dev/null -w "%{http_code}" "https://simulator.frontiercompute.io" 2>/dev/null || echo "000")
if [ "$sim" = "200" ]; then
  check "simulator reachable" ok
else
  echo "skip  simulator reachable (optional web surface HTTP $sim)"
fi

# 8. crates.io
if command -v cargo > /dev/null 2>&1; then
  crate_ver=$(cargo search zap1-verify --limit 1 2>/dev/null | awk -F '"' '/^zap1-verify =/ {print $2}' || echo "error")
else
  crate_ver=$(curl_json "https://crates.io/api/v1/crates/zap1-verify" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['crate']['max_version'])" 2>/dev/null || echo "error")
fi
check "zap1-verify on crates.io" "$([ -n "$crate_ver" ] && [ "$crate_ver" != "error" ] && echo ok || echo "$crate_ver")"

# 9. events feed
events_count=$(curl_json "$API/events?limit=5" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['total_returned'])" 2>/dev/null || echo "0")
check "events feed returns data" "$([ "$events_count" -gt 0 ] 2>/dev/null && echo ok || echo "$events_count")"

# 10. optional live proof verification for current event, if the deployment exposes it
current_leaf=$(curl_json "$API/events?limit=1" | "$PYTHON" -c "import sys,json; d=json.load(sys.stdin); print(d['events'][0]['leaf_hash'] if d.get('events') else '')" 2>/dev/null || echo "")
if [ -n "$current_leaf" ]; then
  valid=$(curl_json "$API/verify/$current_leaf/check" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin).get('valid'))" 2>/dev/null || echo "skip")
  check "current live proof endpoint verifies" "$([ "$valid" = "True" ] && echo ok || echo "$valid")"
else
  check "current live proof endpoint verifies" "no current leaf"
fi

# 11. crates.io
if command -v cargo > /dev/null 2>&1; then
  memo_crate=$(cargo search zcash-memo-decode --limit 1 2>/dev/null | awk -F '"' '/^zcash-memo-decode =/ {print $2}' || echo "error")
else
  memo_crate=$(curl_json "https://crates.io/api/v1/crates/zcash-memo-decode" | "$PYTHON" -c "import sys,json; print(json.load(sys.stdin)['crate']['max_version'])" 2>/dev/null || echo "error")
fi
check "zcash-memo-decode on crates.io" "$([ -n "$memo_crate" ] && [ "$memo_crate" != "error" ] && echo ok || echo "$memo_crate")"

# 12. local verifier and conformance tests
"$PYTHON" conformance/zip1243_conformance.py >/tmp/zap1_zip1243.out 2>&1
zip_result=$(tail -1 /tmp/zap1_zip1243.out)
check "ZIP-1243 conformance vectors" "$(echo "$zip_result" | grep -q "0 failed" && echo ok || echo "$zip_result")"

"$PYTHON" conformance/check_api.py "$API" >/tmp/zap1_api_check.out 2>&1
api_result=$(tail -1 /tmp/zap1_api_check.out)
check "live API schema check" "$(echo "$api_result" | grep -q "0 fail" && echo ok || echo "$api_result")"

if command -v cargo > /dev/null 2>&1; then
  metadata_result=$(cargo metadata --locked --format-version 1 --no-deps >/tmp/zap1_metadata.out 2>&1 && echo ok || tail -1 /tmp/zap1_metadata.out)
  check "cargo metadata locked" "$metadata_result"

  if cargo test --manifest-path zap1-verify/Cargo.toml --offline >/tmp/zap1_verify_tests.out 2>&1; then
    check "zap1-verify tests pass" ok
  else
    verify_result=$(tail -1 /tmp/zap1_verify_tests.out)
    check "zap1-verify tests pass" "$verify_result"
  fi

  if cargo test --manifest-path zcash-memo-decode/Cargo.toml --offline >/tmp/zap1_memo_tests.out 2>&1; then
    check "zcash-memo-decode tests pass" ok
  else
    memo_result=$(tail -1 /tmp/zap1_memo_tests.out)
    check "zcash-memo-decode tests pass" "$memo_result"
  fi

  if [ "${ZAP1_FULL_RUST_TESTS:-0}" = "1" ]; then
    test_result=$(cargo test --quiet --all-targets 2>&1 | grep -c "FAILED" || true)
    check "full cargo test passes" "$([ "$test_result" = "0" ] && echo ok || echo "$test_result failures")"

    # 13. proof bundle audit
    if [ -f examples/live_ownership_attest_proof.json ]; then
      audit_result=$(cargo run --quiet --bin zap1_audit -- --bundle examples/live_ownership_attest_proof.json 2>&1 | head -1)
      check "zap1_audit verifies proof bundle" "$(echo "$audit_result" | grep -q "proof: ok" && echo ok || echo "$audit_result")"
    fi

    # 14. export -> offline audit loop
    if [ -f examples/demo_audit_package.json ]; then
      export_result=$(cargo run --quiet --bin zap1_audit -- --export examples/demo_audit_package.json 2>&1 | tail -1)
      check "zap1_audit verifies export package" "$(echo "$export_result" | grep -q "0 fail" && echo ok || echo "$export_result")"
    fi

    # 15. schema validator
    if [ -f examples/schema_witness.json ]; then
      schema_result=$(cargo run --quiet --bin zap1_schema -- --witness examples/schema_witness.json 2>&1 | tail -1)
      check "zap1_schema validates witness" "$(echo "$schema_result" | grep -q "0 fail" && echo ok || echo "$schema_result")"
    fi
  else
    echo "skip  full root Rust binary checks (set ZAP1_FULL_RUST_TESTS=1)"
  fi
fi

echo
echo "===================="
echo "$pass pass, $fail fail"
echo "anchors: $anchors | leaves: $leaves | protocol: $protocol"

if [ "$fail" -gt 0 ]; then
  exit 1
fi
