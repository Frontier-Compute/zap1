#!/usr/bin/env bash
set -euo pipefail

# ZAP1 Quickstart - see the whole protocol in 60 seconds
# No install needed. Just curl and python3.

API="${ZAP1_API_BASE:-https://api.frontiercompute.cash}"
GREEN='\033[0;32m'
GOLD='\033[0;33m'
DIM='\033[0;90m'
RST='\033[0m'

echo ""
echo -e "${GOLD}ZAP1 Quickstart${RST}"
echo -e "${DIM}Attestation protocol for Zcash. Live on mainnet.${RST}"
echo ""

# 1. Protocol info
echo -e "${GREEN}1. Protocol info${RST}"
curl -sf "$API/protocol/info" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'   Protocol: {d[\"protocol\"]} {d[\"version\"]}')
print(f'   Event types: {d[\"deployed_types\"]}')
print(f'   Hash: {d[\"hash_function\"]}')
"
echo ""

# 2. Anchor history
echo -e "${GREEN}2. On-chain anchors${RST}"
curl -sf "$API/anchor/history" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'   {d[\"total\"]} anchors on Zcash mainnet')
for a in d['anchors'][-2:]:
    print(f'   Block {a[\"height\"]}: {a[\"leaf_count\"]} leaves, txid {a[\"txid\"][:16]}...')
"
echo ""

# 3. Verify a bundled proof without trusting the live server
echo -e "${GREEN}3. Verify a bundled proof locally${RST}"
python3 "$(dirname "$0")/verify_proof.py" "$(dirname "$0")/proof_bundle_example.json" | sed 's/^/   /'
echo ""

# 4. Decode a memo
echo -e "${GREEN}4. Decode a ZAP1 memo${RST}"
MEMO="5a4150313a30393a62303962313662656363323030343763666335623937363733393034643364663937383335356262383531303832623362653466333666363862396561636631"
curl -sf -X POST "$API/memo/decode" -d "$MEMO" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'   Format: {d[\"format\"]}')
print(f'   Event: {d.get(\"event_label\", \"-\")}')
print(f'   Payload: {d.get(\"payload_hash\", \"-\")[:32]}...')
"
echo ""

# 5. Recent events
echo -e "${GREEN}5. Recent events${RST}"
curl -sf "$API/events?limit=3" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for e in d['events']:
    print(f'   {e[\"event_type\"]}: {e.get(\"description\", \"-\")} [{e[\"leaf_hash\"][:16]}...]')
"
echo ""

echo -e "${GOLD}Next steps:${RST}"
echo "   Verify SDK:    cargo add zap1-verify"
echo "   JS SDK:        npm i @frontiercompute/zap1"
echo "   Memo decoder:  cargo add zcash-memo-decode"
echo "   Deploy:        bash scripts/operator-setup.sh myop 3081"
echo "   Full docs:     https://frontiercompute.io/sdk.html"
echo ""
