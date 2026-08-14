#!/usr/bin/env bash
set -euo pipefail

# ZAP1 Quickstart
# Run from an exact checkout. Requires curl, python3, and sed.

API="${ZAP1_API_BASE:-https://api.frontiercompute.cash}"
GREEN='\033[0;32m'
GOLD='\033[0;33m'
DIM='\033[0;90m'
RST='\033[0m'

echo ""
echo -e "${GOLD}ZAP1 Quickstart${RST}"
echo -e "${DIM}Attestation protocol for Zcash. API: $API${RST}"
echo ""

# 1. Protocol info
echo -e "${GREEN}1. Protocol info${RST}"
curl -sf "$API/protocol/info" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'   Protocol: {d[\"protocol\"]} {d[\"version\"]}')
print(f'   Defined event types: {d[\"defined_types\"]}')
print(f'   Hash: {d[\"hash_function\"]}')
"
echo ""

# 2. Recorded anchor references
echo -e "${GREEN}2. Recorded anchor references${RST}"
curl -sf "$API/anchor/history" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'   {d[\"total\"]} API-recorded transaction references')
for a in d['anchors'][-2:]:
    print(f'   Block {a[\"height\"]}: {a[\"leaf_count\"]} leaves, txid {a[\"txid\"][:16]}...')
"
echo -e "${DIM}   These API records do not by themselves prove transaction existence or encrypted memo contents.${RST}"
echo ""

# 3. Verify a bundled proof without trusting the live server
echo -e "${GREEN}3. Verify a bundled proof locally${RST}"
python3 "$(dirname "$0")/verify_proof.py" "$(dirname "$0")/proof_bundle_example.json" | sed 's/^/   /'
echo ""

# 4. Decode a memo
echo -e "${GREEN}4. Decode a ZAP1 memo${RST}"
MEMO="5a4150313a30393a62303962313662656363323030343763666335623937363733393034643364663937383335356262383531303832623362653466333666363862396561636631"
curl -sf -X POST -H "Content-Type: text/plain" "$API/memo/decode" -d "$MEMO" | python3 -c "
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
    print(f'   claimed type {e[\"event_type\"]}: {e.get(\"description\", \"-\")} [{e[\"leaf_hash\"][:16]}...]')
"
echo -e "${DIM}   Public event labels are operator metadata unless a typed witness is separately disclosed and recomputed.${RST}"
echo ""

echo -e "${GOLD}Next steps:${RST}"
echo "   Legacy SDK:    cargo add zap1-verify@0.2.1  # legacy raw-root rules only"
echo "   Current SDK:   use ./zap1-verify from this exact checkout; 0.3.0 is unpublished"
echo "   JS verifier:   @frontiercompute/zap1@0.2.1 supports count-bound v2 with gated legacy"
echo "   Memo decoder:  cargo add zcash-memo-decode@0.1.1  # labels only 0x01-0x0C"
echo "   Current decode: use ./zcash-memo-decode; 0.1.2 is unpublished"
echo "   Deploy:        read OPERATOR_GUIDE.md for the receipt-bound image flow"
echo "   Full docs:     https://frontiercompute.io/sdk.html"
echo ""
