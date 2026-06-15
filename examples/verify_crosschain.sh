#!/usr/bin/env bash
set -euo pipefail

# Verify a ZAP1 Zcash attestation on Ethereum Sepolia.
# Fetches a proof from the ZAP1 API, then calls the on-chain verifier.
# Requires: curl, python3, cast (foundry)

API="${ZAP1_API_BASE:-https://api.frontiercompute.cash}"
VERIFIER="0x3fD65055A8dC772C848E7F227CE458803005C87F"
RPC="https://ethereum-sepolia-rpc.publicnode.com"

RED='\033[0;31m'
GRN='\033[0;32m'
CYN='\033[0;36m'
RST='\033[0m'

echo "ZAP1 cross-chain verification"
echo "============================="
echo ""

# 1. Fetch a proof from Zcash mainnet. If no leaf is supplied, use the
# deployment's current event instead of a historical fixture leaf.
if [ $# -gt 0 ]; then
    LEAF="$1"
else
    LEAF=$(curl -sf "$API/events?limit=1" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['events'][0]['leaf_hash'] if d.get('events') else '')")
fi
if [ -z "$LEAF" ]; then
    echo -e "${RED}FAIL${RST}  Could not discover a current leaf from API"
    exit 1
fi
echo -e "${CYN}Zcash${RST}  Fetching proof for ${LEAF:0:16}..."

PROOF=$(curl -sf "$API/verify/$LEAF/proof.json")
if [ -z "$PROOF" ]; then
    echo -e "${RED}FAIL${RST}  Could not fetch proof from API"
    exit 1
fi

LEAF_HASH=$(echo "$PROOF" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['leaf']['hash'])")
ROOT=$(echo "$PROOF" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['root']['hash'])")
ANCHOR_TXID=$(echo "$PROOF" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['anchor']['txid'])")
ANCHOR_HEIGHT=$(echo "$PROOF" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['anchor']['height'])")
EVENT_TYPE=$(echo "$PROOF" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['leaf']['event_type'])")

# Extract siblings and positions
SIBLINGS=$(echo "$PROOF" | python3 -c "
import json,sys
d = json.load(sys.stdin)
siblings = ['0x' + s['hash'] for s in d['proof']]
print('[' + ','.join(siblings) + ']')
")
POSITIONS=$(echo "$PROOF" | python3 -c "
import json,sys
d = json.load(sys.stdin)
pos = 0
for i, s in enumerate(d['proof']):
    if s['position'] == 'left':
        pos |= (1 << i)
print(pos)
")

echo -e "${CYN}Zcash${RST}  Leaf:   $LEAF_HASH"
echo -e "${CYN}Zcash${RST}  Type:   $EVENT_TYPE"
echo -e "${CYN}Zcash${RST}  Root:   $ROOT"
echo -e "${CYN}Zcash${RST}  Anchor: block $ANCHOR_HEIGHT (txid ${ANCHOR_TXID:0:16}...)"
echo -e "${CYN}Zcash${RST}  Proof:  $(echo "$PROOF" | python3 -c "import json,sys; print(len(json.load(sys.stdin)['proof']))" ) siblings"
echo ""

# 2. Verify on Ethereum Sepolia
echo -e "${CYN}Ethereum${RST}  Calling ZAP1Verifier at ${VERIFIER:0:10}..."

# Check anchor registration
ANCHOR_CHECK=$(cast call "$VERIFIER" \
    "isAnchorRegistered(bytes32)(bool,uint64)" \
    "0x$ROOT" \
    --rpc-url "$RPC" 2>&1)

ANCHOR_REGISTERED=$(echo "$ANCHOR_CHECK" | head -1)

# Verify proof
VALID=$(cast call "$VERIFIER" \
    "verifyProofStateless(bytes32,bytes32[],uint256,bytes32)(bool)" \
    "0x$LEAF_HASH" \
    "$SIBLINGS" \
    "$POSITIONS" \
    "0x$ROOT" \
    --rpc-url "$RPC" 2>&1)

echo ""
echo "============================="
if [ "$VALID" = "true" ]; then
    echo -e "${GRN}PROOF VALID${RST}"
else
    echo -e "${RED}PROOF INVALID${RST}"
fi
echo -e "Anchor registered: $ANCHOR_REGISTERED"
echo -e "Verified on:       Ethereum Sepolia"
echo -e "Contract:          $VERIFIER"
echo -e "Etherscan:         https://sepolia.etherscan.io/address/$VERIFIER"
