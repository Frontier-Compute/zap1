#!/usr/bin/env bash
set -euo pipefail

# Governance attestation demo.
# Shows the full cycle: propose -> vote -> tally -> verify.
# Runs against the live API. Takes an API key as argument.

API="https://pay.frontiercompute.io"
KEY="${1:?Usage: $0 <api_key>}"
GREEN='\033[0;32m'
GOLD='\033[0;33m'
DIM='\033[0;90m'
RST='\033[0m'

echo -e "${GOLD}ZAP1 Governance Demo${RST}"
echo -e "${DIM}Propose, vote, tally - all attested on Zcash mainnet.${RST}"
echo ""

# 1. Create proposal
PROPOSAL_ID="demo-proposal-$(date +%s)"
PROPOSAL_HASH=$(echo -n "Should ZAP1 adopt ZIP 302 as the memo container?" | sha256sum | cut -d' ' -f1)

echo -e "${GREEN}1. Creating proposal${RST}"
echo "   ID: $PROPOSAL_ID"
echo "   Hash: ${PROPOSAL_HASH:0:32}..."

RESULT=$(curl -sf -X POST "$API/event" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d "{\"event_type\":\"GOVERNANCE_PROPOSAL\",\"wallet_hash\":\"dao_operator\",\"proposal_id\":\"$PROPOSAL_ID\",\"proposal_hash\":\"$PROPOSAL_HASH\"}")
PROPOSAL_LEAF=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
echo "   Leaf: ${PROPOSAL_LEAF:0:24}..."
echo ""

# 2. Cast votes (3 voters)
echo -e "${GREEN}2. Casting votes${RST}"
VOTE_LEAVES=""
for voter in alice bob carol; do
  COMMITMENT=$(echo -n "${voter}_yes_${PROPOSAL_ID}" | sha256sum | cut -d' ' -f1)
  RESULT=$(curl -sf -X POST "$API/event" \
    -H "Authorization: Bearer $KEY" \
    -H "Content-Type: application/json" \
    -d "{\"event_type\":\"GOVERNANCE_VOTE\",\"wallet_hash\":\"${voter}\",\"proposal_id\":\"$PROPOSAL_ID\",\"vote_commitment\":\"$COMMITMENT\"}")
  LEAF=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
  echo "   $voter voted -> ${LEAF:0:24}..."
  VOTE_LEAVES="$VOTE_LEAVES $LEAF"
done
echo ""

# 3. Record result
RESULT_HASH=$(echo -n "3_yes_0_no_proposal_${PROPOSAL_ID}" | sha256sum | cut -d' ' -f1)
echo -e "${GREEN}3. Recording result${RST}"
RESULT=$(curl -sf -X POST "$API/event" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d "{\"event_type\":\"GOVERNANCE_RESULT\",\"wallet_hash\":\"dao_operator\",\"proposal_id\":\"$PROPOSAL_ID\",\"result_hash\":\"$RESULT_HASH\"}")
RESULT_LEAF=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
echo "   Result: 3 yes, 0 no -> ${RESULT_LEAF:0:24}..."
echo ""

# 4. Verify
echo -e "${GREEN}4. Verifying proposal attestation${RST}"
CHECK=$(curl -sf "$API/verify/$PROPOSAL_LEAF/check")
VALID=$(echo "$CHECK" | python3 -c "import json,sys; print(json.load(sys.stdin).get('valid', False))")
echo "   Proposal leaf valid: $VALID"

echo -e "${GREEN}   Verifying vote attestations${RST}"
for leaf in $VOTE_LEAVES; do
  CHECK=$(curl -sf "$API/verify/$leaf/check")
  VALID=$(echo "$CHECK" | python3 -c "import json,sys; print(json.load(sys.stdin).get('valid', False))")
  echo "   Vote ${leaf:0:16}... valid: $VALID"
done

echo ""
echo -e "${GOLD}All events committed to Merkle tree.${RST}"
echo -e "${DIM}Anchor the tree root to make them permanently verifiable on Zcash mainnet.${RST}"
echo ""
echo "Receipt URLs:"
echo "  Proposal: https://frontiercompute.io/receipt.html?leaf=$PROPOSAL_LEAF"
echo "  Result:   https://frontiercompute.io/receipt.html?leaf=$RESULT_LEAF"
