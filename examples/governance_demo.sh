#!/usr/bin/env bash
set -euo pipefail

# Synthetic governance-event receipt demo.
# Submits operator-issued proposal, vote, and result claims.

API="${ZAP1_API_BASE:?Set ZAP1_API_BASE explicitly. No default write target is provided.}"
KEY="${1:?Usage: $0 <api_key>}"
GREEN='\033[0;32m'
GOLD='\033[0;33m'
DIM='\033[0;90m'
RST='\033[0m'

echo -e "${GOLD}ZAP1 Governance Demo${RST}"
echo -e "${DIM}Synthetic operator-issued claims. No voter, tally, governance process, or chain publication is authenticated.${RST}"
echo ""

# 1. Create proposal
PROPOSAL_ID="demo-proposal-$(date +%s)"
PROPOSAL_HASH=$(echo -n "Should ZAP1 adopt ZIP 302 as the memo container?" | sha256sum | cut -d' ' -f1)

echo -e "${GREEN}1. Submitting proposal claim${RST}"
echo "   ID: $PROPOSAL_ID"
echo "   Hash: ${PROPOSAL_HASH:0:32}..."

RESULT=$(curl -sf -X POST "$API/event" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d "{\"event_type\":\"GOVERNANCE_PROPOSAL\",\"wallet_hash\":\"$(printf 'zap1-governance-demo-v1:operator' | sha256sum | cut -d' ' -f1)\",\"proposal_id\":\"$PROPOSAL_ID\",\"proposal_hash\":\"$PROPOSAL_HASH\"}")
PROPOSAL_LEAF=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
echo "   Leaf: ${PROPOSAL_LEAF:0:24}..."
echo ""

# 2. Submit synthetic vote claims
echo -e "${GREEN}2. Submitting synthetic vote claims${RST}"
VOTE_LEAVES=""
for voter in alice bob carol; do
  VOTER_SUBJECT=$(printf 'zap1-governance-demo-v1:%s' "$voter" | sha256sum | cut -d' ' -f1)
  COMMITMENT=$(echo -n "${voter}_yes_${PROPOSAL_ID}" | sha256sum | cut -d' ' -f1)
  RESULT=$(curl -sf -X POST "$API/event" \
    -H "Authorization: Bearer $KEY" \
    -H "Content-Type: application/json" \
    -d "{\"event_type\":\"GOVERNANCE_VOTE\",\"wallet_hash\":\"$VOTER_SUBJECT\",\"proposal_id\":\"$PROPOSAL_ID\",\"vote_commitment\":\"$COMMITMENT\"}")
  LEAF=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
  echo "   $voter fixture submitted -> ${LEAF:0:24}..."
  VOTE_LEAVES="$VOTE_LEAVES $LEAF"
done
echo ""

# 3. Submit result claim
RESULT_HASH=$(echo -n "3_yes_0_no_proposal_${PROPOSAL_ID}" | sha256sum | cut -d' ' -f1)
echo -e "${GREEN}3. Submitting result claim${RST}"
RESULT=$(curl -sf -X POST "$API/event" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d "{\"event_type\":\"GOVERNANCE_RESULT\",\"wallet_hash\":\"$(printf 'zap1-governance-demo-v1:operator' | sha256sum | cut -d' ' -f1)\",\"proposal_id\":\"$PROPOSAL_ID\",\"result_hash\":\"$RESULT_HASH\"}")
RESULT_LEAF=$(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
echo "   Synthetic result claim: 3 yes, 0 no -> ${RESULT_LEAF:0:24}..."
echo ""

# 4. Verify
echo -e "${GREEN}4. Reading server bundle-consistency results${RST}"
CHECK=$(curl -sf "$API/verify/$PROPOSAL_LEAF/check")
VALID=$(echo "$CHECK" | python3 -c "import json,sys; print(json.load(sys.stdin).get('valid', False))")
echo "   Proposal bundle consistency reported by server: $VALID"

echo -e "${GREEN}   Reading vote bundle-consistency results${RST}"
for leaf in $VOTE_LEAVES; do
  CHECK=$(curl -sf "$API/verify/$leaf/check")
  VALID=$(echo "$CHECK" | python3 -c "import json,sys; print(json.load(sys.stdin).get('valid', False))")
  echo "   Vote ${leaf:0:16}... server result: $VALID"
done

echo ""
echo -e "${GOLD}Synthetic claims were submitted to $API.${RST}"
echo -e "${DIM}Verify bundle consistency locally. This demo does not prove voters, votes, tally truth, transaction existence, root publication, or encrypted memo binding.${RST}"
echo ""
echo "Bundle endpoints:"
echo "  Proposal: $API/verify/$PROPOSAL_LEAF/proof.json"
echo "  Result:   $API/verify/$RESULT_LEAF/proof.json"
