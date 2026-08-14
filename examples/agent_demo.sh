#!/usr/bin/env bash
set -euo pipefail

# Synthetic agent-event receipt demo
# Submits operator-issued demo claims, then checks their Merkle responses.
# Requires: curl, python3, API key

API="${ZAP1_API:-http://127.0.0.1:3080}"
KEY="${ZAP1_API_KEY:-}"

GRN='\033[0;32m'
GLD='\033[0;33m'
CYN='\033[0;36m'
DIM='\033[0;90m'
RST='\033[0m'

if [ -z "$KEY" ]; then
    echo "Set ZAP1_API_KEY to run write operations."
    echo "Usage: ZAP1_API_KEY=your-key bash examples/agent_demo.sh"
    exit 1
fi

post() {
    curl -sf -X POST "$API/event" \
        -H "Authorization: Bearer $KEY" \
        -H "Content-Type: application/json" \
        -d "$1"
}

AGENT_ID="agent-00zeven-$(date +%s)"
SUBJECT_ID=$(echo -n "zap1-demo-subject-v1:$AGENT_ID" | sha256sum | cut -d' ' -f1)
MODEL_HASH=$(echo -n "demo-model-build-v1" | sha256sum | cut -d' ' -f1)
POLICY_HASH=$(echo -n "spend_limit:1000;approved_tools:search,browser,shell" | sha256sum | cut -d' ' -f1)
PUBKEY_HASH=$(echo -n "$AGENT_ID-pubkey" | sha256sum | cut -d' ' -f1)

echo ""
echo -e "${GLD}Synthetic agent-event receipt demo${RST}"
echo -e "${DIM}Operator-issued fixture claims. No agent, wallet, model, policy, or action is authenticated.${RST}"
echo ""

# 1. Submit register claim
echo -e "${CYN}1. Submitting register claim${RST}"
echo -e "   ${DIM}fixture agent_id: $AGENT_ID${RST}"
REG=$(post "{
    \"event_type\": \"AGENT_REGISTER\",
    \"wallet_hash\": \"$SUBJECT_ID\",
    \"agent_id\": \"$AGENT_ID\",
    \"pubkey_hash\": \"$PUBKEY_HASH\",
    \"model_hash\": \"$MODEL_HASH\",
    \"policy_hash\": \"$POLICY_HASH\"
}")
REG_LEAF=$(echo "$REG" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
echo -e "   ${GRN}register claim submitted${RST} leaf: ${REG_LEAF:0:16}..."
echo ""

# 2. Submit policy claim
echo -e "${CYN}2. Submitting policy claim${RST}"
RULES_HASH=$(echo -n "max_spend_per_tx:100;require_approval_above:500;tools:search,browser" | sha256sum | cut -d' ' -f1)
POL=$(post "{
    \"event_type\": \"AGENT_POLICY\",
    \"wallet_hash\": \"$SUBJECT_ID\",
    \"agent_id\": \"$AGENT_ID\",
    \"policy_version\": 1,
    \"rules_hash\": \"$RULES_HASH\"
}")
POL_LEAF=$(echo "$POL" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
echo -e "   ${GRN}policy claim submitted${RST} v1 leaf: ${POL_LEAF:0:16}..."
echo ""

# 3. Submit synthetic action claims
echo -e "${CYN}3. Submitting synthetic action claims${RST}"
for i in 1 2 3; do
    INPUT=$(echo -n "search query $i: zcash mining pools" | sha256sum | cut -d' ' -f1)
    OUTPUT=$(echo -n "result $i: 5 pools found, hashrate distributed" | sha256sum | cut -d' ' -f1)
    ACT=$(post "{
        \"event_type\": \"AGENT_ACTION\",
        \"wallet_hash\": \"$SUBJECT_ID\",
        \"agent_id\": \"$AGENT_ID\",
        \"action_type\": \"web_search\",
        \"input_hash\": \"$INPUT\",
        \"output_hash\": \"$OUTPUT\"
    }")
    ACT_LEAF=$(echo "$ACT" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
    echo -e "   ${GRN}synthetic action claim $i${RST} (web_search) leaf: ${ACT_LEAF:0:16}..."
done
echo ""

# 4. Read server bundle-consistency results
echo -e "${CYN}4. Reading server bundle-consistency results${RST}"
echo -e "   ${DIM}checking register claim response...${RST}"
CHECK=$(curl -sf "$API/verify/$REG_LEAF/check")
VALID=$(echo "$CHECK" | python3 -c "import json,sys; print(json.load(sys.stdin).get('valid', False))")
echo -e "   register claim server result: ${GRN}$VALID${RST}"

echo -e "   ${DIM}checking policy claim response...${RST}"
CHECK=$(curl -sf "$API/verify/$POL_LEAF/check")
VALID=$(echo "$CHECK" | python3 -c "import json,sys; print(json.load(sys.stdin).get('valid', False))")
echo -e "   policy claim server result: ${GRN}$VALID${RST}"
echo ""

# 5. Export proof bundle
echo -e "${CYN}5. Exporting proof bundle${RST}"
BUNDLE=$(curl -sf "$API/verify/$REG_LEAF/proof.json")
ROOT=$(echo "$BUNDLE" | python3 -c "import json,sys; print(json.load(sys.stdin)['root']['hash'])")
echo -e "   root: ${ROOT:0:24}..."
echo -e "   verify: $API/verify/$REG_LEAF"
echo ""

# 6. Authenticated subject view
echo -e "${CYN}6. Authenticated subject view${RST}"
EVENTS=$(curl -sf \
    -H "Authorization: Bearer $KEY" \
    "$API/lifecycle/$SUBJECT_ID")
COUNT=$(echo "$EVENTS" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('events', [])))")
echo -e "   ${GRN}$COUNT operator-issued events${RST} for demo subject ${SUBJECT_ID:0:16}..."
echo ""

echo -e "${GLD}Demo complete.${RST}"
echo ""
echo "Fixture agent_id: $AGENT_ID"
echo "Submitted claims: 5 (1 register + 1 policy + 3 actions)"
echo "Merkle response endpoint: $API/verify/{leaf_hash}/check"
echo ""
echo "This demonstrates authenticated event submission and bundle consistency only."
echo "It does not prove an agent, wallet, model, policy, action, event label, root publication, or memo binding."
echo "Check bundle consistency locally: python3 examples/verify_proof.py $REG_LEAF --api-base $API"
