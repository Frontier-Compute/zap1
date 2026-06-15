#!/usr/bin/env bash
set -euo pipefail

# 00zeven Agent Demo
# Runs a full agent lifecycle: register, commit policy, take actions, verify proofs.
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
MODEL_HASH=$(echo -n "gpt-5.4-xhigh-2026" | sha256sum | cut -d' ' -f1)
POLICY_HASH=$(echo -n "spend_limit:1000;approved_tools:search,browser,shell" | sha256sum | cut -d' ' -f1)
PUBKEY_HASH=$(echo -n "$AGENT_ID-pubkey" | sha256sum | cut -d' ' -f1)

echo ""
echo -e "${GLD}00zeven Agent Demo${RST}"
echo -e "${DIM}Autonomous agent with shielded wallet and provable track record${RST}"
echo ""

# 1. Register
echo -e "${CYN}1. Registering agent${RST}"
echo -e "   ${DIM}agent: $AGENT_ID${RST}"
REG=$(post "{
    \"event_type\": \"AGENT_REGISTER\",
    \"wallet_hash\": \"$AGENT_ID\",
    \"agent_id\": \"$AGENT_ID\",
    \"pubkey_hash\": \"$PUBKEY_HASH\",
    \"model_hash\": \"$MODEL_HASH\",
    \"policy_hash\": \"$POLICY_HASH\"
}")
REG_LEAF=$(echo "$REG" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
echo -e "   ${GRN}registered${RST} leaf: ${REG_LEAF:0:16}..."
echo ""

# 2. Commit policy
echo -e "${CYN}2. Committing policy${RST}"
RULES_HASH=$(echo -n "max_spend_per_tx:100;require_approval_above:500;tools:search,browser" | sha256sum | cut -d' ' -f1)
POL=$(post "{
    \"event_type\": \"AGENT_POLICY\",
    \"wallet_hash\": \"$AGENT_ID\",
    \"agent_id\": \"$AGENT_ID\",
    \"policy_version\": 1,
    \"rules_hash\": \"$RULES_HASH\"
}")
POL_LEAF=$(echo "$POL" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
echo -e "   ${GRN}policy committed${RST} v1 leaf: ${POL_LEAF:0:16}..."
echo ""

# 3. Take actions
echo -e "${CYN}3. Agent taking actions${RST}"
for i in 1 2 3; do
    INPUT=$(echo -n "search query $i: zcash mining pools" | sha256sum | cut -d' ' -f1)
    OUTPUT=$(echo -n "result $i: 5 pools found, hashrate distributed" | sha256sum | cut -d' ' -f1)
    ACT=$(post "{
        \"event_type\": \"AGENT_ACTION\",
        \"wallet_hash\": \"$AGENT_ID\",
        \"agent_id\": \"$AGENT_ID\",
        \"action_type\": \"web_search\",
        \"input_hash\": \"$INPUT\",
        \"output_hash\": \"$OUTPUT\"
    }")
    ACT_LEAF=$(echo "$ACT" | python3 -c "import json,sys; print(json.load(sys.stdin)['leaf_hash'])")
    echo -e "   ${GRN}action $i${RST} (web_search) leaf: ${ACT_LEAF:0:16}..."
done
echo ""

# 4. Verify proofs
echo -e "${CYN}4. Verifying agent proofs${RST}"
echo -e "   ${DIM}checking registration proof...${RST}"
CHECK=$(curl -sf "$API/verify/$REG_LEAF/check")
VALID=$(echo "$CHECK" | python3 -c "import json,sys; print(json.load(sys.stdin).get('valid', False))")
echo -e "   registration: ${GRN}$VALID${RST}"

echo -e "   ${DIM}checking policy proof...${RST}"
CHECK=$(curl -sf "$API/verify/$POL_LEAF/check")
VALID=$(echo "$CHECK" | python3 -c "import json,sys; print(json.load(sys.stdin).get('valid', False))")
echo -e "   policy: ${GRN}$VALID${RST}"
echo ""

# 5. Export proof bundle
echo -e "${CYN}5. Exporting proof bundle${RST}"
BUNDLE=$(curl -sf "$API/verify/$REG_LEAF/proof.json")
ROOT=$(echo "$BUNDLE" | python3 -c "import json,sys; print(json.load(sys.stdin)['root']['hash'])")
echo -e "   root: ${ROOT:0:24}..."
echo -e "   verify: $API/verify/$REG_LEAF"
echo ""

# 6. Agent lifecycle view
echo -e "${CYN}6. Agent lifecycle${RST}"
EVENTS=$(curl -sf "$API/lifecycle/$AGENT_ID")
COUNT=$(echo "$EVENTS" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('events', [])))")
echo -e "   ${GRN}$COUNT events${RST} for agent $AGENT_ID"
echo ""

echo -e "${GLD}Demo complete.${RST}"
echo ""
echo "Agent: $AGENT_ID"
echo "Events: 5 (1 register + 1 policy + 3 actions)"
echo "All proofs verifiable at: $API/verify/{leaf_hash}/check"
echo ""
echo "This agent has a shielded wallet (Orchard) and a provable track record (ZAP1)."
echo "Verify this proof independently: python3 examples/verify_proof.py $REG_LEAF --api-base $API"
