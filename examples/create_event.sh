#!/usr/bin/env bash
# Submit an operator-issued synthetic event claim to an explicitly selected API.
# Usage: ./create_event.sh <api_key>
# Requires: curl, jq (optional)
set -euo pipefail
API="${ZAP1_API_BASE:?Set ZAP1_API_BASE explicitly. No default write target is provided.}"
KEY="${1:?Usage: $0 <api_key>}"
SUBJECT=$(printf 'zap1-create-event-demo-v1' | sha256sum | cut -d' ' -f1)
curl -fsS -X POST "$API/event" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d "{\"event_type\":\"DEPLOYMENT\",\"wallet_hash\":\"$SUBJECT\",\"serial_number\":\"synthetic-example-001\",\"facility_id\":\"synthetic-example-dc-01\"}" | python3 -m json.tool
echo "Submitted an operator-issued synthetic claim. The response does not prove deployment, identity, or root publication." >&2
