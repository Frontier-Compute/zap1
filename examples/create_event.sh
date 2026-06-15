#!/usr/bin/env bash
# Create a ZAP1 lifecycle event on the live API.
# Usage: ./create_event.sh <api_key>
# Requires: curl, jq (optional)
set -euo pipefail
API="${ZAP1_API_BASE:-https://api.frontiercompute.cash}"
KEY="${1:?Usage: $0 <api_key>}"
curl -s -X POST "$API/event" \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"event_type":"DEPLOYMENT","wallet_hash":"example_wallet","serial_number":"example-001","facility_id":"example-dc-01"}' | python3 -m json.tool
