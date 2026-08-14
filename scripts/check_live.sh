#!/usr/bin/env bash
set +x
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

find_python() {
  if [ -n "${PYTHON:-}" ]; then
    printf '%s\n' "$PYTHON"
  elif command -v python3 >/dev/null 2>&1; then
    printf '%s\n' python3
  elif command -v python >/dev/null 2>&1; then
    printf '%s\n' python
  else
    printf '%s\n' "Python 3 is required" >&2
    return 1
  fi
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

run() {
  printf '\n== %s ==\n' "$1"
  shift
  "$@"
}

PYTHON_BIN="$(find_python)"
require_command git
require_command tar

API="${ZAP1_API_BASE:-https://api.frontiercompute.cash}"
API="${API%/}"
EXPECTED_IMAGE_ID="${ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID:-}"
MAX_SYNC_LAG_BLOCKS="${ZAP1_MAX_SYNC_LAG_BLOCKS:-10}"

ADMIN_API_KEY="${ZAP1_ADMIN_API_KEY:-}"
unset ZAP1_ADMIN_API_KEY
case "$ADMIN_API_KEY" in
  ''|*[!A-Za-z0-9._~-]*)
    printf 'ZAP1_ADMIN_API_KEY is required and must use the safe token alphabet.\n' >&2
    exit 1
    ;;
esac

if [ -z "$EXPECTED_IMAGE_ID" ]; then
  printf 'ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID is required from the operator-local pinned-image receipt.\n' >&2
  exit 1
fi

case "$MAX_SYNC_LAG_BLOCKS" in
  ''|*[!0-9]*)
    printf 'ZAP1_MAX_SYNC_LAG_BLOCKS must be a nonnegative integer.\n' >&2
    exit 1
    ;;
esac

DIRTY_STATE="$(git status --porcelain=v1 --untracked-files=all)"
if [ -n "$DIRTY_STATE" ]; then
  printf 'live evaluation requires a clean checkout of one exact commit:\n%s\n' "$DIRTY_STATE" >&2
  exit 1
fi

REVISION="$(git rev-parse --verify HEAD)"
SOURCE_TREE="$(git rev-parse --verify 'HEAD^{tree}')"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/zap1-live-evaluator.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT
ARCHIVE_ROOT="$TMP_ROOT/source"
mkdir -p "$ARCHIVE_ROOT"
git archive --format=tar HEAD | tar -xf - -C "$ARCHIVE_ROOT"
SOURCE_MANIFEST="$("$PYTHON_BIN" scripts/source_manifest.py --root "$ARCHIVE_ROOT")"

"$PYTHON_BIN" - "$REVISION" "$SOURCE_TREE" "$SOURCE_MANIFEST" "$EXPECTED_IMAGE_ID" <<'PY'
import re
import sys

patterns = (
    ("revision", r"[0-9a-f]{40}"),
    ("source tree", r"[0-9a-f]{40}"),
    ("source manifest", r"[0-9a-f]{64}"),
    ("deployment image ID", r"sha256:[0-9a-f]{64}"),
)
for (label, pattern), value in zip(patterns, sys.argv[1:]):
    if re.fullmatch(pattern, value) is None:
        raise SystemExit(f"invalid {label}: {value!r}")
PY

export ZAP1_API_BASE="$API"
export ZAP1_REQUIRE_SOURCE_PARITY="true"
export ZAP1_EXPECTED_SOURCE_REVISION="$REVISION"
export ZAP1_EXPECTED_SOURCE_TREE="$SOURCE_TREE"
export ZAP1_EXPECTED_SOURCE_MANIFEST_SHA256="$SOURCE_MANIFEST"
export ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID="$EXPECTED_IMAGE_ID"
export ZAP1_REQUIRE_FRESH_ANCHOR="true"
export ZAP1_MAX_SYNC_LAG_BLOCKS="$MAX_SYNC_LAG_BLOCKS"

printf 'ZAP1 fail-closed live evaluator\n'
printf 'API: %s\n' "$API"
printf 'Revision: %s\n' "$REVISION"
printf 'Source tree: %s\n' "$SOURCE_TREE"
printf 'Source manifest: %s\n' "$SOURCE_MANIFEST"
printf 'Expected image declaration from operator-local receipt: %s\n' "$EXPECTED_IMAGE_ID"
printf 'Maximum scanner sync lag: %s blocks\n' "$MAX_SYNC_LAG_BLOCKS"

run "evaluator privacy policy self-test" \
  "$PYTHON_BIN" conformance/check_api.py --self-test
authenticated_api_check() {
  ZAP1_REQUIRE_AUTHENTICATED_ADMIN_CHECKS=true \
    ZAP1_ADMIN_API_KEY="$ADMIN_API_KEY" \
    "$PYTHON_BIN" conformance/check_api.py "$API"
}
run "API schema and declared runtime metadata parity" authenticated_api_check
unset ADMIN_API_KEY
run "anchor liveness" \
  "$PYTHON_BIN" scripts/check_anchor_liveness.py

LIVE_BUNDLE="$TMP_ROOT/current-proof.json"
run "fetch current proof bundle" \
  "$PYTHON_BIN" - "$API" "$LIVE_BUNDLE" <<'PY'
import json
import re
import sys
import urllib.request
from pathlib import Path

api = sys.argv[1].rstrip("/")
bundle_path = Path(sys.argv[2])
headers = {"Accept": "application/json", "User-Agent": "zap1-live-evaluator/1.0"}
forbidden_preimage_fields = {
    "wallet_hash", "serial_number", "serial", "old_wallet_hash", "new_wallet_hash",
    "contract_sha256", "facility_id", "month", "year", "amount_zat",
    "validator_id", "epoch", "proposal_id", "proposal_hash", "vote_commitment",
    "result_hash", "agent_id", "pubkey_hash", "model_hash", "policy_hash",
    "policy_version", "rules_hash", "action_type", "input_hash", "output_hash",
}


def fetch(path):
    request = urllib.request.Request(f"{api}{path}", headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        content_type = response.headers.get("Content-Type", "")
        body = response.read()
    if "json" not in content_type.lower():
        raise RuntimeError(f"{path} returned {content_type or 'unknown content type'}")
    return json.loads(body), body


def preimage_leaks(value, path="$"):
    leaks = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key in forbidden_preimage_fields:
                leaks.append(child_path)
            leaks.extend(preimage_leaks(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            leaks.extend(preimage_leaks(child, f"{path}[{index}]"))
    return leaks


events, _ = fetch("/events?limit=1")
event_leaks = preimage_leaks(events)
if event_leaks:
    raise RuntimeError("public event feed disclosed payload preimages: " + ", ".join(event_leaks[:4]))
rows = events.get("events")
if not isinstance(rows, list) or len(rows) != 1:
    raise RuntimeError("/events?limit=1 did not return exactly one current event")
leaf_hash = rows[0].get("leaf_hash")
if re.fullmatch(r"[0-9a-f]{64}", leaf_hash or "") is None:
    raise RuntimeError("current event leaf_hash is not canonical lowercase hex")

bundle, raw_bundle = fetch(f"/verify/{leaf_hash}/proof.json")
bundle_leaks = preimage_leaks(bundle)
if bundle_leaks:
    raise RuntimeError("public proof bundle disclosed payload preimages: " + ", ".join(bundle_leaks[:4]))
if bundle.get("leaf", {}).get("hash") != leaf_hash:
    raise RuntimeError("proof bundle leaf does not match the requested current leaf")
if bundle.get("leaf", {}).get("event_type_authentication") != "unverified_server_metadata_without_disclosed_witness":
    raise RuntimeError("proof bundle does not label event type as unverified server metadata")
anchor = bundle.get("anchor", {})
if re.fullmatch(r"[0-9a-f]{64}", anchor.get("txid") or "") is None:
    raise RuntimeError("current proof bundle has no canonical transaction reference")
if type(anchor.get("height")) is not int or anchor["height"] <= 0:
    raise RuntimeError("current proof bundle has no confirmed anchor height")

bundle_path.write_bytes(raw_bundle)
print(leaf_hash)
PY

run "independent verification of the fetched current bundle" \
  "$PYTHON_BIN" examples/verify_proof.py "$LIVE_BUNDLE"

printf '\nPASS: API declarations match this checkout and expected image ID, scanner health policy passes, anchor policy is live, and the current bundle verifies\n'
printf 'LIMITATION: /build/info is service-declared metadata. This gate does not remotely attest deployed bytes. The expected image ID must come from the operator-local pinned-image receipt.\n'
