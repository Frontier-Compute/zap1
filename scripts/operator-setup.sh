#!/usr/bin/env bash
set -euo pipefail
umask 077

# Generate a scanning/manual-anchor ZAP1 operator deployment config.
# Usage: ./scripts/operator-setup.sh <operator-name> [port] [build-receipt]
# The caller must provide wallet inputs and its scan birthday height.

RAW_OPERATOR=${1:-}
PORT=${2:-3081}
RECEIPT_PATH=${3:-${ZAP1_BUILD_RECEIPT:-}}

if [ -z "$RAW_OPERATOR" ]; then
    echo "Usage: $0 <operator-name> [port] [build-receipt]"
    echo "Example: $0 acme 3081 /secure/zap1-build-receipt.env"
    exit 1
fi

# Sanitize operator name
OPERATOR=$(echo "$RAW_OPERATOR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
if [ -z "$OPERATOR" ]; then
    echo "Error: operator name has no permitted characters"
    exit 1
fi
case "$PORT" in
    *[!0-9]*|'')
        echo "Error: port must be an integer from 1 to 65535"
        exit 1
        ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    echo "Error: port must be an integer from 1 to 65535"
    exit 1
fi
OUTDIR="operators/$OPERATOR"

if [ -d "$OUTDIR" ]; then
    echo "Error: $OUTDIR already exists"
    exit 1
fi

if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
    echo "Error: operator setup requires a clean checkout of one exact commit"
    exit 1
fi

if [ -z "$RECEIPT_PATH" ] || [ ! -f "$RECEIPT_PATH" ] || [ ! -f "$RECEIPT_PATH.sha256" ]; then
    echo "Error: pass the build receipt emitted by scripts/build_image.sh, with its .sha256 sidecar"
    exit 1
fi
RECEIPT_DIR=$(cd "$(dirname "$RECEIPT_PATH")" && pwd)
RECEIPT_BASE=$(basename "$RECEIPT_PATH")
RECEIPT_PATH="$RECEIPT_DIR/$RECEIPT_BASE"
case "$RECEIPT_BASE" in
    ''|*[!A-Za-z0-9._-]*) echo "Error: receipt basename must use only [A-Za-z0-9._-]"; exit 1 ;;
esac
EXPECTED_RECEIPT_SHA256=$(awk -v name="$RECEIPT_BASE" '
    $2 == name { count += 1; value = $1 }
    END { if (count == 1) print value; else exit 1 }
' "$RECEIPT_PATH.sha256")
case "$EXPECTED_RECEIPT_SHA256" in
    *[!0-9a-f]*|'') echo "Error: receipt sidecar does not contain one canonical hash"; exit 1 ;;
esac
if [ "${#EXPECTED_RECEIPT_SHA256}" -ne 64 ] || \
   [ "$(sha256sum "$RECEIPT_PATH" | cut -d ' ' -f1)" != "$EXPECTED_RECEIPT_SHA256" ]; then
    echo "Error: build receipt checksum mismatch"
    exit 1
fi

receipt_value() {
    awk -F= -v key="$1" '
        $1 == key { count += 1; value = substr($0, index($0, "=") + 1) }
        END { if (count == 1) print value; else exit 1 }
    ' "$RECEIPT_PATH"
}

required_receipt_value() {
    key=$1
    if ! value=$(receipt_value "$key") || [ -z "$value" ]; then
        echo "Error: build receipt must contain exactly one nonempty $key field" >&2
        exit 1
    fi
    printf '%s\n' "$value"
}

RECEIPT_FORMAT=$(required_receipt_value receipt_format)
IMAGE_ID=$(required_receipt_value image_id)
RECEIPT_REVISION=$(required_receipt_value source_revision)
RECEIPT_TREE=$(required_receipt_value source_tree)
RECEIPT_MANIFEST=$(required_receipt_value source_manifest_sha256)
RECEIPT_DOCKERFILE=$(required_receipt_value dockerfile_sha256)
BUILD_INFO_REVISION=$(required_receipt_value build_info_source_revision)
BUILD_INFO_TREE=$(required_receipt_value build_info_source_tree)
BUILD_INFO_MANIFEST=$(required_receipt_value build_info_source_manifest_sha256)

if [ "$RECEIPT_FORMAT" != "zap1-build-receipt-v1" ]; then
    echo "Error: unsupported build receipt format"
    exit 1
fi
IMAGE_HEX=${IMAGE_ID#sha256:}
case "$IMAGE_ID" in
    sha256:*) ;;
    *) echo "Error: invalid image ID in build receipt"; exit 1 ;;
esac
case "$IMAGE_HEX" in
    ''|*[!0-9a-f]*) echo "Error: invalid image ID in build receipt"; exit 1 ;;
esac
if [ "${#IMAGE_HEX}" -ne 64 ]; then
    echo "Error: invalid image ID length in build receipt"
    exit 1
fi

SOURCE_REVISION=$(git rev-parse HEAD)
SOURCE_TREE=$(git rev-parse 'HEAD^{tree}')
ARCHIVE_ROOT=$(mktemp -d)
cleanup() {
    rm -rf -- "$ARCHIVE_ROOT"
}
trap cleanup EXIT
git archive "$SOURCE_REVISION" | tar -x -C "$ARCHIVE_ROOT"
SOURCE_MANIFEST=$(python3 "$ARCHIVE_ROOT/scripts/source_manifest.py" --root "$ARCHIVE_ROOT")
DOCKERFILE_SHA256=$(sha256sum "$ARCHIVE_ROOT/Dockerfile" | cut -d ' ' -f1)
CHECKER_SHA256=$(sha256sum "$ARCHIVE_ROOT/conformance/check_api.py" | cut -d ' ' -f1)
CHECKER_SCHEMA_SHA256=$(sha256sum "$ARCHIVE_ROOT/conformance/api_schemas.json" | cut -d ' ' -f1)

if [ "$RECEIPT_REVISION" != "$SOURCE_REVISION" ] || \
   [ "$RECEIPT_TREE" != "$SOURCE_TREE" ] || \
   [ "$RECEIPT_MANIFEST" != "$SOURCE_MANIFEST" ] || \
   [ "$RECEIPT_DOCKERFILE" != "$DOCKERFILE_SHA256" ]; then
    echo "Error: build receipt does not match the current clean archive"
    exit 1
fi
if [ "$BUILD_INFO_REVISION" != "$SOURCE_REVISION" ] || \
   [ "$BUILD_INFO_TREE" != "$SOURCE_TREE" ] || \
   [ "$BUILD_INFO_MANIFEST" != "$SOURCE_MANIFEST" ]; then
    echo "Error: receipt BUILD_INFO fields do not match the current clean archive"
    exit 1
fi

RESOLVED_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$IMAGE_ID" 2>/dev/null || true)
if [ "$RESOLVED_IMAGE_ID" != "$IMAGE_ID" ]; then
    echo "Error: the exact image ID from the receipt is not present locally"
    exit 1
fi
IMAGE_REVISION=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$IMAGE_ID")
IMAGE_TREE=$(docker image inspect --format '{{index .Config.Labels "io.frontiercompute.zap1.source-tree"}}' "$IMAGE_ID")
IMAGE_MANIFEST=$(docker image inspect --format '{{index .Config.Labels "io.frontiercompute.zap1.source-manifest-sha256"}}' "$IMAGE_ID")
if [ "$IMAGE_REVISION" != "$SOURCE_REVISION" ] || \
   [ "$IMAGE_TREE" != "$SOURCE_TREE" ] || \
   [ "$IMAGE_MANIFEST" != "$SOURCE_MANIFEST" ]; then
    echo "Error: image identity labels do not match the current clean archive"
    exit 1
fi

RUNTIME_BUILD_INFO=$(docker run --rm --entrypoint /bin/cat "$IMAGE_ID" /usr/local/share/zap1/BUILD_INFO)
if [ "$RUNTIME_BUILD_INFO" != "$(sed -n 's/^build_info_//p' "$RECEIPT_PATH")" ]; then
    echo "Error: embedded BUILD_INFO differs from the build receipt"
    exit 1
fi

UFVK=${ZAP1_OPERATOR_UFVK:-}
ADDRESS=${ZAP1_ANCHOR_TO_ADDRESS:-}
SCAN_FROM_HEIGHT=${ZAP1_SCAN_FROM_HEIGHT:-}
if [ -z "$UFVK" ] || [ -z "$ADDRESS" ] || [ -z "$SCAN_FROM_HEIGHT" ]; then
    echo "Error: set ZAP1_OPERATOR_UFVK, ZAP1_ANCHOR_TO_ADDRESS, and ZAP1_SCAN_FROM_HEIGHT from a wallet you control"
    exit 1
fi
case "$UFVK" in
    uview1*) ;;
    *) echo "Error: ZAP1_OPERATOR_UFVK must be a mainnet UFVK beginning uview1"; exit 1 ;;
esac
case "$ADDRESS" in
    u1*) ;;
    *) echo "Error: ZAP1_ANCHOR_TO_ADDRESS must be a mainnet unified address beginning u1"; exit 1 ;;
esac
case "$UFVK" in
    *[!0-9a-z]*) echo "Error: ZAP1_OPERATOR_UFVK must be lowercase bech32"; exit 1 ;;
esac
case "$ADDRESS" in
    *[!0-9a-z]*) echo "Error: ZAP1_ANCHOR_TO_ADDRESS must be lowercase bech32"; exit 1 ;;
esac
if [ "${#UFVK}" -lt 20 ] || [ "${#ADDRESS}" -lt 20 ]; then
    echo "Error: wallet inputs are too short"
    exit 1
fi
case "$SCAN_FROM_HEIGHT" in
    *[!0-9]*|'') echo "Error: ZAP1_SCAN_FROM_HEIGHT must be a nonnegative integer"; exit 1 ;;
esac

echo "Generating operator config: $OPERATOR (port $PORT)"

# Generate API key
API_KEY=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')

mkdir -m 700 -p "$OUTDIR"
mkdir -m 700 -p "$OUTDIR/evaluator"
cp "$ARCHIVE_ROOT/conformance/check_api.py" "$OUTDIR/evaluator/check_api.py"
cp "$ARCHIVE_ROOT/conformance/api_schemas.json" "$OUTDIR/evaluator/api_schemas.json"
chmod 500 "$OUTDIR/evaluator/check_api.py"
chmod 400 "$OUTDIR/evaluator/api_schemas.json"

# Write .env
cat > "$OUTDIR/.env" <<EOF
# ZAP1 operator: $OPERATOR
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

UFVK=$UFVK
NETWORK=Mainnet
ZEBRA_RPC_URL=http://127.0.0.1:8232
SCAN_FROM_HEIGHT=$SCAN_FROM_HEIGHT
LISTEN_ADDR=127.0.0.1:$PORT
DB_PATH=/data/zap1.db
API_KEY=$API_KEY
ZAP1_DEPLOYMENT_IMAGE_ID=$IMAGE_ID
ANCHOR_TO_ADDRESS=$ADDRESS
ANCHOR_BROADCAST_ENABLED=false
TRIAL_KEY_ISSUANCE_ENABLED=false
EOF
chmod 600 "$OUTDIR/.env"

# Write docker-compose
cat > "$OUTDIR/docker-compose.yml" <<EOF
services:
  zap1-$OPERATOR:
    image: $IMAGE_ID
    pull_policy: never
    container_name: zap1-$OPERATOR
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./data:/data
    env_file:
      - .env
    healthcheck:
      test: ["CMD-SHELL", "body=\$\$(curl -fsS http://127.0.0.1:$PORT/health) && printf '%s' \"\$\$body\" | grep -q '\\"scanner_operational\\":true' && printf '%s' \"\$\$body\" | grep -q '\\"rpc_reachable\\":true'"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF

# Write run script
cat > "$OUTDIR/run.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "\$(dirname "\$0")"
BASE_URL="http://127.0.0.1:$PORT"
CHECKER_PATH="evaluator/check_api.py"
CHECKER_SCHEMA_PATH="evaluator/api_schemas.json"
STARTUP_WAIT_SECONDS="\${ZAP1_STARTUP_WAIT_SECONDS:-3600}"
STARTUP_POLL_SECONDS="\${ZAP1_STARTUP_POLL_SECONDS:-5}"
MAX_SYNC_LAG_BLOCKS="\${ZAP1_MAX_SYNC_LAG_BLOCKS:-10}"

case "\$STARTUP_WAIT_SECONDS" in
  ''|*[!0-9]*) echo "ZAP1_STARTUP_WAIT_SECONDS must be a positive integer" >&2; exit 1 ;;
esac
case "\$STARTUP_POLL_SECONDS" in
  ''|*[!0-9]*) echo "ZAP1_STARTUP_POLL_SECONDS must be a positive integer" >&2; exit 1 ;;
esac
case "\$MAX_SYNC_LAG_BLOCKS" in
  ''|*[!0-9]*) echo "ZAP1_MAX_SYNC_LAG_BLOCKS must be a nonnegative integer" >&2; exit 1 ;;
esac
if [ "\$STARTUP_WAIT_SECONDS" -lt 1 ] || [ "\$STARTUP_POLL_SECONDS" -lt 1 ]; then
  echo "startup wait and poll seconds must both be positive" >&2
  exit 1
fi
verify_pinned_evaluator() {
  [ "\$(sha256sum "\$CHECKER_PATH" | cut -d ' ' -f1)" = "$CHECKER_SHA256" ] && \
    [ "\$(sha256sum "\$CHECKER_SCHEMA_PATH" | cut -d ' ' -f1)" = "$CHECKER_SCHEMA_SHA256" ]
}
if ! verify_pinned_evaluator; then
  echo "Pinned evaluator bytes do not match the generated operator receipt" >&2
  exit 1
fi

stop_failed() {
  echo "\$1" >&2
  docker compose stop
  exit 1
}

docker compose up -d --no-build --pull never
DEADLINE=\$((SECONDS + STARTUP_WAIT_SECONDS))

# Bind the reachable process to the receipt before allowing a long scanner
# catch-up window. A wrong image or source identity is not a transient state.
BUILD_INFO_JSON=""
while [ "\$SECONDS" -lt "\$DEADLINE" ]; do
  if BUILD_INFO_JSON=\$(curl -fsS --connect-timeout 5 --max-time 15 "\$BASE_URL/build/info"); then
    break
  fi
  sleep "\$STARTUP_POLL_SECONDS"
done
if [ -z "\$BUILD_INFO_JSON" ]; then
  stop_failed "Build identity endpoint did not become reachable before the startup deadline"
fi
if ! printf '%s' "\$BUILD_INFO_JSON" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
revision, tree, manifest, image_id = sys.argv[1:]
source = data.get("source", {})
deployment = data.get("deployment", {})
assurance = data.get("build_assurance", {})
checks = {
    "deployment revision": source.get("deployment_revision") == revision,
    "source tree": source.get("source_tree") == tree,
    "source manifest": source.get("source_manifest_sha256") == manifest,
    "public evidence revision": source.get("public_evidence_revision") == revision,
    "deployment image ID": deployment.get("image_id") == image_id,
    "runtime manifest verification": source.get("source_manifest_verified") is True,
    "complete build metadata": assurance.get("metadata_complete") is True,
    "locked Cargo build": assurance.get("cargo_locked") is True,
    "path remapping": assurance.get("path_remapping") is True,
    "build manifest verification": assurance.get("source_manifest_verified") is True,
}
failed = [label for label, ok in checks.items() if not ok]
if failed:
    print("build identity mismatch: " + ", ".join(failed), file=sys.stderr)
    raise SystemExit(1)
' "$SOURCE_REVISION" "$SOURCE_TREE" "$SOURCE_MANIFEST" "$IMAGE_ID"; then
  stop_failed "Deployment identity does not match the verified build receipt"
fi

# A fresh wallet birthday can require a real catch-up. Wait for the same health
# policy enforced by the final evaluator instead of treating HTTP 200 as ready.
HEALTH_READY=false
while [ "\$SECONDS" -lt "\$DEADLINE" ]; do
  if HEALTH_JSON=\$(curl -fsS --connect-timeout 5 --max-time 15 "\$BASE_URL/health"); then
    if printf '%s' "\$HEALTH_JSON" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
maximum = int(sys.argv[1])
lag = data.get("sync_lag")
scanned = data.get("last_scanned_height")
tip = data.get("chain_tip")
consistent = (
    type(lag) is int
    and type(scanned) is int
    and type(tip) is int
    and lag == max(tip - scanned, 0)
)
ready = (
    data.get("scanner_operational") is True
    and data.get("rpc_reachable") is True
    and consistent
    and 0 <= lag <= maximum
)
print(
    "scanner_operational={} rpc_reachable={} sync_lag={} max_sync_lag={}".format(
        data.get("scanner_operational"),
        data.get("rpc_reachable"),
        lag,
        maximum,
    )
)
raise SystemExit(0 if ready else 1)
' "\$MAX_SYNC_LAG_BLOCKS"; then
      HEALTH_READY=true
      break
    fi
  fi
  sleep "\$STARTUP_POLL_SECONDS"
done
if [ "\$HEALTH_READY" != true ]; then
  stop_failed "Scanner did not satisfy the configured health policy before the startup deadline"
fi

if ! verify_pinned_evaluator; then
  stop_failed "Pinned evaluator bytes changed during startup"
fi

if ! ZAP1_API_BASE="http://127.0.0.1:$PORT" \
  ZAP1_REQUIRE_SOURCE_PARITY=true \
  ZAP1_EXPECTED_SOURCE_REVISION=$SOURCE_REVISION \
  ZAP1_EXPECTED_SOURCE_TREE=$SOURCE_TREE \
  ZAP1_EXPECTED_SOURCE_MANIFEST_SHA256=$SOURCE_MANIFEST \
  ZAP1_EXPECTED_DEPLOYMENT_IMAGE_ID=$IMAGE_ID \
  ZAP1_MAX_SYNC_LAG_BLOCKS="\$MAX_SYNC_LAG_BLOCKS" \
  python3 "\$CHECKER_PATH" "http://127.0.0.1:$PORT"; then
  stop_failed "Deployment identity, API schema, or final health check failed"
fi
echo "ZAP1 operator '$OPERATOR' started on port $PORT"
echo "Health: curl http://127.0.0.1:$PORT/health"
echo "Anchor QR requires the API key in an Authorization header; never put it in a URL."
EOF
chmod 700 "$OUTDIR/run.sh"

# Summary
echo ""
echo "Operator: $OPERATOR"
echo "Port: $PORT"
echo "API key: stored only in $OUTDIR/.env"
echo "Address: $ADDRESS"
echo "Scan from height: $SCAN_FROM_HEIGHT"
echo "Image ID: $IMAGE_ID"
echo "Build receipt: $RECEIPT_PATH"
echo ""
echo "Files:"
echo "  $OUTDIR/.env        - container config"
echo "  $OUTDIR/docker-compose.yml"
echo "  $OUTDIR/run.sh"
echo "  $OUTDIR/evaluator/  - pinned checker and schema from the exact source archive"
echo ""
echo "Start: cd $OUTDIR && ./run.sh"
echo "Anchor QR: use an Authorization header; API keys in URLs are rejected."
echo "No wallet or spending seed was created. The supplied UFVK and address remain operator-owned inputs."
